import sys
import os
import time
import shutil
import subprocess
import signal
import json
from dnslib import DNSRecord, QTYPE, A, RR
from dnslib.server import DNSServer, BaseResolver

# Path for shared stats
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_stats.json")

class BlockResolver(BaseResolver):
    def __init__(self, blocklist_file, upstream="8.8.8.8"):
        self.blocklist_file = blocklist_file
        self.upstream = upstream
        self.blocked_domains = set()
        self.last_mtime = 0
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0
        }
        self.load_blocklist()
        self.save_stats()

    def load_blocklist(self):
        try:
            if os.path.exists(self.blocklist_file):
                with open(self.blocklist_file, "r") as f:
                    self.blocked_domains = {
                        line.strip().lower() 
                        for line in f 
                        if line.strip() and not line.strip().startswith("#")
                    }
                print(f"[DNS] Loaded {len(self.blocked_domains)} blocked domains from {self.blocklist_file}")
            else:
                print(f"[DNS] Blocklist file {self.blocklist_file} not found. Starting with empty blocklist.")
        except Exception as e:
            print(f"[DNS] Error loading blocklist: {e}")

    def save_stats(self):
        try:
            with open(STATS_FILE, "w") as f:
                json.dump(self.stats, f)
        except Exception as e:
            pass

    def resolve(self, request, handler):
        # Dynamically reload blocklist if it was modified
        try:
            mtime = os.path.getmtime(self.blocklist_file)
            if mtime != self.last_mtime:
                self.last_mtime = mtime
                self.load_blocklist()
        except Exception:
            pass

        qname = str(request.q.qname).strip(".").lower()
        qtype = request.q.qtype
        
        self.stats["total_queries"] += 1
        
        # Check if domain matches any blocked domain
        is_blocked = False
        matched_rule = ""
        for blocked in self.blocked_domains:
            # Matches exact domain or sub-domain
            if qname == blocked or qname.endswith("." + blocked):
                is_blocked = True
                matched_rule = blocked
                break
        
        if is_blocked:
            self.stats["blocked_queries"] += 1
            self.save_stats()
            print(f"[DNS BLOCKED] {qname} (Matched rule: {matched_rule})")
            
            # Log DNS block to shared dpi_log.txt for dashboard display
            try:
                log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpi_log.txt")
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                with open(log_file, "a") as lf:
                    lf.write(f"[{now_str}] BLOCKED SNI: {qname} (IP: DNS Sinkhole)\n")
            except Exception as e:
                pass
            
            # Return 0.0.0.0
            reply = request.reply()
            if qtype == QTYPE.A:
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            return reply
        
        self.save_stats()
        
        # Forward to upstream
        try:
            reply_data = request.send(self.upstream, 53, timeout=2.0)
            reply = DNSRecord.parse(reply_data)
            return reply
        except Exception as e:
            print(f"[DNS ERROR] Failed to resolve {qname} upstream: {e}")
            return request.reply()


# DNS Configuration Management
def get_platform():
    return sys.platform

def get_active_interfaces():
    interfaces = []
    try:
        output = subprocess.check_output(["netsh", "interface", "show", "interface"]).decode("utf-8", errors="ignore")
        for line in output.splitlines():
            if "Connected" in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    interfaces.append(" ".join(parts[3:]))
    except Exception:
        pass
    if not interfaces:
        interfaces = ["Wi-Fi", "Ethernet"]
    return interfaces

def set_dns():
    platform = get_platform()
    print(f"[System] Configuring DNS settings for platform: {platform}")
    if platform.startswith("win"):
        interfaces = get_active_interfaces()
        for iface in interfaces:
            print(f"[System] Setting IPv4 DNS to 127.0.0.1 and IPv6 DNS to ::1 on interface: '{iface}'")
            cmd_ipv4 = f'netsh interface ipv4 set dnsservers name="{iface}" static 127.0.0.1 primary'
            cmd_ipv6 = f'netsh interface ipv6 set dnsservers name="{iface}" static ::1 primary'
            res_ipv4 = subprocess.run(cmd_ipv4, shell=True, capture_output=True, text=True)
            res_ipv6 = subprocess.run(cmd_ipv6, shell=True, capture_output=True, text=True)
            print(f"[System] IPv4 exit code: {res_ipv4.returncode}")
            if res_ipv4.returncode != 0:
                print(f"[System] IPv4 error: {res_ipv4.stderr.strip()}")
            print(f"[System] IPv6 exit code: {res_ipv6.returncode}")
            if res_ipv6.returncode != 0:
                print(f"[System] IPv6 error: {res_ipv6.stderr.strip()}")
        print("[System] Windows DNS configured successfully via netsh.")
    elif platform == "darwin":
        # macOS
        try:
            output = subprocess.check_output(["networksetup", "-listallnetworkservices"]).decode().split('\n')
            services = [s.strip() for s in output if s.strip() and not s.startswith('*')]
            for service in services:
                # Check if it has active IP
                info = subprocess.check_output(["networksetup", "-getinfo", service]).decode()
                if "IP address:" in info:
                    subprocess.run(["networksetup", "-setdnsservers", service, "127.0.0.1"])
                    print(f"[System] macOS DNS for '{service}' set to 127.0.0.1")
        except Exception as e:
            print(f"[System] Error setting macOS DNS: {e}")
    else:
        # Linux
        try:
            # Backup
            if os.path.exists("/etc/resolv.conf") and not os.path.exists("/etc/resolv.conf.backup"):
                shutil.copy("/etc/resolv.conf", "/etc/resolv.conf.backup")
            with open("/etc/resolv.conf", "w") as f:
                f.write("nameserver 127.0.0.1\n")
            print("[System] Linux /etc/resolv.conf updated to 127.0.0.1")
        except Exception as e:
            print(f"[System] Error setting Linux DNS (run with sudo): {e}")

def restore_dns():
    platform = get_platform()
    print(f"[System] Restoring original DNS settings...")
    if platform.startswith("win"):
        interfaces = get_active_interfaces()
        for iface in interfaces:
            print(f"[System] Restoring DNS settings to DHCP on interface: '{iface}'")
            cmd_ipv4 = f'netsh interface ipv4 set dnsservers name="{iface}" source=dhcp'
            cmd_ipv6 = f'netsh interface ipv6 set dnsservers name="{iface}" source=dhcp'
            res_ipv4 = subprocess.run(cmd_ipv4, shell=True, capture_output=True, text=True)
            res_ipv6 = subprocess.run(cmd_ipv6, shell=True, capture_output=True, text=True)
            print(f"[System] Restore IPv4 exit code: {res_ipv4.returncode}")
            print(f"[System] Restore IPv6 exit code: {res_ipv6.returncode}")
        print("[System] Windows DNS restored to DHCP successfully.")
    elif platform == "darwin":
        try:
            output = subprocess.check_output(["networksetup", "-listallnetworkservices"]).decode().split('\n')
            services = [s.strip() for s in output if s.strip() and not s.startswith('*')]
            for service in services:
                info = subprocess.check_output(["networksetup", "-getinfo", service]).decode()
                if "IP address:" in info:
                    subprocess.run(["networksetup", "-setdnsservers", service, "empty"])
                    print(f"[System] macOS DNS for '{service}' restored")
        except Exception as e:
            print(f"[System] Error restoring macOS DNS: {e}")
    else:
        # Linux
        try:
            if os.path.exists("/etc/resolv.conf.backup"):
                shutil.copy("/etc/resolv.conf.backup", "/etc/resolv.conf")
                os.remove("/etc/resolv.conf.backup")
                print("[System] Linux /etc/resolv.conf restored")
        except Exception as e:
            print(f"[System] Error restoring Linux DNS: {e}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--restore-only":
        restore_dns()
        return

    blocklist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt")
    resolver = BlockResolver(blocklist_path)
    
    server_ipv4 = DNSServer(resolver, address="127.0.0.1", port=53)
    server_ipv6 = None
    try:
        server_ipv6 = DNSServer(resolver, address="::1", port=53)
        server_ipv6.start_thread()
        print("[DNS] Local IPv6 DNS server running on ::1:53...")
    except Exception as e:
        print(f"[DNS Warning] Could not start IPv6 server on ::1: {e}")
    
    # Set DNS
    set_dns()
    
    # Register clean shutdown
    def signal_handler(sig, frame):
        print("\n[DNS] Stopping server...")
        server_ipv4.stop()
        if server_ipv6:
            server_ipv6.stop()
        restore_dns()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("[DNS] Local IPv4 DNS server running on 127.0.0.1:53...")
    try:
        server_ipv4.start()
    except Exception as e:
        print(f"[DNS Error] Could not start server: {e}")
        print("Note: Running on port 53 requires administrator/root privileges.")
        restore_dns()

if __name__ == "__main__":
    main()
