import sys
import os
import argparse
import re
import urllib.parse
import subprocess
import threading
import signal
import time
import requests

# Track child processes for clean termination
dns_process = None
dpi_process = None
dashboard_process = None
local_dir = os.path.dirname(os.path.abspath(__file__))

def extract_youtube_domains(url):
    domains = set()
    # Pre-seed with standard Google/YouTube ad-serving domains
    domains.update([
        "googleads.g.doubleclick.net",
        "imasdk.googleapis.com",
        "pagead2.googlesyndication.com",
        "pubads.g.doubleclick.net",
        "ad.doubleclick.net",
        "static.doubleclick.net",
        "www.googleadservices.com",
        "adservice.google.com"
    ])
    
    print(f"\n[Scraper] Parsing YouTube video page: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Match direct media stream subdomains like *.googlevideo.com
            matches = re.findall(r'[a-zA-Z0-9\-]+\.googlevideo\.com', response.text)
            for match in matches:
                domains.add(match.lower())
                
            # Scan general URLs for ad networks
            urls = re.findall(r'https?://[a-zA-Z0-9\-\.]+', response.text)
            for u in urls:
                hostname = urllib.parse.urlparse(u).hostname
                if hostname:
                    hostname = hostname.lower()
                    if any(x in hostname for x in ["googlevideo", "doubleclick", "googlesyndication", "googleads"]):
                        domains.add(hostname)
        else:
            print(f"[Scraper] Warning: Received HTTP {response.status_code} from YouTube.")
    except Exception as e:
        print(f"[Scraper] Error accessing YouTube: {e}")
        
    print(f"[Scraper] Found {len(domains)} associated ad/stream domains.")
    return domains

def update_blocklist(domains, blocklist_file="blocklist.txt"):
    if not os.path.isabs(blocklist_file):
        blocklist_file = os.path.join(local_dir, blocklist_file)
        
    existing = set()
    if os.path.exists(blocklist_file):
        with open(blocklist_file, "r") as f:
            existing = {line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")}
            
    new_domains = domains - existing
    if new_domains:
        with open(blocklist_file, "a") as f:
            for d in sorted(new_domains):
                f.write(f"\n{d}")
        print(f"[Blocklist] Appended {len(new_domains)} new domains to {blocklist_file}")
    else:
        print("[Blocklist] No new domains to append; blocklist is up to date.")

def build_cpp_engine():
    print("\n[DPI] Compiling C++ Live DPI Engine...")
    make_cmd = "make"
    env = os.environ.copy()
    if sys.platform.startswith("win"):
        env["PATH"] = "C:\\Windows\\System32\\Npcap;C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin;" + env["PATH"]
        if os.path.exists("C:\\msys64\\mingw64\\bin\\mingw32-make.exe"):
            make_cmd = "C:\\msys64\\mingw64\\bin\\mingw32-make.exe"
        else:
            make_cmd = "mingw32-make"
        
    try:
        # Run clean first to ensure a fresh build
        subprocess.run([make_cmd, "clean"], env=env, cwd=local_dir, capture_output=True)
        # Build binary
        result = subprocess.run([make_cmd], env=env, cwd=local_dir, capture_output=True, text=True)
        if result.returncode == 0:
            print("[DPI] C++ compilation successful.")
        else:
            print(f"[DPI Error] Compilation failed:\n{result.stderr}")
            sys.exit(1)
    except Exception as e:
        print(f"[DPI Error] Could not compile: {e}")
        sys.exit(1)

def cleanup_firewall():
    print("\n[System] Flushing dynamic firewall blocking rules...")
    # Read dpi_log.txt to find blocked IPs
    log_file = os.path.join(local_dir, "dpi_log.txt")
    if not os.path.exists(log_file):
        return
        
    ips = set()
    try:
        with open(log_file, "r") as f:
            for line in f:
                match = re.search(r"IP:\s*([0-9\.]+)", line)
                if match:
                    ips.add(match.group(1))
    except Exception as e:
        print(f"[System] Error parsing log file for firewall cleanup: {e}")
        
    for ip in ips:
        if sys.platform.startswith("win"):
            cmd = f'netsh advfirewall firewall delete rule name="Block-YT-Ad-{ip}"'
        elif sys.platform == "darwin":
            cmd = f'sudo pfctl -a com.apple/live_dpi -F rules'
        else:
            cmd = f'sudo iptables -D OUTPUT -d {ip} -j DROP'
            
        subprocess.run(cmd, shell=True, capture_output=True)
    print(f"[System] Flushed rules for {len(ips)} blocked IPs.")

def stream_logs(pipe, prefix):
    try:
        for line in iter(pipe.readline, ''):
            if line:
                print(f"{prefix} {line.strip()}")
    except Exception:
        pass

def main():
    global dns_process, dpi_process, dashboard_process
    
    # Check for administrator / root access
    is_admin = False
    if sys.platform.startswith("win"):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
    else:
        is_admin = os.getuid() == 0
        
    if not is_admin:
        print("[Error] This script must be run with administrator/root privileges to bind to port 53 and perform live packet capture.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Combined DNS & Live DPI YouTube Ad-Blocker")
    parser.add_argument("--url", type=str, help="YouTube video URL to dynamically block associated domains")
    parser.add_argument("--interface", type=str, default="", help="Specific network interface to capture packets on")
    args = parser.parse_args()

    # Copy Npcap DLLs locally if needed (fixes non-compatible mode)
    copied_dlls = []
    if sys.platform.startswith("win"):
        import shutil
        npcap_dir = "C:\\Windows\\System32\\Npcap"
        if not os.path.exists(npcap_dir):
            npcap_dir = "C:\\Windows\\sysnative\\Npcap"
        for dll in ["wpcap.dll", "Packet.dll"]:
            src = os.path.join(npcap_dir, dll)
            dst = os.path.join(local_dir, dll)
            if os.path.exists(src):
                try:
                    shutil.copy(src, dst)
                    copied_dlls.append(dst)
                    print(f"[System] Copied Npcap {dll} to local directory for compatibility.")
                except Exception as e:
                    print(f"[System Warning] Could not copy {dll}: {e}")

    # Step 1: dynamic domains extraction
    if args.url:
        yt_domains = extract_youtube_domains(args.url)
        update_blocklist(yt_domains)

    # Step 2: Build C++ engine
    build_cpp_engine()

    # Signal handler for clean exit
    def signal_handler(sig, frame):
        print("\n[System] Shutdown signal received. Cleaning up...")
        if dpi_process:
            dpi_process.terminate()
        if dns_process:
            dns_process.terminate()
            dns_process.wait()
        if dashboard_process:
            dashboard_process.terminate()
            dashboard_process.wait()
        
        # Directly restore DNS settings from parent script on exit
        try:
            import dns_server
            dns_server.restore_dns()
        except Exception as e:
            print(f"[System Error] Failed to restore DNS settings: {e}")
            
        # Clean up copied DLLs
        for dll_path in copied_dlls:
            try:
                if os.path.exists(dll_path):
                    os.remove(dll_path)
            except Exception:
                pass

        cleanup_firewall()
        print("[System] Reverted all changes. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Step 3: Run Python DNS Server Subprocess
    print("\n[System] Starting local DNS server...")
    dns_process = subprocess.Popen(
        [sys.executable, "-u", "dns_server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Capture stderr in stdout log stream
        text=True,
        bufsize=1,
        cwd=local_dir
    )
    
    # Start thread to read DNS logs
    dns_thread = threading.Thread(target=stream_logs, args=(dns_process.stdout, "[DNS SERVER]"), daemon=True)
    dns_thread.start()

    # Step 3.5: Run Flask Dashboard Subprocess
    print("\n[System] Starting Flask dashboard...")
    dashboard_process = subprocess.Popen(
        [sys.executable, "-u", "dashboard.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=local_dir
    )
    
    # Start thread to read Dashboard logs
    dashboard_thread = threading.Thread(target=stream_logs, args=(dashboard_process.stdout, "[DASHBOARD]"), daemon=True)
    dashboard_thread.start()

    # Wait for DNS server and dashboard to initialize
    time.sleep(2)

    # Step 4: Run C++ DPI Engine Subprocess
    print("\n[System] Starting Live DPI Engine...")
    dpi_bin = "./live_dpi.exe" if sys.platform.startswith("win") else "./live_dpi"
    
    dpi_args = [dpi_bin]
    dpi_args.extend(["--blocklist", os.path.join(local_dir, "blocklist.txt")])
    if args.interface:
        dpi_args.extend(["--interface", args.interface])
        
    env = os.environ.copy()
    if sys.platform.startswith("win"):
        env["PATH"] = "C:\\Windows\\System32\\Npcap;C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin;" + env["PATH"]

    dpi_process = subprocess.Popen(
        dpi_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Capture C++ stderr to stdout stream
        text=True,
        bufsize=1,
        env=env,
        cwd=local_dir
    )

    # Start thread to read DPI logs
    dpi_thread = threading.Thread(target=stream_logs, args=(dpi_process.stdout, "[DPI ENGINE]"), daemon=True)
    dpi_thread.start()

    print("\n=======================================================")
    print("  System fully operational. Blocking ads in real-time. ")
    print("  Press Ctrl+C to terminate and restore settings.      ")
    print("=======================================================\n")

    # Monitor processes
    try:
        while True:
            if dns_process.poll() is not None:
                print("[Warning] DNS server stopped unexpectedly.")
                break
            if dpi_process.poll() is not None:
                print("[Warning] DPI engine stopped unexpectedly.")
                break
            if dashboard_process.poll() is not None:
                print("[Warning] Dashboard stopped unexpectedly.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
        
    signal_handler(None, None)

if __name__ == "__main__":
    main()
