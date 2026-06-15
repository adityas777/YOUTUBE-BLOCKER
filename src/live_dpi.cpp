#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <pcap.h>

#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

std::unordered_set<std::string> g_blocked_domains;
std::mutex g_blocklist_mutex;
std::string g_blocklist_file = "blocklist.txt";

// Load domains from blocklist
void loadBlocklist() {
    std::lock_guard<std::mutex> lock(g_blocklist_mutex);
    g_blocked_domains.clear();
    std::ifstream file(g_blocklist_file);
    if (!file.is_open()) {
        std::cerr << "[DPI] Warning: Cannot open blocklist file " << g_blocklist_file << std::endl;
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Trim leading and trailing whitespace
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), line.end());
        
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Convert to lowercase
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        g_blocked_domains.insert(line);
    }
    std::cout << "[DPI] Loaded " << g_blocked_domains.size() << " domains to block." << std::endl;
}

// Subdomain matching
bool shouldBlockDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(g_blocklist_mutex);
    if (domain.empty()) return false;
    
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(), ::tolower);
    
    if (g_blocked_domains.count(lower_domain)) return true;
    
    for (const auto& blocked : g_blocked_domains) {
        if (lower_domain.length() > blocked.length() && 
            lower_domain.compare(lower_domain.length() - blocked.length() - 1, blocked.length() + 1, "." + blocked) == 0) {
            return true;
        }
    }
    
    return false;
}

// Log blocking event
void logBlock(const std::string& sni, const std::string& ip) {
    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);
    
    std::ofstream log_file("dpi_log.txt", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        struct tm* time_info = std::localtime(&time_t_now);
        char time_str[64];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
        
        log_file << "[" << time_str << "] BLOCKED SNI: " << sni << " (IP: " << ip << ")" << std::endl;
    }
    std::cout << "[DPI BLOCKED] SNI: " << sni << " -> IP: " << ip << " (Firewall rule added)" << std::endl;
}

// Dynamic firewall blocking
void blockIPFirewall(const std::string& ip) {
    static std::unordered_set<std::string> blocked_ips;
    static std::mutex block_mutex;
    
    std::lock_guard<std::mutex> lock(block_mutex);
    if (blocked_ips.count(ip)) return;
    
    blocked_ips.insert(ip);
    std::string cmd;
    
    #if defined(_WIN32) || defined(_WIN64)
        cmd = "netsh advfirewall firewall add rule name=\"Block-YT-Ad-" + ip + "\" dir=out action=block remoteip=" + ip;
    #elif defined(__APPLE__)
        cmd = "echo \"block drop out quick to " + ip + "\" | sudo pfctl -a com.apple/live_dpi -f -";
    #else
        cmd = "sudo iptables -I OUTPUT -d " + ip + " -j DROP";
    #endif
    
    int res = std::system(cmd.c_str());
    if (res != 0) {
        std::cerr << "[FIREWALL] Warning: Failed to execute firewall command for IP: " << ip << std::endl;
    }
}

// Packet handler callback
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet_data) {
    RawPacket raw;
    raw.header.ts_sec = header->ts.tv_sec;
    raw.header.ts_usec = header->ts.tv_usec;
    raw.header.incl_len = header->caplen;
    raw.header.orig_len = header->len;
    raw.data.assign(packet_data, packet_data + header->caplen);
    
    ParsedPacket parsed;
    if (!PacketParser::parse(raw, parsed)) {
        return;
    }
    
    if (parsed.has_ip && parsed.has_tcp && parsed.dest_port == 443 && parsed.payload_length > 0) {
        auto sni = SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
        if (sni) {
            std::string host = *sni;
            if (shouldBlockDomain(host)) {
                logBlock(host, parsed.dest_ip);
                blockIPFirewall(parsed.dest_ip);
            }
        }
    }
}

// Watch blocklist for changes in a background thread
void watchBlocklist() {
    try {
        auto last_write_time = std::filesystem::last_write_time(g_blocklist_file);
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            try {
                auto current_write_time = std::filesystem::last_write_time(g_blocklist_file);
                if (current_write_time != last_write_time) {
                    last_write_time = current_write_time;
                    std::cout << "[DPI] Blocklist file modified. Reloading..." << std::endl;
                    loadBlocklist();
                }
            } catch (...) {
                // File might be temporarily locked during write
            }
        }
    } catch (...) {
        std::cerr << "[DPI Warning] Could not start blocklist file watcher." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::string selected_interface = "";
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--interface" && i + 1 < argc) {
            selected_interface = argv[++i];
        } else if (arg == "--blocklist" && i + 1 < argc) {
            g_blocklist_file = argv[++i];
        }
    }
    
    std::cout << "=========================================" << std::endl;
    std::cout << "      Live DPI Engine Sniffer Active     " << std::endl;
    std::cout << "=========================================" << std::endl;
    
    loadBlocklist();
    
    // Start blocklist watching thread
    std::thread watcher_thread(watchBlocklist);
    watcher_thread.detach();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev_name = selected_interface;
    
    if (dev_name.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
            return 1;
        }
        
        // Print all detected interfaces for debugging
        std::cout << "[DPI] Searching for network interfaces..." << std::endl;
        pcap_if_t* d;
        int idx = 0;
        for (d = alldevs; d != NULL; d = d->next) {
            std::cout << "  [" << idx++ << "] Device: " << d->name;
            if (d->description) std::cout << " (" << d->description << ")";
            std::cout << " [Loopback: " << (d->flags & PCAP_IF_LOOPBACK ? "Yes" : "No")
                      << ", Has Addresses: " << (d->addresses != NULL ? "Yes" : "No") << "]" << std::endl;
        }
        
        // Auto-select active interface (prioritize Wi-Fi and Ethernet over Bluetooth/virtual)
        pcap_if_t* backup_dev = NULL;
        for (d = alldevs; d != NULL; d = d->next) {
            if (!(d->flags & PCAP_IF_LOOPBACK) && d->addresses != NULL) {
                std::string desc = d->description ? d->description : "";
                std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);
                
                if (desc.find("wi-fi") != std::string::npos || 
                    desc.find("wifi") != std::string::npos || 
                    desc.find("wireless") != std::string::npos || 
                    desc.find("ethernet") != std::string::npos || 
                    desc.find("intel") != std::string::npos ||
                    desc.find("realtek") != std::string::npos) {
                    dev_name = d->name;
                    break;
                }
                if (backup_dev == NULL) {
                    backup_dev = d;
                }
            }
        }
        
        if (dev_name.empty() && backup_dev != NULL) {
            dev_name = backup_dev->name;
        }
        
        if (dev_name.empty() && alldevs != NULL) {
            dev_name = alldevs->name;
        }
        
        pcap_freealldevs(alldevs);
    }
    
    if (dev_name.empty()) {
        std::cerr << "[DPI] Error: No network interfaces found." << std::endl;
        return 1;
    }
    
    std::cout << "[DPI] Capturing on interface: " << dev_name << std::endl;
    
    pcap_t* handle = pcap_open_live(dev_name.c_str(), 65536, 1, 10, errbuf);
    if (handle == NULL) {
        std::cerr << "[DPI] Error: Could not open device: " << errbuf << std::endl;
        return 1;
    }
    
    // Compile and apply a BPF filter to only capture port 443 traffic (HTTPS Client Hellos)
    struct bpf_program fp;
    std::string filter_exp = "tcp port 443";
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[DPI] Error: Could not parse filter " << filter_exp << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[DPI] Error: Could not install filter " << filter_exp << std::endl;
        return 1;
    }
    
    std::cout << "[DPI] Packet filter 'tcp port 443' compiled & applied." << std::endl;
    std::cout << "[DPI] SNI Sniffer is active. Press Ctrl+C to stop." << std::endl;
    
    pcap_loop(handle, 0, packetHandler, NULL);
    
    pcap_close(handle);
    return 0;
}
