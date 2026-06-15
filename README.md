# 🛡️ Hybrid DNS & DPI YouTube Ad-Blocker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

A state-of-the-art, multi-layered network security system that blocks YouTube ads at the protocol level. By combining a **local DNS Sinkhole**, a **real-time Deep Packet Inspection (DPI) Engine**, a **host-level dynamic firewall integration**, and a **Chrome Extension companion**, this project intercepts and drops ad streams before they reach your browser.

```
                  ┌────────────── Chrome Extension ─────────────┐
                  │ - Detects YouTube video navigation         │
                  │ - Sends video URL to Local Flask Server    │
                  └─────────────────────┬───────────────────────┘
                                        │ (HTTP POST)
                                        ▼
                                ┌───────────────┐
                                │  Flask App    │◄─── Reads
                                │  (Dashboard)  │     Logs/Stats
                                └───────┬───────┘
                                        │ (Appends to)
                                        ▼
                                ┌───────────────┐
                                │ Blocklist.txt │
                                └────┬─────┬────┘
                  ┌──────────────────┘     └──────────────────┐
                  ▼                                           ▼
       ┌─────────────────────┐                     ┌─────────────────────┐
       │  Local DNS Server   │                     │   C++ DPI Engine    │
       │  (dnslib Resolver)  │                     │   (Npcap Sniffer)   │
       └──────────┬──────────┘                     └──────────┬──────────┘
                  │                                           │
       Intercepts DNS queries                      Sniffs TLS Client Hello
     Sinkholes matches to 0.0.0.0                 Extracts SNI Host Header
                  │                                           │
                  ▼                                           ▼
       [ BLOCKS AD RESOLUTION ]                     [ BLOCKS SERVER IP via ]
                                                    [   DYNAMIC FIREWALL   ]
```

---

## 📖 Table of Contents
1. [Core Features](#-core-features)
2. [How It Works (High Level)](#-how-it-works-high-level)
3. [Repository Structure](#-repository-structure)
4. [Prerequisites](#-prerequisites)
5. [Installation & Setup](#-installation--setup)
   - [Windows Setup (Recommended)](#windows-setup-recommended)
   - [Chrome Extension Installation](#chrome-extension-installation)
   - [Linux / macOS Setup](#linux--macos-setup)
6. [Usage Instructions](#-usage-instructions)
7. [The Dashboard](#-the-dashboard)
8. [Uninstalling](#-uninstalling)
9. [Technical Deep Dive](#-technical-deep-dive)

---

## ✨ Core Features
- **Dynamic Stream Scraping**: Automatically extracts Google/YouTube ad-serving subdomains (like `*.googlevideo.com`) in real-time when navigating to a video.
- **Dual-Layer Blocking (DNS + DPI)**:
  - **DNS Sinkholing**: Resolves known ad domains immediately to `0.0.0.0`.
  - **TLS SNI Inspection**: Inspects raw packet handshakes on Port 443, extracts the Server Name Indication (SNI), and targets IPs serving ads even if they pass the DNS block.
- **Dynamic Firewall Injection**: Injects temporary OS firewall rules (`netsh` on Windows, `iptables` on Linux, `pfctl` on macOS) to drop all packets to and from identified ad-serving IP addresses.
- **Beautiful Web Dashboard**: Clean Flask-based web interface showing live stats, query rates, and detailed block logs.
- **Automated Startup Integration**: Schedule startup tasks to launch the system silently in the background.

---

## 🔍 How It Works (High Level)
YouTube servers deliver video streams and advertisements using the same underlying server pool (`*.googlevideo.com`). Standard DNS blockers fail here because blocking the domain entirely blocks the main video. 

This hybrid system solves that using a multi-step detection loop:
1. **Scraping**: When you open a YouTube video, the Chrome extension captures the URL and notifies the local scraper. The scraper extracts the exact subdomains assigned to feed ads/data for that page session.
2. **DNS Sinkhole**: DNS queries for these specific ad subdomains are redirected to a local server running on port 53. It immediately resolves them to `0.0.0.0`.
3. **Deep Packet Inspection (DPI)**: For connections that bypass DNS (e.g., cached IPs or hardcoded client connections), the C++ sniffer reads outgoing traffic on port 443. It extracts the plaintext **Server Name Indication (SNI)** in the TLS Client Hello handshake.
4. **Firewall Drop**: If the SNI matches a blocked domain, the system adds a block rule directly to your operating system's firewall for that server's IP address. The connection is terminated instantly.

For a detailed breakdown of the network packet logic and multi-threaded architecture, see [design.md](file:///c:/Users/pglap/OneDrive/Desktop/add%20blocker/design.md).

---

## 📁 Repository Structure
```
YOUTUBE-BLOCKER/
│
├── src/                        # C++ DPI Engine Source Files
│   ├── live_dpi.cpp           # Sniffer Entry point (captures packets, triggers firewall)
│   ├── dpi_mt.cpp             # Multi-threaded PCAP processor (reference architecture)
│   ├── packet_parser.cpp      # Layer 2/3/4 Header Decoder
│   ├── sni_extractor.cpp      # TLS Client Hello Handshake Parser
│   └── rule_manager.cpp       # Thread-safe block rule controller
│
├── include/                    # C++ Header Files
│   ├── packet_parser.h
│   ├── sni_extractor.h
│   └── types.h
│
├── extension/                  # Chrome Extension Companion
│   ├── manifest.json          # Extension Manifest V3
│   ├── background.js          # Listens for tab updates & updates blocklist
│   ├── popup.html             # Pop-up UI
│   └── popup.js               # Fetches stats from Flask API
│
├── templates/                  # Flask UI Templates
│   └── index.html             # Beautiful Dark-theme Web Dashboard
│
├── block_ads.py                # Main Orchestrator (Starts DNS, Web Server & DPI Engine)
├── dns_server.py               # Custom dnslib-based DNS Server & Resolver
├── dashboard.py                # Flask Web Server & API backend
├── blocklist.txt               # Main blacklist containing blocked domain suffixes
├── install_startup_task.bat    # Windows Scheduled Task installer
├── uninstall_startup_task.bat  # Windows scheduled task and clean-up script
└── Makefile                    # Compiles C++ DPI binaries
```

---

## 🛠️ Prerequisites
- **Python 3.8+**
  - Install dependencies: `pip install requests dnslib flask`
- **C++ Compiler (C++17 support)**
  - Windows: **MinGW-w64** (GCC) or **MSVC** (Visual Studio)
  - Linux/macOS: **GCC** or **Clang**
- **Npcap / Libpcap Library**
  - Windows: Install **Npcap** in "WinPcap API-compatible mode" (https://npcap.com/)
  - Linux: `sudo apt install libpcap-dev`
  - macOS: Built-in (Requires Xcode command line tools)

---

## 🚀 Installation & Setup

### Windows Setup (Recommended)

#### Step 1: Install Npcap
1. Download Npcap from [npcap.com](https://npcap.com/).
2. Run the installer and make sure to check the option:
   - `[x] Install Npcap in WinPcap API-compatible mode`
3. Finish the installation.

#### Step 2: Install Compiler (MinGW-w64)
1. Download MSYS2 from [msys2.org](https://www.msys2.org/).
2. Install to `C:\msys64`.
3. Open **MSYS2 MINGW64** from the Start Menu (not the default MSYS2 terminal) and run:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
   ```
4. Add `C:\msys64\mingw64\bin` to your Windows **PATH** Environment Variable.
5. Restart your computer.

#### Step 3: Run the Orchestrator
Open a Command Prompt (cmd) or PowerShell **as Administrator** and run:
```cmd
python block_ads.py
```
This script will:
- Check for Administrator permissions.
- Automatically compile the C++ `live_dpi.cpp` engine.
- Copy Npcap DLLs to the local workspace for compatibility.
- Configure system DNS settings to route through `127.0.0.1` and `::1`.
- Start the DNS sinkhole, Flask Web server, and the C++ sniffing thread.

---

### Chrome Extension Installation
1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer Mode** in the top right corner.
4. Click **Load unpacked** in the top left.
5. Select the `extension/` folder inside this project directory.
6. Pin the **Hybrid Ad-Blocker Companion** extension.

---

### Linux / macOS Setup

#### Step 1: Install Dependencies
```bash
# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential libpcap-dev python3-pip
pip3 install requests dnslib flask

# macOS
xcode-select --install
pip3 install requests dnslib flask
```

#### Step 2: Compile and Run
Run the orchestrator with `sudo` (required to bind to DNS port 53 and read network interfaces):
```bash
sudo python3 block_ads.py
```

---

## ⚡ Usage Instructions

Once the orchestrator (`block_ads.py`) is running and the Chrome Extension is loaded:
- Open your browser and navigate to a YouTube video.
- The companion extension will automatically detect the URL and ping the orchestrator.
- The scraper adds video stream domains (e.g. `rr---sn-p5qlsmz7.googlevideo.com`) dynamically to `blocklist.txt`.
- The local DNS server immediately sinkholes requests to these hosts.
- Any outgoing HTTPS traffic matching these hosts is blocked on sight by the C++ packet sniffer and banned from your network adapter using your firewall.
- Open **http://127.0.0.1:5000** in your browser to watch the real-time block log!

---

## 📊 The Dashboard
The web dashboard is fully interactive and provides visual feedback on system activity:
- **DNS Resolution Stats**: Displays total queries routed, total queries blocked, and overall block percentage.
- **Dynamic Scraper Form**: Submit YouTube URLs manually to extract and block ad domains directly from the UI.
- **DPI Log Stream**: View timestamps, target SNI hostnames, destination IPs, and the engine action taken (DNS Sinkhole or IP Firewall Ban).

---

## 🧹 Uninstalling

### Windows Startup Removal & Cleanup
If you installed the background scheduled task, run the uninstall script **as Administrator**:
```cmd
uninstall_startup_task.bat
```
This script will:
- Stop and delete the Scheduled Task.
- Terminate all active background instances of the DNS server, Dashboard, and DPI engine.
- Revert your network adapters' primary DNS settings back to DHCP mode.

On Linux/macOS, simply press `Ctrl+C` in the terminal running `block_ads.py` to restore original DNS settings and clean up firewall rules.

---

## 🛠️ Technical Deep Dive
For a detailed analysis of the program architecture, flow diagrams, and internal code modules:
- Check out **[design.md](file:///c:/Users/pglap/OneDrive/Desktop/add%20blocker/design.md)** in the repository root.
- Read how we decode raw Ethernet headers, parse IPv4/TCP layers, navigate SSL Client Hellos, and manage safe concurrent queues in C++.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
