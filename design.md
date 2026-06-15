# 🛠️ System Design: Hybrid DNS & DPI YouTube Ad-Blocker

This document details the architecture, data flows, and sub-system specifications of the Hybrid DNS & DPI YouTube Ad-Blocker.

---

## 🗺️ Architectural Overview

The project is structured as a closed-loop system across user space (Chrome extension, Python services, C++ sniffer), network stack, and kernel space (OS packet filter/firewall).

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                           USER SPACE                             │
 │                                                                  │
 │  ┌──────────────────┐               ┌─────────────────────────┐  │
 │  │ Chrome Extension │               │ Flask App / Dashboard   │  │
 │  │ (Tab listener)   ├──────────────►│ (Saves to blocklist.txt)│  │
 │  └──────────────────┘  HTTP POST    └───────────┬─────────────┘  │
 │                                                 │                │
 │                                                 ▼                │
 │                                         ┌───────────────┐        │
 │                          ┌─────────────►│ blocklist.txt │        │
 │                          │ File Read   └───────┬───────┘        │
 │                          │                     │ File Watcher   │
 │                          │                     ▼                │
 │                  ┌───────┴───────┐     ┌───────────────┐        │
 │                  │  DNS Server   │     │  C++ Engine   │        │
 │                  │ (Port 53 Res) │     │ (Npcap Loop)  │        │
 │                  └───────┬───────┘     └───────┬───────┘        │
 └──────────────────────────┼─────────────────────┼────────────────┘
                            │                     │
 ┌──────────────────────────┼─────────────────────┼────────────────┐
 │                      KERNEL SPACE              │                │
 │                          ▼                     ▼                │
 │                  ┌───────────────┐     ┌───────────────┐        │
 │                  │  DNS Sinkhole │     │  OS Firewall  │        │
 │                  │ (IPv4: 0.0.0.0)     │ (netsh rules) │        │
 │                  └───────────────┘     └───────────────┘        │
 └──────────────────────────────────────────────────────────────────┘
```

---

## 🎛️ Component Analysis

### 1. The Chrome Extension Companion (`extension/`)
- **Role**: Active interceptor of browser navigation.
- **Trigger**: Listens to Chrome’s `chrome.tabs.onUpdated` event.
- **Behavior**: When the updated URL matches `youtube.com/watch?v=` or `youtu.be/`, it issues an asynchronous HTTP POST request to the local Flask server. It transmits the video URL for dynamic ad-host parsing.
- **Popup UI**: Queries `/api/stats` every 4 seconds to update current DNS block statistics and show live logs of blocks.

### 2. The Local DNS Server (`dns_server.py`)
- **Role**: Sub-net address control.
- **Libraries**: `dnslib` is used to build a custom resolver.
- **Initialization**:
  - Automatically identifies all connected network adapters (using `netsh` on Windows, `networksetup` on macOS, or `/etc/resolv.conf` on Linux).
  - Switches primary DNS configuration of active adapters to loopback `127.0.0.1` (IPv4) and `::1` (IPv6).
  - Restores settings back to DHCP on system shutdown.
- **Resolving Logic**:
  - Listens on Port 53.
  - Queries match checking: checks if the requested hostname exactly equals or ends with any line in `blocklist.txt`.
  - **Sinkhole Action**: If matched, it returns an `A` record mapping the domain to `0.0.0.0` with a low TTL (60 seconds) to prevent client-side caching of the block state, logs it, and increments stats.
  - **Forward Action**: If unmatched, it forwards the query to Google DNS (`8.8.8.8`) on Port 53.

### 3. C++ Live DPI Engine (`src/live_dpi.cpp`)
- **Role**: Real-time packet parsing and firewall trigger.
- **Flow**:
  - Initializes `pcap_open_live` on the active network adapter.
  - Compiles and loads a Berkeley Packet Filter (BPF) string `"tcp port 443"` to exclude all UDP, ICMP, and non-HTTPS traffic, maximizing sniffer performance.
  - Parses captured packets layer by layer.
  - Extracts SNI (Server Name Indication) from the TLS Client Hello.
  - Compares the SNI against `blocklist.txt`.
  - On a match:
    1. **Log block**: Records the event to `dpi_log.txt`.
    2. **Firewall Ban**: Spawns a sub-process shell command adding a block rule targeting the destination IP:
       - **Windows**: `netsh advfirewall firewall add rule name="Block-YT-Ad-[IP]" dir=out action=block remoteip=[IP]`
       - **Linux**: `iptables -I OUTPUT -d [IP] -j DROP`
       - **macOS**: `pfctl` anchor insertion.

---

## 📡 Packet Parsing & SNI Extraction

To identify domains inside encrypted TLS (HTTPS) connections, the C++ packet parser decodes headers down to Layer 7 payload.

### Protocol Laying Architecture
```
┌─────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 Bytes)                                  │
│ - Dest MAC [0-5] | Src MAC [6-11] | EtherType [12-13]       │
├─────────────────────────────────────────────────────────────┤
│ IPv4 Header (Minimum 20 Bytes)                              │
│ - Protocol (0x06 = TCP) | Src IP | Dest IP                  │
├─────────────────────────────────────────────────────────────┤
│ TCP Header (Variable, minimum 20 Bytes)                     │
│ - Src Port | Dest Port (443) | Data Offset (Header size)    │
├─────────────────────────────────────────────────────────────┤
│ TLS Plaintext Handshake Payload                             │
│ - Content Type (0x16 = Handshake)                           │
│ - Handshake Type (0x01 = Client Hello)                      │
│ - Extensions -> SNI Extension (Type 0x0000)                 │
└─────────────────────────────────────────────────────────────┘
```

### SNI Byte Offset Matching Protocol
1. **Handshake Verification**:
   - Check if payload byte `0 == 0x16` (TLS Handshake Record).
   - Check if payload byte `5 == 0x01` (Handshake Type: Client Hello).
2. **Parsing Extensions**:
   - Start parsing at offset `43` (skips Version, Random, and Session ID length).
   - Skip Session ID data, Cipher Suite lists, and Compression lists.
   - Read the Extensions overall length.
   - Loop through each extension block:
     - Read 2 bytes for Extension Type.
     - Read 2 bytes for Extension Length.
     - If Type is `0x0000` (Server Name Indication), decode the payload:
       - Read hostname list length (2 bytes).
       - Read server name type (1 byte, `0x00` = hostname).
       - Read hostname string length (2 bytes).
       - Extract the ASCII hostname from the offset buffer.

---

## 🧵 Multi-Threaded Reference Architecture (`src/dpi_mt.cpp`)

For heavy packet loads, the system features a decoupled, multi-threaded pipeline designed to prevent packet loss.

```
                     ┌──────────────────┐
                     │  Reader Thread   │ (pcap_next)
                     └────────┬─────────┘
                              │
               ┌──────────────┴──────────────┐
               │     hash(5-tuple) % LBs     │ Consistent Hashing
               ▼                             ▼
     ┌──────────────────┐          ┌──────────────────┐
     │   Load Balancer  │          │   Load Balancer  │
     │     Thread 0     │          │     Thread 1     │
     └────────┬─────────┘          └────────┬─────────┘
              │                             │
       ┌──────┴──────┐               ┌──────┴──────┐
       │ hash % FPs  │               │ hash % FPs  │
       ▼             ▼               ▼             ▼
 ┌──────────┐ ┌──────────┐     ┌──────────┐ ┌──────────┐
 │FastPath 0│ │FastPath 1│     │FastPath 2│ │FastPath 3│ (DPI engine / Rules)
 └────┬─────┘ └────┬─────┘     └────┬─────┘ └────┬─────┘
      │            │                │            │
      └────────────┴───────┬────────┴────────────┘
                           │ Pushes to Output Queue
                           ▼
                  ┌──────────────────┐
                  │   Output Queue   │ (TSQueue)
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Writer Thread   │ (pcap_dump to disk)
                  └──────────────────┘
```

### Thread Components
1. **Reader Thread**: Acts as the sole receiver. It pulls packets from the capture buffer and computes a fast 5-tuple hash to assign the packet to a specific **Load Balancer (LB)** thread.
2. **Load Balancer Threads**: Maintain light queues. They compute a secondary hash to load balance the traffic evenly among the **Fast Path (FP)** processing threads.
3. **Fast Path Threads**: The core processors. Each FP thread keeps its own isolated connection flow map. This design prevents locks on shared memory. FP threads parse the TLS headers, check block rules, and decide to drop or forward the packet.
4. **Writer Thread**: Pulls approved packets from a unified output queue (`TSQueue`) and commits them to the output PCAP file.

### Consistent Flow Hashing
To correctly track TLS handshakes, every packet belonging to the same connection flow must go to the same Fast Path thread. A **5-tuple hash** maps connections consistently:
$$\text{Hash} = (\text{SrcIP} \oplus \text{DestIP}) + (\text{SrcPort} \oplus \text{DestPort}) + \text{Protocol}$$
The thread index is selected via modulo arithmetic:
$$\text{ThreadIndex} = \text{Hash} \pmod N$$
This ensures that TCP packets representing a flow are processed sequentially on the same CPU core, preserving TCP packet ordering and avoiding synchronization overhead.

---

## 💾 IPC & File Synchronization

Because the services run as independent operating system processes, communication is handled asynchronously using file-level watch interfaces:

- **`blocklist.txt` Sync**: 
  - The Flask Dashboard appends domains to this file.
  - The C++ Sniffer starts a background file-watch thread. It polls the filesystem timestamp of `blocklist.txt` every 2 seconds via `std::filesystem::last_write_time`.
  - When a change is detected, it reloads the blocklist into memory without interrupting packet capture.
- **`dns_stats.json` Sync**:
  - The DNS resolver updates query metrics and writes them to a JSON file.
  - Flask reads this file to update visual counters in the Dashboard API.
- **`dpi_log.txt` Stream**:
  - Both `dns_server.py` and `live_dpi.exe` append blocked logs directly to this shared text file.
  - Flask parses this file using regular expressions and streams the 20 most recent entries in reverse chronological order.
