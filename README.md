A Python-based network reconnaissance and intrusion detection tool built with Scapy. It combines passive traffic sniffing, active host scanning, ARP discovery, and real-time threat detection into a single interactive CLI.

# Features

* Passive Sniffing — Captures live traffic, discovers IPs, and optionally performs active scans on newly seen hostsn
* ARP Discovery — Sends ARP probes across the inferred subnet CIDR to enumerate live hosts
* Detection-Only (IDS) Mode — Lightweight mode that runs threat detectors without any active scanning
* Port Scanner — Async TCP port scanner with banner grabbing and service identification
* OS Fingerprinting — Guesses OS from TTL, open ports, hostname patterns, and MAC vendor lookups
* GeoIP Lookup — Resolves public IPs to city/country using ipapi.co
* Reverse DNS — Resolves hostnames for discovered IPs
* SSL/TLS Inspection — Grabs certificate CN, issuer, and expiry from port 443
* Traceroute — Maps the network path to each discovered host
* Results Export — Saves full scan results to scan_results.json

# Threat Detectors
DetectorWhat it catchesARP Spoof DetectionMAC address changes for a known IPPort Scan DetectionSource scanning ≥20 unique ports within 30 secondsSYN Flood DetectionSource sending ≥80 SYN packets within 5 secondsDNS Tamper DetectionDNS responses with changed rdata for a known query
All alerts are printed to stdout and appended to alerts.log.

# Requirements

Python 3.8+
Root / Administrator privileges (required for raw packet capture)
Linux or macOS recommended (Windows has limited Scapy support)

Install Dependencies
bashpip install scapy requests tqdm

Usage
```
bashsudo python sniffer.py
You will be prompted to configure the run interactively:
=== Interactive Packet Sniffer Menu ===


Modes:
  [0] passive       - Discover IPs from traffic and perform active scans
  [1] arp           - ARP probe the subnet and actively scan all hosts
  [2] detect-only   - Run IDS detectors only (no active scanning)

Choose mode index (default 2 = detect-only):

Available interfaces:
  [0] eth0
  [1] wlan0
  [x] Enter custom interface name
Select interface index:

Packet count for passive sniffing (default 100):
Start port for scans (default 20):
End port for scans (default 1024):
```
# Output
```
Console
[NEW IP FOUND] 192.168.1.105
[SCAN STARTED] 192.168.1.105
Scanning 192.168.1.105: 100%|████████████| 1005/1005
[SCAN COMPLETE] 192.168.1.105
[2025-01-01 12:00:00] Port scan suspected from 10.0.0.50 (22 unique ports in last 30s)
scan_results.json
json{
  "192.168.1.105": {
    "hostname": "my-laptop.local",
    "guessed_os": "Windows",
    "mac": "aa:bb:cc:dd:ee:ff",
    "geoip": "Local",
    "ssl": {},
    "traceroute": ["192.168.1.1"],
    "open_ports": {
      "80": { "service": "http", "banner": "Apache/2.4.51" },
      "445": { "service": "microsoft-ds", "banner": "Unknown" }
    }
  }
}
alerts.log
[2025-01-01 12:00:05] ARP spoof suspected: 192.168.1.1 previously aa:bb:cc:11:22:33, now ff:ee:dd:cc:bb:aa
[2025-01-01 12:00:10] SYN flood suspected from 10.0.0.50 (95 SYNs in last 5s)
```
# Traffic Simulator (simulate_attacks.py)
A companion script for testing the IDS detectors on loopback without a real attacker.
bashsudo python simulate_attacks.py
Sends three simulated attack sequences with a 1-second gap between each:

Port Scan — SYN packets to ports 20–60 from 10.0.0.50
DNS Tampering — Two DNS responses for the same query with different rdata
SYN Flood — 120 SYN packets to port 80

Run this in one terminal while sniffer.py is running in detect-only mode on the same interface to verify the detectors fire correctly.

# Architecture
sniffer.py
├── Passive sniff / ARP discovery          (scapy AsyncSniffer / srp)
├── handle_ip()                            (async per-host coordinator)
│   ├── reverse_dns()
│   ├── geoip_lookup()
│   ├── get_ssl_info()
│   ├── run_traceroute()
│   ├── scan_host_ports()
│   │   └── scan_port() + grab_banner()   (async TCP connect)
│   └── guess_os()
└── Detectors (run on every packet)
    ├── detect_arp_spoof()
    ├── detect_portscan()
    ├── detect_syn_flood()
    └── detect_dns_tamper()
Concurrency is managed with asyncio semaphores (global_semaphore caps total concurrent host scans; host_locks prevents duplicate scans per IP). A background cleanup thread periodically clears the port-scan and SYN-flood sliding windows.

# Limitations & Notes

* Root required — Raw socket capture needs elevated privileges on all platforms.
* Active scans are noisy — ARP and passive modes with active scanning enabled will generate TCP connect traffic to every discovered host. Use detect-only on production networks.
* MAC vendor lookups — OS fingerprinting calls api.macvendors.com; this will fail in air-gapped environments.
* GeoIP rate limits — ipapi.co has a free-tier limit of ~1,000 requests/day per IP.
* Windows support — Scapy on Windows requires Npcap and has reduced interface support.
