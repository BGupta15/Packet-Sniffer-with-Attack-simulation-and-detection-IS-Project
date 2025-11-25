import asyncio
import ipaddress
import json
import platform
import socket
import ssl
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import re
import requests

from scapy.all import (
    AsyncSniffer,
    ARP,
    DNS,
    DNSRR,
    Ether,
    IP,
    TCP,
    UDP,
    get_if_addr,
    get_if_list,
    srp,
    traceroute,
)
from tqdm import tqdm

# Global variable
captured_ips = set()
results = {}
ttl_data = {}
mac_data = {}
port_usage = defaultdict(int)

arp_baseline = {}
portscan_tracker = {}
syn_counter = Counter()
dns_records = {}
alert_log_path = "alerts.log"
alerts = []

PORTSCAN_PORT_THRESHOLD = 20
PORTSCAN_WINDOW = 30
SYN_FLOOD_THRESHOLD = 80
SYN_WINDOW = 5

semaphore = asyncio.Semaphore(2)
host_locks = defaultdict(lambda: asyncio.Semaphore(2))
global_semaphore = asyncio.Semaphore(20)
executor = ThreadPoolExecutor(max_workers=8)

running_tasks = set()
stop_event = asyncio.Event()
_cleanup_thread_stop = threading.Event()


# Utilities
def log_alert(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    alerts.append({"ts": ts, "msg": msg})
    try:
        with open(alert_log_path, "a") as af:
            af.write(line + "\n")
    except Exception:
        pass


def guess_os(ttl: int, hostname: str = "", open_ports: dict = None, mac: str = ""):
    open_ports = open_ports or {}
    hostname = hostname.lower()

    # TTL-based
    if ttl >= 250:
        base_guess = "Router/IoT"
    elif ttl >= 120:
        base_guess = "Windows"
    elif ttl >= 60:
        base_guess = "Linux/Unix"
    elif ttl > 0:
        base_guess = "Embedded/Unknown"
    else:
        base_guess = "Unknown"

    # Port-based
    port_list = list(open_ports.keys())
    if 135 in port_list or 139 in port_list or 445 in port_list:
        return "Windows"
    if 22 in port_list or 111 in port_list or 2049 in port_list:
        return "Linux/Unix"
    if 80 in port_list and 23 in port_list:
        base_guess = "Router/IoT"

    # Hostname hints
    if re.search(r"(win|desktop|brinda)", hostname):
        return "Windows"
    if re.search(r"(ubuntu|debian|kali|raspberry|pi|linux|server)", hostname):
        return "Linux/Unix"
    if re.search(r"(router|dsl|lan|tplink|dlink|gateway|modem)", hostname):
        return "Router/IoT"

    # MAC vendor lookup 
    if mac and mac != "Unknown":
        try:
            vendor = requests.get(f"https://api.macvendors.com/{mac}", timeout=5).text
            if any(v in vendor.lower() for v in ["microsoft", "intel"]):
                return "Windows"
            if any(v in vendor.lower() for v in ["raspberry", "canon", "tp-link", "cisco"]):
                return "Router/IoT"
            if any(v in vendor.lower() for v in ["apple"]):
                return "macOS/iOS"
            if any(v in vendor.lower() for v in ["linux", "ubuntu"]):
                return "Linux/Unix"
        except Exception:
            pass

    return base_guess



def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def geoip_lookup(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return "Local"
    except Exception:
        pass
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json", timeout=6)
        data = res.json()
        city = data.get("city") or ""
        country = data.get("country_name") or ""
        if city or country:
            return ", ".join([s for s in (city, country) if s])
        region = data.get("region") or data.get("country") or data.get("country_code")
        if region:
            return region
        return "Unknown"
    except Exception:
        return "Unknown"



def get_ssl_info(ip: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                cn = ""
                issuer = ""
                try:
                    cn = cert.get("subject", [[("", "")]])[0][0][1]
                except Exception:
                    pass
                try:
                    issuer = cert.get("issuer", [[("", "")]])[0][0][1]
                except Exception:
                    pass
                return {"CN": cn, "Issuer": issuer, "Expiry": cert.get("notAfter")}
    except Exception:
        return {}

def _cleanup_worker():
    while not _cleanup_thread_stop.is_set():
        now = time.time()
        for src in list(portscan_tracker.keys()):
            entries = portscan_tracker.get(src, set())
            portscan_tracker[src] = {(p, t) for (p, t) in entries if now - t <= PORTSCAN_WINDOW}
            if not portscan_tracker[src]:
                del portscan_tracker[src]
        syn_counter.clear()
        time.sleep(SYN_WINDOW)


_cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True)
_cleanup_thread.start()


def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2: 
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        old = arp_baseline.get(ip)
        if old and old != mac:
            log_alert(f"ARP spoof suspected: {ip} previously {old}, now {mac}")
        arp_baseline[ip] = mac


def _is_syn(pkt):
    try:
        return pkt.haslayer(TCP) and (int(pkt[TCP].flags) & 0x02 != 0)
    except Exception:
        return False


def detect_portscan(pkt):
    if IP in pkt and _is_syn(pkt):
        src = pkt[IP].src
        dport = int(pkt[TCP].dport)
        now = time.time()
        entries = portscan_tracker.setdefault(src, set())
        entries.add((dport, now))
        unique_ports = {p for (p, _) in entries}
        if len(unique_ports) >= PORTSCAN_PORT_THRESHOLD:
            log_alert(f"Port scan suspected from {src} ({len(unique_ports)} unique ports in last {PORTSCAN_WINDOW}s)")


def detect_syn_flood(pkt):
    if IP in pkt and _is_syn(pkt):
        src = pkt[IP].src
        syn_counter[src] += 1
        if syn_counter[src] >= SYN_FLOOD_THRESHOLD:
            log_alert(f"SYN flood suspected from {src} ({syn_counter[src]} SYNs in last {SYN_WINDOW}s)")


def detect_dns_tamper(pkt):
    if pkt.haslayer(UDP) and int(pkt[UDP].sport) == 53 and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
        try:
            qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else None
            an = pkt[DNSRR]
            try:
                rdata = str(an.rdata)
            except Exception:
                rdata = repr(getattr(an, "rdata", None))
            prev = dns_records.get(qname)
            if prev and prev != rdata:
                log_alert(f"DNS tamper suspected for {qname}: {prev} -> {rdata}")
            dns_records[qname] = rdata
        except Exception:
            pass

# Active scanning helpers (async)
async def grab_banner(ip, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=1)
            return banner.decode(errors="ignore").strip()
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        return "Unknown"


async def scan_port(ip, port, timeout=1):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def scan_host_ports(ip, ports):
    open_ports = {}
    tasks = [scan_port(ip, port) for port in ports]
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Scanning {ip}", leave=True):
        port = await f
        if port:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "unknown"
            banner = await grab_banner(ip, port)
            open_ports[port] = {"service": service, "banner": banner}
            port_usage[port] += 1
    return open_ports


def run_traceroute(ip):
    try:
        res, _ = traceroute(ip, maxttl=10, verbose=False)
        return [r[1].src for r in res]
    except Exception:
        return []


def infer_cidr_from_iface(iface):
    try:
        ip = get_if_addr(iface)
        if ip and ip.count('.') == 3 and not ip.startswith("127."):
            network = ipaddress.ip_network(ip + '/24', strict=False)
            return str(network)
    except Exception:
        pass
    return "192.168.43.0/24"

def detection_only_mode(iface):
    print("[*] Running detection-only (IDS) on interface:", iface)

    def detector_prn(pkt):
        try:
            detect_arp_spoof(pkt)
            detect_portscan(pkt)
            detect_syn_flood(pkt)
            detect_dns_tamper(pkt)
        except Exception:
            pass

    try:
        sniffer = AsyncSniffer(iface=iface, prn=detector_prn, store=False)
        sniffer.start()
        return sniffer
    except Exception as e:
        print(f"[!] Detection sniff failed on {iface}: {e}")
        return None


def process_packet_factory(loop, ports, run_detectors=True, run_active_scans=True):
    def process_packet(pkt):
        if run_detectors:
            try:
                detect_arp_spoof(pkt)
                detect_portscan(pkt)
                detect_syn_flood(pkt)
                detect_dns_tamper(pkt)
            except Exception:
                pass
        if IP in pkt:
            for ip in [pkt[IP].src, pkt[IP].dst]:
                if not ip:
                    continue
                if ip not in captured_ips:
                    print(f"[NEW IP FOUND] {ip}")
                    captured_ips.add(ip)
                    try:
                        ttl_data[ip] = int(pkt[IP].ttl)
                    except Exception:
                        ttl_data[ip] = 0
                    if run_active_scans:
                        coro = handle_ip(ip, ports)

                        def _create_task():
                            task = asyncio.create_task(coro)
                            running_tasks.add(task)

                            def _on_done(t):
                                running_tasks.discard(t)

                            task.add_done_callback(_on_done)

                        loop.call_soon_threadsafe(_create_task)

    return process_packet


def passive_sniff(loop, interface, count, ports, run_detectors=True, run_active_scans=True):
    try:
        process_packet = process_packet_factory(loop, ports, run_detectors, run_active_scans)
        kwargs = {"iface": interface, "prn": process_packet, "store": False}
        if isinstance(count, int) and count > 0:
            kwargs["count"] = count
        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()
        return sniffer
    except Exception as e:
        print(f"[!] Sniff failed on interface {interface}: {e}")
        return None

async def handle_ip(ip, ports):
    async with global_semaphore:
        async with host_locks[ip]:
            print(f"\n[SCAN STARTED] {ip}")
            loop = asyncio.get_running_loop()
            hostname = await loop.run_in_executor(executor, reverse_dns, ip)
            guessed_os = guess_os(ttl_data.get(ip, 0))
            mac = mac_data.get(ip, "Unknown")
            geo = await loop.run_in_executor(executor, geoip_lookup, ip)
            ssl_info = {}
            if 443 in ports:
                ssl_info = await loop.run_in_executor(executor, get_ssl_info, ip)
            traceroute_path = await loop.run_in_executor(executor, run_traceroute, ip)
            open_ports = await scan_host_ports(ip, ports)

            results[ip] = {
                "hostname": hostname,
                "guessed_os": guessed_os,
                "mac": mac,
                "geoip": geo,
                "ssl": ssl_info,
                "traceroute": traceroute_path,
                "open_ports": open_ports,
            }
            try:
                with open("scan_results.json", "w") as f:
                    json.dump(results, f, indent=4)
            except Exception:
                pass

            print(f"[SCAN COMPLETE] {ip}")


def arp_discovery(interface):
    print(f"[*] Sending ARP requests on {interface}...")
    ip_range = infer_cidr_from_iface(interface)
    print(f"[*] ARP discovery using IP range {ip_range}")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    packet = ether / arp
    try:
        ans, _ = srp(packet, timeout=20, iface=interface, verbose=False)
    except Exception as e:
        print(f"[!] ARP discovery failed on {interface}: {e}")
        return

    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        captured_ips.add(ip)
        mac_data[ip] = mac
        ttl_data[ip] = 64



def show_port_trends():
    print("\n[*] Port Activity Trend (most common open ports):")
    for port, count in sorted(port_usage.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port}: Open on {count} device(s)")


def show_network_map():
    print("\n[*] Network Map (Simplified):")
    for ip, data in results.items():
        print(f"└── {ip} ({data.get('hostname')}) [{data.get('mac')}] → {data.get('guessed_os')}")


def choose_interface():
    ifaces = []
    try:
        ifaces = get_if_list()
    except Exception:
        pass
    if not ifaces:
        print("No interfaces detected via scapy.get_if_list(); defaulting to 'lo'")
        return "lo"
    print("\nAvailable interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"  [{i}] {iface}")
    print("  [x] Enter custom interface name")
    while True:
        choice = input("Select interface index (default loopback if unsure): ").strip()
        if choice == "":
            # try to find a loopback-ish iface
            for candidate in ifaces:
                if "Loopback" in candidate or "loopback" in candidate.lower() or candidate.lower().startswith("lo"):
                    print(f"Auto-selected interface: {candidate}")
                    return candidate
            # fallback to first iface
            print(f"Auto-selected interface: {ifaces[0]}")
            return ifaces[0]
        if choice.lower() == "x":
            custom = input("Enter interface name: ").strip()
            if custom:
                return custom
            else:
                continue
        try:
            idx = int(choice)
            if 0 <= idx < len(ifaces):
                return ifaces[idx]
        except Exception:
            pass
        print("Invalid choice, try again.")


def choose_mode():
    modes = ["passive", "arp", "detect-only"]
    print("\nModes:")
    for i, m in enumerate(modes):
        desc = {
            "passive": "Passive sniffing: discover IPs from traffic and (optionally) perform active scans",
            "arp": "ARP discovery: send ARP probes across inferred CIDR and actively scan discovered hosts",
            "detect-only": "Detection-only (IDS): run detectors (ARP spoof, portscan, SYN flood, DNS tamper) without active scans",
        }[m]
        print(f"  [{i}] {m} - {desc}")
    while True:
        choice = input("Choose mode index (default 2 = detect-only): ").strip()
        if choice == "":
            return "detect-only"
        try:
            idx = int(choice)
            if 0 <= idx < len(modes):
                return modes[idx]
        except Exception:
            pass
        print("Invalid input, try again.")


async def menu_main():
    print("=== Interactive Packet Sniffer Menu ===")
    mode = choose_mode()
    iface = choose_interface()
    pkt_count = input("Packet count for passive sniffing (default 100): ").strip()
    try:
        pkt_count = int(pkt_count) if pkt_count else 100
    except Exception:
        pkt_count = 100
    port_start = input("Start port for scans (default 20): ").strip()
    port_end = input("End port for scans (default 1024): ").strip()
    try:
        ps = int(port_start) if port_start else 20
        pe = int(port_end) if port_end else 1024
    except Exception:
        ps, pe = 20, 1024

    ports = list(range(ps, pe + 1))

    print("\nSummary of choices:")
    print(f"  Mode: {mode}")
    print(f"  Interface: {iface}")
    print(f"  Packet count (passive sniff): {pkt_count}")
    print(f"  Port range: {ps} - {pe} ({len(ports)} ports)")
    confirm = input("Proceed? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted by user.")
        return

    loop = asyncio.get_running_loop()
    if platform.system() != "Windows":
        import signal as _sig

        for sig in (_sig.SIGINT, _sig.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: stop_event.set())
            except NotImplementedError:
                pass
    else:
        def _win_watcher():
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                try:
                    loop.call_soon_threadsafe(stop_event.set)
                except Exception:
                    stop_event.set()

        t = threading.Thread(target=_win_watcher, daemon=True)
        t.start()

    sniffer = None
    try:
        if mode == "passive":
            print("[*] Passive sniffing started. Press Ctrl+C to stop.")
            sniffer = passive_sniff(loop, iface, pkt_count, ports, run_detectors=False, run_active_scans=True)
            if isinstance(pkt_count, int) and pkt_count > 0:
                try:
                    while sniffer and getattr(sniffer, "running", True):
                        await asyncio.sleep(0.2)
                except asyncio.CancelledError:
                    pass
            else:
                await stop_event.wait()
            if running_tasks:
                print("[*] Waiting up to 30s for active scan tasks to finish...")
                try:
                    await asyncio.wait(list(running_tasks), timeout=30)
                except Exception:
                    pass
        elif mode == "arp":
            print("[*] ARP discovery + active scan mode.")
            arp_discovery(iface)
            tasks = []
            for ip in list(captured_ips):
                coro = handle_ip(ip, ports)
                task = asyncio.create_task(coro)
                running_tasks.add(task)
                task.add_done_callback(lambda t: running_tasks.discard(t))
                tasks.append(task)
            if tasks:
                await asyncio.wait(tasks)
        elif mode == "detect-only":
            print("[*] Detection-only mode. Press Ctrl+C to stop.")
            sniffer = detection_only_mode(iface)
            await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass

    for t in list(running_tasks):
        try:
            t.cancel()
        except Exception:
            pass

    _cleanup_thread_stop.set()
    await asyncio.sleep(0.2)

    print(f"\n[*] Finished. {len(results)} IPs scanned (results saved to scan_results.json if any).")
    try:
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(menu_main())
    except KeyboardInterrupt:
        stop_event.set()
        time.sleep(0.1)
        print("\nInterrupted by user. Exiting.")