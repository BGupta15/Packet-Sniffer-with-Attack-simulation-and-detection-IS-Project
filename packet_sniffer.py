def infer_cidr_from_iface(iface):
    try:
        ip = get_if_addr(iface)
        if ip and ip.count('.') == 3 and not ip.startswith("127."):
            network = ipaddress.ip_network(ip + '/24', strict=False)
            return str(network)
    except Exception:
        pass
    return "192.168.43.0/24"


# -----------------------------
# Detection-only & passive helpers (sniff callbacks)
# -----------------------------
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
        # Run detectors only if requested
        if run_detectors:
            try:
                detect_arp_spoof(pkt)
                detect_portscan(pkt)
                detect_syn_flood(pkt)
                detect_dns_tamper(pkt)
            except Exception:
                pass

        # If we are in any sniffing mode, we must process IPs
        if IP in pkt:
            for ip in [pkt[IP].src, pkt[IP].dst]:
                if not ip:
                    continue
                
                # FIX: Add IP to captured_ips and log regardless of run_active_scans flag
                if ip not in captured_ips:
                    print(f"[NEW IP FOUND] {ip}")
                    captured_ips.add(ip)
                    try:
                        ttl_data[ip] = int(pkt[IP].ttl)
                    except Exception:
                        ttl_data[ip] = 0
                    
                    # Only create active scanning tasks if allowed
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
        # Note: run_detectors/run_active_scans flags control the behavior inside the prn callback
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
            mac = mac_data.get(ip, "Unknown")
            guessed_os_initial = guess_os(ttl_data.get(ip, 0))
            geo = await loop.run_in_executor(executor, geoip_lookup, ip)
            ssl_info = {}
            if 443 in ports:
                ssl_info = await loop.run_in_executor(executor, get_ssl_info, ip)
            
            traceroute_path = await loop.run_in_executor(executor, run_traceroute, ip)
            
            open_ports = await scan_host_ports(ip, ports)
            
            # Re-guess OS after port scanning provides more data
            guessed_os_final = guess_os(ttl_data.get(ip, 0), hostname, open_ports, mac)

            results[ip] = {
                "hostname": hostname,
                "guessed_os": guessed_os_final,
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


# -----------------------------
# Active ARP discovery mode
# -----------------------------
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
        # Add IPs from ARP to captured_ips (used by scan tasks)
        captured_ips.add(ip)
        mac_data[ip] = mac
        ttl_data[ip] = 64
        print(f"[ARP DISCOVERY] {ip} found.") # Log discovery


# -----------------------------
# Reporting helpers
# -----------------------------
def show_port_trends():
    print("\n[*] Port Activity Trend (most common open ports):")
    for port, count in sorted(port_usage.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port}: Open on {count} device(s)")


def show_network_map():
    print("\n[*] Network Map (Simplified):")
    for ip, data in results.items():
        print(f"└── {ip} ({data.get('hostname')}) [{data.get('mac')}] → {data.get('guessed_os')}")


# -----------------------------
# Interactive menu & main loop
# -----------------------------
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
        choice = input("Select interface index (default loopback): ").strip()
        if choice == "":
            for candidate in ifaces:
                if "Loopback" in candidate or "loopback" in candidate.lower() or candidate.lower().startswith("lo"):
                    print(f"Auto-selected interface: {candidate}")
                    return candidate
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
            "passive": "Passive sniffing: discover IPs and (optionally) run active scans (No detectors)",
            "arp": "ARP discovery: active scan discovered hosts (No detectors)",
            "detect-only": "Detection-only (IDS): run detectors (No sniffing/scanning)",
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
    
    # --- Mode-dependent user input ---
    pkt_count = 0
    ports = []
    run_active = False # Default to False, updated below

    if mode == "passive":
        pkt_count = input("Packet count for passive sniffing (default 100): ").strip()
        try:
            pkt_count = int(pkt_count) if pkt_count else 100
        except Exception:
            pkt_count = 100
        
        # Ask if active scanning should run during passive mode
        run_scan_choice = input("Run active port scans on discovered IPs? (y/N): ").strip().lower()
        if run_scan_choice == 'y':
            run_active = True
            port_start = input("Start port for scans (default 20): ").strip()
            port_end = input("End port for scans (default 1024): ").strip()
            try:
                ps = int(port_start) if port_start else 20
                pe = int(port_end) if port_end else 1024
            except Exception:
                ps, pe = 20, 1024
            ports = list(range(ps, pe + 1))
        
    elif mode == "arp":
        run_active = True # ARP mode always runs active scans after discovery
        port_start = input("Start port for scans (default 20): ").strip()
        port_end = input("End port for scans (default 1024): ").strip()
        try:
            ps = int(port_start) if port_start else 20
            pe = int(port_end) if port_end else 1024
        except Exception:
            ps, pe = 20, 1024
        ports = list(range(ps, pe + 1))
    
    # --- Summary & Confirmation ---
    print("\nSummary of choices:")
    print(f"  Mode: {mode}")
    print(f"  Interface: {iface}")
    if mode == "passive":
        print(f"  Packet count: {pkt_count}")
        print(f"  Active Scanning: {'ON' if run_active else 'OFF'}")
        if run_active:
             print(f"  Port range: {len(ports)} ports")
    elif mode == "arp":
        print(f"  ARP Mode: Discovery + Scanning")
        print(f"  Port range: {len(ports)} ports")
        
    confirm = input("Proceed? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted by user.")
        return

    loop = asyncio.get_running_loop()

    # --- Cross-platform signal handling ---
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
        # ---------------------------------------------
        # Mode Logic: Only ONE block executes
        # ---------------------------------------------
        if mode == "passive":
            print(f"[*] Passive sniffing started. Detectors: OFF. Active Scan: {'ON' if run_active else 'OFF'}.")
            
            # Use run_detectors=False to ensure no detector logic runs
            sniffer = passive_sniff(loop, iface, pkt_count, ports, run_detectors=False, run_active_scans=run_active)
            
            if isinstance(pkt_count, int) and pkt_count > 0:
                try:
                    while sniffer and getattr(sniffer, "running", True):
                        await asyncio.sleep(0.2)
                except asyncio.CancelledError:
                    pass
            else:
                await stop_event.wait()

            if running_tasks and run_active:
                print("[*] Waiting up to 30s for active scan tasks to finish...")
                try:
                    await asyncio.wait(list(running_tasks), timeout=30)
                except Exception:
                    pass

        elif mode == "arp":
            print("[*] ARP discovery + active scan mode. Detectors BLOCKED.")
            # 1. Perform ARP discovery (synchronous)
            arp_discovery(iface) 
            
            # 2. Launch scan tasks for discovered IPs
            tasks = []
            for ip in list(captured_ips):
                if ip not in results:
                    coro = handle_ip(ip, ports)
                    task = asyncio.create_task(coro)
                    running_tasks.add(task)
                    task.add_done_callback(lambda t: running_tasks.discard(t))
                    tasks.append(task)
            
            # 3. Wait for all scans to finish
            if tasks:
                await asyncio.wait(tasks)

        elif mode == "detect-only":
            print("[*] Detection-only mode is running. Sniffing is continuous, NO Active scanning is run.")
            sniffer = detection_only_mode(iface)
            await stop_event.wait()
        
    except asyncio.CancelledError:
        pass
    finally:
        # ---------------------------------------------
        # Cleanup section runs regardless of mode choice
        # ---------------------------------------------
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass

        # polite cancellation of running tasks
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