import time
from scapy.all import IP, TCP, UDP, DNS, DNSRR, DNSQR, send

LO = "127.0.0.1"
SRC = "10.0.0.50"
TARGET = LO

def send_port_scan(src=SRC, target=TARGET, start=20, end=60, delay=0.05):
    print("[SIM] Sending port-scan (SYNs) to", target)
    for p in range(start, end+1):
        pkt = IP(src=src, dst=target)/TCP(sport=40000, dport=p, flags="S")
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[SIM] Port-scan done")

def send_syn_flood(src=SRC, target=TARGET, count=120, delay=0.006):
    print("[SIM] Sending SYN flood to", target)
    for i in range(count):
        pkt = IP(src=src, dst=target)/TCP(sport=30000 + (i % 1000), dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[SIM] SYN flood done")

def send_dns_tamper(qname="example.local."):
    print("[SIM] Sending DNS responses (original + tampered) to", TARGET)
    resp1 = IP(src="8.8.8.8", dst=TARGET)/UDP(sport=53,dport=5353)/DNS(id=1, qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata="1.2.3.4"))
    send(resp1, verbose=False)
    time.sleep(0.05)
    resp2 = IP(src="8.8.8.8", dst=TARGET)/UDP(sport=53,dport=5353)/DNS(id=1, qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata="5.6.7.8"))
    send(resp2, verbose=False)
    print("[SIM] DNS tamper sent")

if __name__ == "__main__":
    print("Waiting 2 seconds for IDS to be ready...")
    time.sleep(2)
    send_port_scan()
    time.sleep(1)
    send_dns_tamper()
    time.sleep(30)
    send_syn_flood()
    print("All simulated traffic sent.")