from scapy.all import TCP, IP
from collections import defaultdict

def detect(packets, threshold=10):
    scan_attempts = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            if flags == "S":
                src = pkt[IP].src
                dst_port = pkt[TCP].dport
                scan_attempts[src].add(dst_port)

    for src, ports in scan_attempts.items():
        if len(ports) >= threshold:
            print(f"[!] Possible port scan from {src} — {len(ports)} ports probed")
