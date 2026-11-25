from scapy.all import TCP, IP
from collections import Counter

def detect(packets):
    rst_counts = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == "RA" or pkt[TCP].flags == "R":
                rst_counts[pkt[IP].src] += 1

    for ip, count in rst_counts.items():
        if count >= 5:
            print(f"[!] {ip} sent {count} RST packets — possible refused/failed connections")
