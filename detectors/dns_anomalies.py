from scapy.all import DNS, DNSQR
from collections import Counter

def detect(packets):
    queries = Counter()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="ignore")
            queries[qname] += 1

    for domain, count in queries.items():
        if len(domain) > 50:
            print(f"[!] Unusually long DNS query (possible tunneling): {domain}")
        if count > 20:
            print(f"[!] High-frequency DNS query: {domain} ({count} times)")
