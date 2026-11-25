from scapy.all import Raw
import re

CRED_PATTERNS = [
    re.compile(rb"username=([^&\s]+)", re.IGNORECASE),
    re.compile(rb"password=([^&\s]+)", re.IGNORECASE),
    re.compile(rb"USER\s+(\S+)", re.IGNORECASE),
    re.compile(rb"PASS\s+(\S+)", re.IGNORECASE),
]

def detect(packets):
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            for pattern in CRED_PATTERNS:
                match = pattern.search(payload)
                if match:
                    print(f"[!] Possible plaintext credential: {match.group(0)[:60]}")
