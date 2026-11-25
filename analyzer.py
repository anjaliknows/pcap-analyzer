from scapy.all import rdpcap
import argparse
from detectors import port_scan, failed_connections, dns_anomalies, plaintext_creds

def load_pcap(path):
    print(f"[*] Loading {path}...")
    packets = rdpcap(path)
    print(f"[*] Loaded {len(packets)} packets")
    return packets

def main():
    parser = argparse.ArgumentParser(description="PCAP anomaly analyzer")
    parser.add_argument("pcap", help="Path to .pcap/.pcapng file")
    args = parser.parse_args()

    packets = load_pcap(args.pcap)

    print("\n=== Port Scan Detection ===")
    port_scan.detect(packets)

    print("\n=== Failed Connection Analysis ===")
    failed_connections.detect(packets)

    print("\n=== DNS Anomalies ===")
    dns_anomalies.detect(packets)

    print("\n=== Plaintext Credential Check ===")
    plaintext_creds.detect(packets)

if __name__ == "__main__":
    main()
