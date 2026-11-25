# PCAP Anomaly Analyzer

A command-line tool that scans network capture files (`.pcap`/`.pcapng`) and flags suspicious activity — port scans, failed connection floods, DNS anomalies, and plaintext credentials — using Python and Scapy.

## Why I built this

Built as part of my B.Sc. Cybersecurity & Digital Forensics coursework (Elphinstone College) to apply packet-level analysis concepts practically, rather than just reading about them. It's designed to be reusable on any pcap — including captures from my other lab work (Nmap reconnaissance, SSH/SMB brute-force testing).

## What it detects

| Detector | What it flags | Real-world technique it mirrors |
|---|---|---|
| Port scan | One source IP sending bare SYN packets to many distinct ports | Classic Nmap SYN scan detection, used in IDS/IPS rules |
| Failed connections | High volume of TCP RST packets from one IP | Refused connections / closed-port probing — common scan side-effect |
| DNS anomalies | Unusually long domain names or high-frequency repeated queries | DNS tunneling (data exfiltration / C2) detection heuristic |
| Plaintext credentials | Username/password strings in HTTP form data or FTP commands | Catching unencrypted credential transmission — why HTTPS/SFTP matter |

## How to run it

```bash
git clone <your-repo-url>
cd pcap-analyzer
python3 -m venv venv
source venv/bin/activate
pip install scapy

python3 analyzer.py sample_pcaps/<your-file>.pcap
```

## Sample output

Captured a live SYN scan (`nmap -sS <target> -p 1-100`) against a gateway on my lab network:

```
[*] Loading sample_pcaps/scan_test.pcap...
[*] Loaded 223 packets

=== Port Scan Detection ===
[!] Possible port scan from 192.168.200.128 — 100 ports probed

=== Failed Connection Analysis ===
[!] 192.168.200.2 sent 99 RST packets — possible refused/failed connections

=== DNS Anomalies ===

=== Plaintext Credential Check ===
```

The tool correctly identified both sides of the scan: the source probing 100 ports, and the target resetting 99 of them (only one port was open).

For comparison, a clean capture of normal web + DNS traffic (`curl`, `nslookup`) produces no false positives:

```
[*] Loading sample_pcaps/web_test.pcap...
[*] Loaded 23 packets

=== Port Scan Detection ===

=== Failed Connection Analysis ===

=== DNS Anomalies ===

=== Plaintext Credential Check ===
```

## Project structure

```
pcap-analyzer/
├── analyzer.py
├── detectors/
│   ├── port_scan.py
│   ├── failed_connections.py
│   ├── dns_anomalies.py
│   └── plaintext_creds.py
├── sample_pcaps/
└── requirements.txt
```

## Limitations / next steps

- Thresholds (port count, RST count, DNS frequency) are static — a future version could make these configurable via CLI flags.
- No encrypted traffic inspection (by design — this only looks at what's visible in plaintext).
- Built and tested on Kali Linux with Python 3.14 and Scapy 2.8.0.
- 
