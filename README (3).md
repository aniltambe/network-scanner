# Advanced Network Security Scanner & Logger

A comprehensive, multi-threaded network diagnostics, port scanning, and automated logging tool designed for network administrators and security auditors.

## Features
- **Multi-Threaded Port Scanning:** Scans target IPs/domains efficiently using customizable worker threads.
- **Service & Banner Grabbing:** Attempts to extract service information from common open ports (e.g., HTTP, FTP, SSH).
- **Subnet Scanner:** Scans entire subnets to detect active hosts on a local area network.
- **Detailed JSON/Text Logging:** Automatically saves structural diagnostic reports with timestamps.
- **Zero Third-Party Dependencies:** Built natively using Python standard modules (`socket`, `threading`, `json`, `datetime`).

## Prerequisites
- **Python 3.x** installed.

## How to Run
Execute the main script via terminal:
```bash
python network_scanner.py
```
