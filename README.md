🚀 Fast Python Port Scanner

A lightweight, multi-threaded TCP port scanner written in Python. Designed to be fast, clean, and easy to use, with optional service detection (banner grabbing) and output exporting.
✨ Features

    Multi-threaded: Scans 100 ports concurrently for maximum speed.
    Smart Defaults: Automatically scans the top ~55 most common ports if no range is specified.
    Service Detection (-sV): Grabs banners to identify the actual service running on the port.
    Verbose Mode (-v): Prints ports to the console live as they are being scanned.
    Export Results (-oN): Saves scan results to a text file for later analysis.
    Flexible Port Targeting (-p): Scan single ports, comma-separated lists, or custom ranges.

📦 Requirements

    Python 3.10+ (Uses modern type hinting)

No external libraries are required! It uses only Python standard libraries (socket, argparse, concurrent.futures).
🛠️ Usage

python scanner.py <target> [options]

Options
Flag
	
Description
target	Target IP address or domain name (e.g., 192.168.1.1 or scanme.nmap.org).
-p	Port range to scan (e.g., 1-1024 or 22,80,443). Defaults to top common ports.
-sV	Enable service detection (banner grabbing).
-v	Enable verbose output (live scanning progress).
-oN	Save scan results to a specified text file.
