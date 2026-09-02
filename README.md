🐍 Viper

A lightweight, highly concurrent TCP port scanner written in Python. Designed to be fast, clean, and easy to use, featuring service detection, customizable threading, and multi-format output exporting.
✨ Features

    Custom Thread Count (-t): Control the speed! Adjust the number of concurrent threads (default: 100) for lightning-fast scans or stealthy, low-and-slow scans.
    Smart Defaults: Automatically scans the top ~55 most common ports if no range is specified, giving you instant, meaningful results.
    Service Detection (-sV): Grabs banners to identify the actual service and version running on the port.
    Verbose Mode (-v): Prints ports to the console live as they are being scanned.
    Multi-Format Exporting: Save scan results to a human-readable text file (-oN) OR a machine-readable JSON file (-oJ) for integration with other tools.
    CLI Aesthetic: Features a clean ASCII art banner, colored terminal output, and precise scan timing metrics.
    Flexible Port Targeting (-p): Scan single ports, comma-separated lists, or custom ranges.

📦 Requirements

    Python 3.10+ (Uses modern type hinting)

No external libraries are required! Viper runs purely on Python standard libraries (socket, argparse, concurrent.futures, json).
🛠️ Usage

python viper.py <target> [options]

🛠️ Usage

python viper.py <target> [options]

Options
Flag
	
Description
target	Target IP address or domain name (e.g., 192.168.1.1 or scanme.nmap.org).
-p	Port range to scan (e.g., 1-1024 or 22,80,443). Defaults to top common ports.
-sV	Enable service detection (banner grabbing).
-v	Enable verbose output (live scanning progress).
-t	Number of concurrent threads (default: 100).
-oN	Save scan results to a specified text file.
-oJ	Save scan results to a specified JSON file.

⚠️ Legal & Ethical Disclaimer

This tool is intended for educational purposes and authorized network auditing only. Port scanning without explicit permission from the target owner may be illegal and is considered an attack in many jurisdictions. Only scan networks and devices you own or have explicit permission to test.
📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
