
# 🐍 Viper

A lightweight, highly concurrent TCP port scanner written in Python. Designed to be fast, clean, and easy to use, featuring service detection, OS fingerprinting, customizable threading, and multi-format output exporting.

## ✨ Features

- **OS Detection (`-O`):** Performs ICMP ping fingerprinting to guess the target's Operating System (Windows, Linux/Unix, or Network Devices) based on TTL values.
- **Custom Thread Count (`-t`):** Control the speed! Adjust the number of concurrent threads (default: 100) for lightning fast scans or stealthy, low and slow scans.
- **Smart Defaults:** Automatically scans the top ~65 most common ports if no range is specified, giving you instant, meaningful results.
- **Service Detection (`-sV`):** Grabs banners to identify the actual service and version running on the port. Includes smart HTTP header parsing and a massive built-in dictionary of common ports.
- **Verbose Mode (`-v`):** Prints ports to the console live as they are being scanned.
- **Multi-Format Exporting:** Save scan results to a human-readable text file (`-oN`) OR a machine-readable JSON file (`-oJ`) for integration with other tools.
- **CLI Aesthetic:** Features a clean ASCII art banner, colored terminal output, and precise scan timing metrics.
- **Flexible Port Targeting (`-p`):** Scan single ports, comma-separated lists, or custom ranges.

## 📦 Requirements

- Python 3.10+ (Uses modern type hinting)

No external libraries are required! Viper runs purely on Python standard libraries (`socket`, `argparse`, `concurrent.futures`, `json`, `subprocess`).

## 🛠️ Usage

```bash
python viper.py <target> [options]
```

### Options

| Flag | Description |
| :--- | :--- |
| `target` | Target IP address or domain name (e.g., `192.168.1.1` or `scanme.nmap.org`). |
| `-p` | Port range to scan (e.g., `1-1024` or `22,80,443`). Defaults to top common ports. |
| `-sV` | Enable service detection (banner grabbing). |
| `-O` | Enable OS detection via ICMP TTL fingerprinting. |
| `-v` | Enable verbose output (live scanning progress). |
| `-t` | Number of concurrent threads (default: 100). |
| `-oN` | Save scan results to a specified text file. |
| `-oJ` | Save scan results to a specified JSON file. |

### Examples

**1. Quick default scan (Top common ports):**
```bash
python viper.py scanme.nmap.org
```

**2. Full scan with Service Detection and OS Detection:**
```bash
python viper.py 10.129.179.51 -sV -O
```

**3. High-speed scan with 500 threads:**
```bash
python viper.py 192.168.1.1 -p 1-2000 -t 500
```

**4. Verbose scan saving results to BOTH text and JSON formats:**
```bash
python viper.py scanme.nmap.org -p 22,80,443 -sV -O -v -oN results.txt -oJ results.json
```

## ⚠️ Legal & Ethical Disclaimer

This tool is intended for educational purposes and authorized network auditing only. Port scanning without explicit permission from the target owner may be illegal and is considered an attack in many jurisdictions. **Only scan networks and devices you own or have explicit permission to test.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
