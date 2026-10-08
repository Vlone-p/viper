
# 🐍 Viper

A lightweight, highly concurrent TCP port scanner written in Python. Designed to be fast, clean, and easy to use, featuring service detection, OS fingerprinting, subnet scanning, and multi format output exporting.

## ✨ Features

- **Live Open Port Alerts:** Prints discovered open ports to the console the exact millisecond they are found, eliminating the wait for the final results table.
- **Port State Detection:** Accurately distinguishes between `open`, `closed` (actively rejected), and `filtered` (dropped by a firewall) ports.
- **Modular Codebase:** Split into multiple files for easy maintenance and contribution.
- **Web Title Extraction:** Grabs HTML title tags and HTTP headers for instant web service identification.
- **Robust Banner Grabbing:** Securely wraps HTTPS ports in TLS to read encrypted banners and uses smart loops to capture large headers.
- **Hardened Input Validation:** Safely parses port ranges and catches malformed inputs without crashing.
- **Full Port Range (`-p-`):** Scan all 65535 ports using standard Nmap syntax.
- **Graceful Exit (`Ctrl+C`):** Safely cancel a scan and immediately view or save the partial results.
- **Scan Randomization (`--randomize`):** Shuffles target IPs and ports to evade firewalls and intrusion detection systems.
- **Configurable Timeout (`--timeout`):** Adjust socket timeouts for high latency networks.
- **XML Output (`-oX`):** Export scan results in standard XML format for easy parsing by enterprise security tools like Metasploit or Dradis.
- **Grepable Output (`-oG`):** Export results in a format easily searchable with standard Linux command line tools.
- **Safe Mode (`--safe`):** Presets that limit threads and add delays for stealthy or cautious auditing.
- **Host Discovery (`-sn`):** Perform a fast ping sweep to identify live hosts on a subnet before scanning.
- **Read Targets From File (`-iL`):** Scan a list of IPs, domains, or CIDR subnets from a text file.
- **Exclude Ports (`--exclude`):** Skip specific ports during a scan to save time.
- **OS Detection (`-O`):** Performs ICMP ping fingerprinting to guess the target OS based on TTL values.
- **Custom Thread Count (`-t`):** Control the speed with concurrent threads (default: 100) for lightning fast or low and slow scans.
- **Smart Defaults:** Automatically scans the top common ports if none are specified, giving you instant results.
- **Verbose Mode (`-v`):** Displays a dynamic progress bar showing scan completion percentage and the current target.
- **CLI Aesthetic:** Features a clean ASCII art banner, colored terminal output, and precise scan timing metrics.

## 📁 Project Structure

Viper is split into modular components to keep the code clean and organized:

- `viper.py` - Main entry point, CLI arguments, and output formatting.
- `scanner.py` - Threading logic, live alerts, and port state detection.
- `network.py` - Ping sweeps, OS detection, and target loading.
- `banners.py` - Robust banner grabbing, TLS wrapping, and web title parsing.
- `utils.py` - Terminal colors, port constants, and input validation.

## 📦 Requirements

- Python 3.10+ (Uses modern type hinting)

No external libraries are required! Viper runs purely on Python standard libraries (`socket`, `argparse`, `concurrent.futures`, `json`, `ssl`, `ipaddress`, `subprocess`, `xml`).

## 🛠️ Usage

```bash
python viper.py <target> [options]
```

### Options

| Flag | Description |
| :--- | :--- |
| `target` | Target IP, domain, or CIDR subnet (e.g., `192.168.1.0/24`). Optional if using `-iL`. |
| `-iL` | Read targets from a specified text file. |
| `-p` | Port range to scan (e.g., `1-1024` or `22,80,443`). Use `-p-` for all ports. Defaults to top common ports. |
| `--exclude` | Exclude specific ports (e.g., `80,443`). |
| `-sV` | Enable service detection (banner grabbing). |
| `-O` | Enable OS detection via ICMP TTL fingerprinting. |
| `-sn` | Perform a ping sweep only (disable port scanning). |
| `-v` | Enable verbose output (dynamic progress bar). |
| `-t` | Number of concurrent threads (default: 100). |
| `--timeout` | Socket timeout in seconds (default: 1.0). |
| `--delay` | Add a random delay in seconds between probes (e.g., 0.5). |
| `--safe` | Enable safe mode (limits threads to 10, adds 0.5s delay). |
| `--randomize` | Randomize target IPs and ports to evade firewalls. |
| `-oN` | Save scan results to a specified text file. |
| `-oJ` | Save scan results to a specified JSON file. |
| `-oX` | Save scan results to a specified XML file. |
| `-oG` | Save scan results to a specified grepable text file. |

### Examples

**1. Quick default scan (Top common ports):**
```bash
python viper.py scanme.nmap.org
```

**2. Full port scan with service detection and high threads:**
```bash
python viper.py 10.10.10.10 -p- -sV -t 500
```

**3. Read targets from a file, randomize scan, and save to XML format:**
```bash
python viper.py -iL targets.txt --randomize -oX results.xml
```

**4. Ping sweep only to find live hosts on a subnet:**
```bash
python viper.py 10.10.10.0/24 -sn
```

**5. Safe mode scan with custom timeout saving to JSON:**
```bash
python viper.py scanme.nmap.org -p 1-1000 --safe --timeout 2.0 -oJ results.json
```

## ⚠️ Legal & Ethical Disclaimer

This tool is intended for educational purposes and authorized network auditing only. Port scanning without explicit permission from the target owner may be illegal and is considered an attack in many jurisdictions. **Only scan networks and devices you own or have explicit permission to test.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
