
# 🐍 Viper

A lightweight, highly concurrent TCP port scanner written in Python. Designed to be fast, clean, and easy to use, featuring service detection, OS fingerprinting, subnet scanning, and multi format output exporting.

## ✨ Features

- **Host Discovery (`-sn`):** Perform a fast ping sweep to identify live hosts on a subnet before scanning.
- **Read Targets From File (`-iL`):** Scan a large list of IPs, domains, or CIDR subnets directly from a text file.
- **Exclude Ports (`--exclude`):** Skip specific ports during a scan to save time or avoid known services.
- **Delay Between Probes (`--delay`):** Add a random delay between connection attempts to evade firewalls and intrusion detection systems.
- **OS Detection (`-O`):** Performs ICMP ping fingerprinting to guess the target Operating System (Windows, Linux/Unix, or Network Devices) based on TTL values.
- **Custom Thread Count (`-t`):** Control the speed! Adjust the number of concurrent threads (default: 100) for lightning fast scans or stealthy, low and slow scans.
- **Smart Defaults:** Automatically scans the top ~65 most common ports if no range is specified, giving you instant, meaningful results.
- **Service Detection (`-sV`):** Grabs banners to identify the actual service and version running on the port. Includes smart HTTP header parsing and a massive built in dictionary of common ports.
- **Verbose Mode (`-v`):** Displays a dynamic progress bar showing scan completion percentage and the current target.
- **Multi Format Exporting:** Save scan results to a human readable text file (`-oN`) OR a machine readable JSON file (`-oJ`) for integration with other tools.
- **CLI Aesthetic:** Features a clean ASCII art banner, colored terminal output, and precise scan timing metrics.
- **Flexible Port Targeting (`-p`):** Scan single ports, comma separated lists, custom ranges, or entire CIDR subnets.

## 📦 Requirements

- Python 3.10+ (Uses modern type hinting)

No external libraries are required! Viper runs purely on Python standard libraries (`socket`, `argparse`, `concurrent.futures`, `json`, `ipaddress`, `subprocess`).

## 🛠️ Usage

```bash
python viper.py <target> [options]
```

### Options

| Flag | Description |
| :--- | :--- |
| `target` | Target IP, domain, or CIDR subnet (e.g., `192.168.1.0/24`). Optional if using `-iL`. |
| `-iL` | Read targets from a specified text file. |
| `-p` | Port range to scan (e.g., `1-1024` or `22,80,443`). Defaults to top common ports. |
| `--exclude` | Exclude specific ports (e.g., `80,443`). |
| `-sV` | Enable service detection (banner grabbing). |
| `-O` | Enable OS detection via ICMP TTL fingerprinting. |
| `-sn` | Perform a ping sweep only (disable port scanning). |
| `-v` | Enable verbose output (dynamic progress bar). |
| `-t` | Number of concurrent threads (default: 100). |
| `--delay` | Add a random delay in seconds between probes (e.g., 0.5). |
| `-oN` | Save scan results to a specified text file. |
| `-oJ` | Save scan results to a specified JSON file. |

### Examples

**1. Quick default scan (Top common ports):**
```bash
python viper.py scanme.nmap.org
```

**2. Scan a full subnet with OS detection and high threads:**
```bash
python viper.py 10.10.10.0/24 -O -t 200
```

**3. Read targets from a file and exclude ports:**
```bash
python viper.py -iL targets.txt --exclude 22,80
```

**4. Ping sweep only to find live hosts:**
```bash
python viper.py 10.10.10.0/24 -sn
```

**5. Verbose scan with delay saving to JSON:**
```bash
python viper.py scanme.nmap.org -p 1-1000 -v --delay 0.5 -oJ results.json
```

## ⚠️ Legal & Ethical Disclaimer

This tool is intended for educational purposes and authorized network auditing only. Port scanning without explicit permission from the target owner may be illegal and is considered an attack in many jurisdictions. **Only scan networks and devices you own or have explicit permission to test.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
