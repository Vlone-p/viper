# 🐍 Viper

A lightweight, highly concurrent TCP port scanner written in Python. Designed to be fast, clean, and easy to use, featuring service detection, OS fingerprinting, subnet scanning, firewall evasion, and multi format output exporting.

## ✨ Features

- **Standard Timing Profiles (`-T1` to `-T10`):** Precise control over scan speed, from slow and stealthy to insanely fast.
- **Source Port Manipulation (`-g`):** Spoof the source port (e.g., 53 for DNS) to bypass strict firewalls and access control lists.
- **Dynamic Top Ports (`--top-ports`):** Scan the N most common ports (e.g., `--top-ports 100`) for rapid reconnaissance.
- **Host Exclusion (`--exclude-targets`):** Skip specific IPs or subnets when scanning large networks to avoid critical infrastructure.
- **Deep HTTP Fingerprinting:** Extracts `Server`, `X-Powered-By`, `WWW-Authenticate`, and HTML titles for instant web service identification.
- **Version Extraction:** Uses smart regex to clean raw banners, parsing exact version numbers (e.g., `OpenSSH 8.2p1`).
- **Live Open Port Alerts:** Prints discovered open ports to the console the exact millisecond they are found, eliminating the wait for the final results table.
- **Port State Detection:** Accurately distinguishes between `open`, `closed` (actively rejected), and `filtered` (dropped by a firewall) ports.
- **Modular Codebase:** Split into multiple files for easy maintenance and contribution.
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
| `--top-ports` | Scan the N most common ports (e.g., `--top-ports 100`). |
| `--exclude` | Exclude specific ports (e.g., `80,443`). |
| `--exclude-targets` | Exclude specific IPs or subnets (e.g., `192.168.1.1`). |
| `-sV` | Enable service detection (banner grabbing). |
| `-O` | Enable OS detection via ICMP TTL fingerprinting. |
| `-sn` | Perform a ping sweep only (disable port scanning). |
| `-v` | Enable verbose output (dynamic progress bar). |
| `-t` | Number of concurrent threads (default: 100). |
| `-T` | Timing profile 1 (slow) to 10 (insane). |
| `--timeout` | Socket timeout in seconds (default: 1.0). |
| `--delay` | Add a random delay in seconds between probes (e.g., 0.5). |
| `--safe` | Enable safe mode (limits threads to 10, adds 0.5s delay). |
| `--randomize` | Randomize target IPs and ports to evade firewalls. |
| `-g` | Specify a source port for firewall evasion (e.g., 53). Requires sudo for ports under 1024. |
| `-oN` | Save scan results to a specified text file. |
| `-oJ` | Save scan results to a specified JSON file. |
| `-oX` | Save scan results to a specified XML file. |
| `-oG` | Save scan results to a specified grepable text file. |

### Examples

**1. Quick default scan (Top common ports):**
```bash
python viper.py scanme.nmap.org
```

**2. Aggressive full port scan with service detection:**
```bash
python viper.py 10.10.10.10 -p- -sV -T8
```

**3. Firewall evasion using source port 53 (DNS):**
```bash
sudo python viper.py 10.10.10.10 -g 53 -T3
```

**4. Read targets from a file, randomize scan, and save to XML format:**
```bash
python viper.py -iL targets.txt --randomize -oX results.xml
```

**5. Ping sweep only to find live hosts on a subnet:**
```bash
python viper.py 10.10.10.0/24 -sn
```

**6. Scan top 100 ports, excluding the gateway:**
```bash
python viper.py 192.168.1.0/24 --top-ports 100 --exclude-targets 192.168.1.1
```

## ⚠️ Legal & Ethical Disclaimer

This tool is intended for educational purposes and authorized network auditing only. Port scanning without explicit permission from the target owner may be illegal and is considered an attack in many jurisdictions. **Only scan networks and devices you own or have explicit permission to test.**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
