# SMRIB – Multi-protocol Scanner

`smrib.py` is an asyncio-powered reconnaissance utility that supports TCP connect scans, TCP SYN probing, UDP probes, batch execution, and web directory discovery. It can write results to CSV/JSON, capture packets, and grab banners where supported.

## Prerequisites

- Python 3.8+
- Optional: [`scapy`](https://scapy.net/) for SYN and UDP probe modes. When Scapy is unavailable, those modes are disabled automatically.
- Packet capture (`--pcap`) requires root privileges so the tool can open raw sockets.

Clone the repository and ensure executable permissions:

```bash
chmod +x smrib.py
```

## Getting help

Display the full CLI documentation:

```bash
python3 smrib.py --help
```

## Core options

- `--targets` accepts an IP, hostname, CIDR, or filename containing one target per line.
- `--start` / `--end` define a port range, while `--ports` accepts explicit comma-separated ports and ranges.
- `--top-ports` pulls the most popular ports from `top-ports.txt` (or `--top-ports-file`).
- `--csv`, `--json`, and `--pcap` persist results; omit the argument to auto-generate timestamped names.
- `--banner` enables banner grabbing on TCP connect scans.
- `--syn` and `--udp` switch to Scapy-backed TCP SYN or UDP probing modes (root required).
- `--rate`, `--concurrency`, `--timeout`, `--retries`, and `--retry-backoff` control performance and resilience.
- `--fast` activates an aggressive profile that automatically tunes timeouts, concurrency, and mode selection for speed.
- `--batch`, `--batch-battery`, and `--web-dir` activate the specialized workflows described in the examples below.

## End-to-end examples

The commands in this section are ready to copy, paste, and run. Adjust file paths and target values to match your environment. Examples that require root are explicitly labeled.

### 1. TCP connect sweep with banner capture *(root only when using --pcap)*

```bash
sudo python3 smrib.py --targets targets_hotelasp.txt --ports "21,22,80,443" --banner --csv Logs/log_hotelasp.csv --json Logs/log_hotelasp.json --pcap Logs/log_hotelasp.pcap
```

**What it does:** Establishes full TCP sessions against the listed targets, retrieves available banners, and stores results in CSV, JSON, and PCAP artifacts.

### 2. High-concurrency TCP SYN reconnaissance *(root required)*

```bash
sudo python3 smrib.py --targets 10.0.5.2 --start 1 --end 1024 --syn --rate 15 --concurrency 200 --csv Logs/log_syn_10_0_5_2.csv
```

**What it does:** Launches a Scapy-powered SYN scan across the first 1,024 ports with rate limiting, capturing the findings in CSV format.

### 3. UDP DNS inspection with adaptive retries *(root required for --pcap)*

```bash
sudo python3 smrib.py --targets 1.1.1.1 --ports 53 --udp --udp-probe dns --timeout 1.5 --retries 3 --retry-backoff 0.25 --csv Logs/log_dns_lookup.csv --pcap Logs/log_dns_lookup.pcap
```

**What it does:** Sends DNS queries with exponential backoff, records UDP responsiveness, and saves packet captures for review.

### 4. UDP NTP probing *(root required for --pcap)*

```bash
sudo python3 smrib.py --targets 17.253.84.253 --ports 123 --udp --udp-probe ntp --timeout 4 --retries 2 --csv Logs/log_ntp_lookup.csv --pcap Logs/log_ntp_lookup.pcap
```

**What it does:** Checks for NTP services, logging outcomes and optionally capturing packet traces for verification.

### 5. Fast mode scan with shuffled ports

```bash
python3 smrib.py --targets 10.0.5.5 --ports "22,80,443,100-200" --fast --show-closed-terminal --csv Logs/log_fast_10_0_5_5.csv
```

**What it does:** Applies the aggressive fast profile, randomizes port order, prints closed ports to the terminal, and saves a CSV summary.

### 6. Batch-driven multi-run execution

```bash
python3 smrib.py --batch batch_10_0_5_0.txt
```

**What it does:** Reads each non-comment line in `batch_10_0_5_0.txt` as a full CLI invocation and executes the scans sequentially.

### 7. Compact diagnostic battery across a target list

```bash
python3 smrib.py --batch-battery targets_hotelasp.txt --csv Logs/batch_battery_hotelasp.csv --json Logs/batch_battery_hotelasp.json
```

**What it does:** Runs a curated set of TCP connect, SYN, and UDP checks (where permitted) against every entry in the target file, consolidating the results.

### 8. Web directory enumeration helper

```bash
python3 smrib.py --web-dir --url https://hotelasp.com --wordlist webdir_wordlist.txt
```

**What it does:** Iterates through the supplied wordlist, requesting each path relative to the URL and printing the observed HTTP status codes.

## Tips

- Use `--show-only-open` to focus terminal output on open services while still logging closed ports to disk.
- Combine `--top-ports` with `--fast` for rapid reconnaissance on well-known services.
- When writing to directories such as `Logs/`, ensure they exist beforehand: `mkdir -p Logs`.

## License

This repository is provided as part of the RED TEAM Course materials. Review local policies before scanning hosts you do not own or administer.
