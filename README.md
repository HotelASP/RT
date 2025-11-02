# SMRIB – Multi-protocol Scanner

`smrib.py` is an asyncio-powered reconnaissance utility that supports TCP connect scans, TCP SYN probing, UDP probes, batch execution, and web directory discovery. It can write results to CSV/JSON, capture packets, and grab banners where supported.

The script is safe to run with no arguments: `python3 smrib.py` will automatically scan the default target host using the baked-in timing parameters **and** enable a helpful baseline profile (`--show-only-open`, `--banner`, `--top-ports 100`, `--csv logs/results.csv`, and `--json logs/results.json`). Those defaults can be overridden by environment variables or the command-line flags described below.

## Quick start

```bash
python3 smrib.py
```

Running the tool exactly as shown performs a TCP connect scan against `hackthissite.org` (or the value of `PORTSCAN_HOST`), enumerating the top 100 ports while grabbing banners, showing only the open results in the terminal, and saving structured CSV/JSON output to `logs/results.*`. Concurrency defaults to 100, the timeout to 0.3 seconds, and the rate limiter remains disabled. All of these values come from the defaults baked into the script and can be tuned by setting `PORTSCAN_*` environment variables or passing explicit flags.

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

## Default configuration and parameters

The table below summarises the most commonly adjusted parameters, their default values, and the environment variables that override them before command-line parsing occurs.

| Flag | Purpose | Default | Environment variable |
|------|---------|---------|----------------------|
| `--targets` | Hostname, IP address, CIDR block, or file containing one target per line. | `hackthissite.org` | `PORTSCAN_HOST` |
| `--start` | Inclusive start of the port range. | `1` | `PORTSCAN_START` |
| `--end` | Inclusive end of the port range. | `1024` | `PORTSCAN_END` |
| `--ports` | Explicit list of ports/ranges (overrides `--start/--end`). | `None` | n/a |
| `--top-ports` | Use the top *n* entries from a popularity list. | `None` | n/a |
| `--concurrency` | Maximum simultaneous socket operations per host. | `100` | `PORTSCAN_CONCURRENCY` |
| `--timeout` | Socket/probe timeout in seconds. | `0.3` | `PORTSCAN_TIMEOUT` |
| `--rate` | Per-host operations per second (`0` disables the limiter). | `0` | `PORTSCAN_RATE` |
| `--retries` | Retry attempts for SYN/UDP probes. | `1` | n/a |
| `--retry-backoff` | Exponential backoff base in seconds between retries. | `0.2` | n/a |
| `--fast` | Enables aggressive mode tuning (see below). | `False` | n/a |

All other CLI switches fall back to sane defaults (`False` for boolean toggles, no output files unless requested). When you launch the tool with no parameters, SMRIB automatically enables `--show-only-open`, `--banner`, `--top-ports 100`, `--csv logs/results.csv`, and `--json logs/results.json` to provide a rich out-of-the-box experience. Any combination of flags can be supplied alongside the defaults; unspecified options keep their default values.

### What `--fast` mode changes

Fast mode increases concurrency (subject to file descriptor guardrails), caps timeouts to 0.3 seconds, disables banner collection and retries, prefers SYN scanning when allowed, shuffles port order, and scans private/internal targets as-is. The terminal output will confirm the effective settings whenever `--fast` is used.

## How the code is organised

- **Argument parsing:** `build_cli_parser()` defines the command-line interface and wires default values from the `DEFAULTS` dictionary. Running without parameters simply produces a namespace populated by those defaults.
- **Scan orchestration:** `run_full_scan()` resolves targets, normalises concurrency, prepares optional packet captures, and launches the asynchronous scanning tasks. It coordinates output to the terminal and optional CSV/JSON/PCAP files.
- **Asynchronous workers:** `scan_all_selected_ports_for_host()` schedules one coroutine per port, honouring concurrency semaphores and the rate limiter (`FixedRateLimiter`). Depending on the selected mode (`connect`, `syn`, or `udp`), it delegates to the appropriate probe function.
- **Protocol handlers:** `scan_tcp_connect_once()`, `scan_tcp_syn_once()`, and `scan_udp_once()` implement the actual network operations. SYN/UDP functionality relies on Scapy when installed.
- **Batch features:** `run_batch_from_file()` and `run_batch_battery()` allow you to supply multiple runs in a specification file, reusing the same argument parser to ensure identical validation.

These entry points are heavily commented in the source file to assist new users who want to explore or extend the scanner.

## Core options

- `--targets` accepts an IP, hostname, CIDR, or filename containing one target per line.
- `--start` / `--end` define a port range, while `--ports` accepts explicit comma-separated ports and ranges.
- `--top-ports` pulls the most popular ports from `data/top-ports.txt` (or `--top-ports-file`).
- `--csv`, `--json`, and `--pcap` persist results; omit the argument to auto-generate timestamped names.
- `--banner` enables banner grabbing on TCP connect scans.
- `--syn` and `--udp` switch to Scapy-backed TCP SYN or UDP probing modes (root required).
- `--rate`, `--concurrency`, `--timeout`, `--retries`, and `--retry-backoff` control performance and resilience.
- `--fast` activates an aggressive profile that automatically tunes timeouts, concurrency, and mode selection for speed.
- `--batch`, `--batch-battery`, and `--web-dir` activate the specialized workflows described in the examples below.

For quick experiments, you can export environment variables once (for example, `export PORTSCAN_HOST=scanme.nmap.org`) and then run `python3 smrib.py` repeatedly without retyping the host.

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

### 5a. Running with defaults only

```bash
python3 smrib.py
```

**What it does:** Scans `hackthissite.org` across the top 100 ports using connect mode with concurrency 100, timeout 0.3 seconds, banner grabbing enabled, and the terminal restricted to open findings. Results are persisted automatically to `logs/results.csv` and `logs/results.json`. Adjust `PORTSCAN_*` variables or CLI flags to change these values.

### 6. Batch-driven multi-run execution

```bash
python3 smrib.py --batch batch.txt
```

**What it does:** Reads each non-comment line in `batch.txt` as a full CLI invocation and executes the scans sequentially.

### 7. Compact diagnostic battery across a target list

```bash
python3 smrib.py --batch-battery targets.txt --csv logs/batch_battery.csv --json logs/batch_battery.json
```

**What it does:** Runs a curated set of TCP connect, SYN, and UDP checks (where permitted) against every entry in the target file, consolidating the results.

### 8. Web directory enumeration helper

```bash
python3 smrib.py --web-dir --url https://hotelasp.com --wordlist 'data/webdir_wordlist.txt'
```

**What it does:** Iterates through the supplied wordlist, requesting each path relative to the URL and printing the observed HTTP status codes.

The bundled wordlist (`webdir_wordlist.txt`) and top ports file (`top-ports.txt`) are stored in the `data/` directory. Providing just the filename automatically resolves to that location.

## Tips

- Use `--show-only-open` to focus terminal output on open services while still logging closed ports to disk.
- Combine `--top-ports` with `--fast` for rapid reconnaissance on well-known services.
- When writing to directories such as `Logs/`, ensure they exist beforehand: `mkdir -p Logs`.

## License

This repository is provided as part of the RED TEAM Course materials. Review local policies before scanning hosts you do not own or administer.
