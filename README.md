# SMRIB – Multi-protocol Scanner

SMRIB is an asyncio-powered reconnaissance toolkit that performs TCP connect scans, TCP SYN probing, UDP probes, batch execution, and lightweight web directory discovery. It can persist results to CSV/JSON, capture packets, and capture service banners. The project is designed for red-team training environments and is safe to run with no additional arguments.

## Table of contents

- [Key capabilities](#key-capabilities)
- [Quick start](#quick-start)
- [Installation & prerequisites](#installation--prerequisites)
- [Usage overview](#usage-overview)
  - [Core options](#core-options)
  - [Fast mode](#fast-mode)
  - [Compatibility mode (`--mode1`)](#compatibility-mode---mode1)
- [Configuration defaults](#configuration-defaults)
- [Batch & automation helpers](#batch--automation-helpers)
- [Understanding outputs](#understanding-outputs)
- [End-to-end examples](#end-to-end-examples)
- [Tips & troubleshooting](#tips--troubleshooting)
- [Project layout](#project-layout)
- [License](#license)

## Key capabilities

- **Multi-protocol support** – TCP connect, TCP SYN (Scapy), UDP probes, and HTTP directory enumeration.
- **Asynchronous engine** – High-concurrency execution with rate limiting, retries, and adaptive timeouts.
- **Rich artifacts** – Export CSV, JSON, and optional PCAP captures; banner collection for supported services.
- **Batch automation** – Reuse batch files or curated batteries for repeatable operations.
- **Environment-driven defaults** – Override baked-in defaults via `PORTSCAN_*` environment variables.

## Quick start

```bash
python3 smrib.py
```

Running the tool with no flags launches a TCP connect scan against the default target (see [Configuration defaults](#configuration-defaults)). The scan enumerates the top 100 ports, collects banners, shows only open services in the terminal, and writes CSV/JSON logs to `logs/results.*`.

## Installation & prerequisites

1. **Clone the repository** into your workspace.
2. **Ensure Python 3.8+** is available.
3. Optionally install [`scapy`](https://scapy.net/) to enable SYN and UDP probe modes.
4. Grant execute permission if you plan to run the script directly:

   ```bash
   chmod +x smrib.py
   ```

> **Note:** SYN/UDP probing and packet capture (`--pcap`) require root privileges for raw socket access. Without Scapy installed, the script automatically disables those modes.

Display the full CLI reference at any time with:

```bash
python3 smrib.py --help
```

## Usage overview

SMRIB reads command-line arguments defined in `build_cli_parser()` and orchestrates scans via `run_full_scan()`. Execution is handled asynchronously using worker coroutines that target each selected port.

### Core options

- `--targets` – Hostname, IP, CIDR, or file containing targets (one per line).
- `--start` / `--end` – Inclusive port range; overridden by `--ports`.
- `--ports` – Explicit list of ports or ranges (e.g., `80,443,100-120`).
- `--top-ports` – Scans the most common ports from `data/top-ports.txt` or a custom list.
- `--csv`, `--json`, `--pcap` – Persist results to disk (auto-generates filenames if omitted).
- `--banner` – Capture service banners for TCP connect scans.
- `--syn`, `--udp` – Switch to Scapy-backed SYN or UDP probing modes.
- `--rate`, `--concurrency`, `--timeout`, `--retries`, `--retry-backoff` – Control throughput and resilience.
- `--mode1` – Sequential, blocking TCP connect loop that mirrors legacy scripts.
- `--batch`, `--batch-battery`, `--web-dir` – Enable higher-level workflows.

Use environment variables (e.g., `export PORTSCAN_HOST=scanme.nmap.org`) to set persistent defaults before invoking the script.

### Fast mode

`--fast` activates an aggressive profile tailored for speed:

- Raises concurrency (subject to safety guardrails).
- Caps timeouts at 0.3 seconds and disables banner collection and retries.
- Prefers SYN scanning when possible (requires Scapy + root).
- Shuffles port order and scans private/internal targets without adjustments.
- Prints the effective configuration when enabled.

### Compatibility mode (`--mode1`)

Compatibility mode disables the asynchronous engine and performs a simple, blocking `socket.create_connection()` loop. This mirrors traditional shell scripts: deterministic ordering, no external dependencies, and automatic mapping of common service names. Expect slower performance compared to the default asynchronous engine.

## Configuration defaults

The table below summarises key parameters, their default values, and the environment variables that override them prior to CLI parsing.

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
| `--fast` | Enables aggressive mode tuning. | `False` | n/a |

When run with no arguments, SMRIB automatically applies the following additional defaults to provide a robust out-of-the-box experience:

- `--show-only-open`
- `--banner`
- `--top-ports 100`
- `--csv logs/results.csv`
- `--json logs/results.json`

Terminal output shows only open services unless one of the `--show-closed-terminal*` flags is provided.

## Batch & automation helpers

- `--batch <file>` – Executes each non-comment line of the file as a full CLI invocation.
- `--batch-battery <targets.txt>` – Runs a curated mix of TCP connect, SYN, and UDP checks against each listed target.
- `--web-dir --url <url> --wordlist <file>` – Performs HTTP directory discovery using the provided wordlist. Files in the `data/` directory (e.g., `webdir_wordlist.txt`, `top-ports.txt`) are automatically resolved by filename only.

## Understanding outputs

All scan results are normalised before being persisted. CSV and JSON writers produce records with the following fields (modelled by the `ScanRecord` data class):

- **host** – Host label or IP that was scanned.
- **port** – Destination port number.
- **proto** – Transport protocol (`tcp` or `udp`).
- **status** – Classification such as `open`, `closed`, or `filtered`.
- **note** – Diagnostic information (errors, banners, etc.).
- **banner** – Captured banner text for TCP connect scans when enabled.
- **time_utc** – Timestamp when the result was recorded.
- **duration_ms** – Duration of the probe in milliseconds.

When `--show-only-open` is active, the same filter applies to persisted artifacts so that CSV/JSON logs contain only open findings.

## End-to-end examples

The commands below are ready to adapt to your environment. Paths requiring root access are labelled accordingly.

1. **TCP connect sweep with banner capture** *(root required only when using `--pcap`)*

   ```bash
   sudo python3 smrib.py --targets targets_hotelasp.txt --ports "21,22,80,443" --banner --csv logs/log_hotelasp.csv --json logs/log_hotelasp.json --pcap logs/log_hotelasp.pcap
   ```

   Performs full TCP sessions against the listed targets, retrieves banners, and stores CSV/JSON/PCAP artifacts.

2. **High-concurrency TCP SYN reconnaissance** *(root required)*

   ```bash
   sudo python3 smrib.py --targets 10.0.5.2 --start 1 --end 1024 --syn --rate 15 --concurrency 200 --csv logs/log_syn_10_0_5_2.csv
   ```

   Launches a Scapy-backed SYN scan across ports 1–1024 with rate limiting, outputting findings to CSV.

3. **UDP DNS inspection with adaptive retries** *(root required for `--pcap`)*

   ```bash
   sudo python3 smrib.py --targets 1.1.1.1 --ports 53 --udp --udp-probe dns --timeout 1.5 --retries 3 --retry-backoff 0.25 --csv logs/log_dns_lookup.csv --pcap logs/log_dns_lookup.pcap
   ```

   Sends DNS queries with exponential backoff, records UDP responsiveness, and optionally captures packets.

4. **UDP NTP probing** *(root required for `--pcap`)*

   ```bash
   sudo python3 smrib.py --targets 17.253.84.253 --ports 123 --udp --udp-probe ntp --timeout 4 --retries 2 --csv logs/log_ntp_lookup.csv --pcap logs/log_ntp_lookup.pcap
   ```

   Checks for NTP services, logging outcomes and optionally capturing packet traces.

5. **Fast mode scan with shuffled ports**

   ```bash
   python3 smrib.py --targets 10.0.5.5 --ports "22,80,443,100-200" --fast --show-closed-terminal --csv logs/log_fast_10_0_5_5.csv
   ```

   Applies the fast profile, randomises port order, prints closed ports, and writes a CSV summary.

6. **Running with defaults only**

   ```bash
   python3 smrib.py
   ```

   Scans `hackthissite.org` across the top 100 ports using connect mode with concurrency 100, timeout 0.3 seconds, banner grabbing enabled, and terminal output restricted to open findings. Results persist to `logs/results.csv` and `logs/results.json`.

7. **Batch-driven multi-run execution**

   ```bash
   python3 smrib.py --batch batch.txt
   ```

   Reads each non-comment line in `batch.txt` as a full CLI invocation and executes the scans sequentially.

8. **Compact diagnostic battery across a target list**

   ```bash
   python3 smrib.py --batch-battery targets.txt --csv logs/batch_battery.csv --json logs/batch_battery.json
   ```

   Runs a curated set of TCP connect, SYN, and UDP checks (where permitted) against every entry in the target file.

9. **Web directory enumeration helper**

   ```bash
   python3 smrib.py --web-dir --url https://hotelasp.com --wordlist 'data/webdir_wordlist.txt'
   ```

   Iterates through the supplied wordlist, requesting each path relative to the URL and printing HTTP status codes.

## Tips & troubleshooting

- Terminal output focuses on open services by default. Use `--show-closed-terminal` to include closed/filtered results or `--show-closed-terminal-only` to review them without persisting to disk.
- Combine `--top-ports` with `--fast` for rapid reconnaissance on well-known services.
- SMRIB creates missing directories (e.g., `logs/`) automatically. If artifacts fail to save, double-check filesystem permissions.
- When running SYN/UDP scans, confirm Scapy is installed and execute the script with root privileges.

## Project layout

- `smrib.py` – Main executable script containing argument parsing, orchestration, and protocol handlers.
- `data/` – Reference files such as `top-ports.txt` and `webdir_wordlist.txt` used by CLI helpers.
- `batch.txt`, `targets.txt`, `targets_found.txt`, `targets_internal.txt` – Example inputs for batch workflows.

## License

This repository is provided as part of the RED TEAM Course materials. Review local policies before scanning hosts you do not own or administer.
