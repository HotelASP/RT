#!/usr/bin/env python3
# portscanner-mrib.py v1
# Async port scanner that supports:
#  - TCP connect scans using asyncio (no root required)
#  - SYN and UDP scans via Scapy run in an executor (root required)
#  - IPv4/IPv6 for connect mode (Scapy primarily IPv4)
#  - Targets as single host, CIDR block, or file with targets
#  - Per-host concurrency, rate limiting, port shuffling, banner grab
#  - JSON/CSV output for discovered open ports
#
# High-level flow:
#  1. Parse CLI args.
#  2. Expand targets and ports.
#  3. For each target:
#     a. Resolve target to an IP address.
#     b. Run scan_host which schedules per-port tasks.
#     c. Collect open results and optionally write CSV/JSON.
#
# Notes:
#  - Use --syn or --udp only with root and Scapy installed.
#  - Connect mode uses asyncio.open_connection and behaves like "tcp connect".
#  - UDP mode sends single UDP packet and waits for ICMP reply.
#  - Rate limiting is a simple token-bucket-like limiter implemented as fixed intervals.

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import random
import socket
import sys
import time
from datetime import datetime, timezone
from typing import List, Tuple, Optional

# Try to import scapy. If import fails the script continues but --syn/--udp will exit later.
try:
    import scapy.all as scapy
    SCAPY = True
except Exception:
    SCAPY = False

# Default settings (overridable via environment)
DEFAULTS = {
    "HOST": os.environ.get("PORTSCAN_HOST", "160.153.248.110"),
    "PORTS": os.environ.get("PORTSCAN_PORTS", "21,22,135,80,443,445,50920-50930"),
    "START": int(os.environ.get("PORTSCAN_START", "1")),
    "END": int(os.environ.get("PORTSCAN_END", "1024")),
    "CONCURRENCY": int(os.environ.get("PORTSCAN_CONCURRENCY", "1")),
    "TIMEOUT": float(os.environ.get("PORTSCAN_TIMEOUT", "1.0")),
    "RATE": int(os.environ.get("PORTSCAN_RATE", "0")),  # 0 = unlimited
}

def now_utc():
    """Return current time in ISO8601 UTC string."""
    return datetime.now(timezone.utc).isoformat()

def parse_targets(arg: str) -> List[str]:
    """
    Accept either:
      - a filesystem path to a file with one target per line
      - a CIDR like 10.0.0.0/24 (returns all host addresses)
      - a single hostname or IP address
    Returns a list of target strings (IP or hostname).
    """
    if os.path.isfile(arg):
        with open(arg, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        return targets
    # Try CIDR expansion
    try:
        net = ipaddress.ip_network(arg, strict=False)
        # Return hosts() to avoid network/broadcast on IPv4. If only one address, hosts() may be empty; fallback.
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    except ValueError:
        # Not a CIDR. Treat as single host or IP.
        return [arg]

def parse_ports(range_start: int, range_end: int, spec: Optional[str]) -> List[int]:
    """
    Parse ports specification:
      - spec: comma separated numbers and ranges, e.g. "22,80,8000-8100"
      - if spec is None use start..end inclusive
    Returns sorted unique valid ports 1..65535.
    """
    if spec:
        out = []
        for part in spec.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                out.extend(range(int(a), int(b) + 1))
            else:
                out.append(int(part))
        ports = [p for p in out if 1 <= p <= 65535]
    else:
        ports = list(range(range_start, range_end + 1))
    return sorted(set(ports))

async def banner_grab(reader: asyncio.StreamReader, timeout: float, max_bytes: int = 128) -> str:
    """
    Read up to max_bytes from a connected TCP stream.
    Used only for basic banner grabbing on TCP connect.
    Returns decoded text or empty string on any error/timeout.
    """
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode('utf-8', errors='replace').strip()
    except Exception:
        return ""

async def scan_port_connect(host: str, port: int, timeout: float, banner: bool) -> Tuple[str, int, str, str, str]:
    """
    TCP connect scan using asyncio.open_connection.
    Returns tuple: (host, port, proto, status, note)
      - status: "open", "closed", "filtered"
      - note: extra explanation or banner if requested
    Behavior:
      - if connection succeeds: "open"
      - ConnectionRefusedError -> "closed"
      - Timeout or network unreachable -> "filtered"
    """
    try:
        # open_connection will attempt IPv4/IPv6 depending on host. asyncio implements happy-eyeballs behavior.
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
        note = ""
        if banner:
            # Attempt a quick banner read. Non-blocking if empty.
            note = await banner_grab(reader, timeout=min(timeout, 0.5))
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            # Some transports don't implement wait_closed; ignore.
            pass
        return host, port, "tcp", "open", note
    except asyncio.TimeoutError:
        return host, port, "tcp", "filtered", "timeout"
    except ConnectionRefusedError:
        return host, port, "tcp", "closed", "ECONNREFUSED"
    except OSError as e:
        # Map common errno to filtered vs closed
        if getattr(e, "errno", None) in (101, 113, 110):  # ENETUNREACH, EHOSTUNREACH, ETIMEDOUT
            return host, port, "tcp", "filtered", os.strerror(e.errno)
        return host, port, "tcp", "closed", getattr(e, "strerror", repr(e))
    except Exception as e:
        return host, port, "tcp", "filtered", type(e).__name__

def _scapy_syn_once(dst: str, dport: int, timeout: float):
    """
    Blocking scapy operation that sends one TCP SYN and waits for a response.
    Called in executor so it does not block the asyncio loop.
    Interprets responses:
      - None -> no response -> "filtered"
      - SYN+ACK -> "open" (sends RST to avoid completing handshake)
      - RST -> "closed"
      - other -> "filtered"/"unexpected"
    """
    pkt = scapy.IP(dst=dst)/scapy.TCP(dport=dport, flags="S")
    ans = scapy.sr1(pkt, timeout=timeout, verbose=0)
    if ans is None:
        return "filtered", "no-response"
    if ans.haslayer(scapy.TCP):
        f = ans[scapy.TCP].flags
        if f & 0x12 == 0x12:  # SYN+ACK
            # polite cleanup: send RST so server doesn't see a completed handshake later
            scapy.send(scapy.IP(dst=dst)/scapy.TCP(dport=dport, flags="R"), verbose=0)
            return "open", "SYN-ACK"
        if f & 0x14 == 0x14 or f & 0x04 == 0x04:  # RST
            return "closed", "RST"
    return "filtered", "unexpected"

async def scan_port_syn(host: str, port: int, timeout: float) -> Tuple[str, int, str, str, str]:
    """
    Asynchronous wrapper around the blocking scapy SYN probe.
    Uses run_in_executor to avoid blocking the event loop.
    """
    loop = asyncio.get_running_loop()
    try:
        status, note = await loop.run_in_executor(None, _scapy_syn_once, host, port, timeout)
        return host, port, "tcp", status, note
    except Exception as e:
        return host, port, "tcp", "filtered", type(e).__name__

def _scapy_udp_once(dst: str, dport: int, timeout: float):
    """
    Blocking scapy UDP probe:
      - send an empty UDP packet to dst:dport and wait for reply
      - If no response -> "open|filtered" (UDP is ambiguous)
      - If ICMP type 3 code 3 (port unreachable) -> "closed"
      - Other ICMP -> "filtered"
    This is an interpretation commonly used by UDP scanners like nmap.
    """
    pkt = scapy.IP(dst=dst)/scapy.UDP(dport=dport)
    ans = scapy.sr1(pkt, timeout=timeout, verbose=0)
    if ans is None:
        return "open|filtered", "no-response"
    if ans.haslayer(scapy.ICMP):
        icmp = ans[scapy.ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed", "icmp-port-unreachable"
        return "filtered", f"icmp type={icmp.type} code={icmp.code}"
    return "open|filtered", "unexpected"

async def scan_port_udp(host: str, port: int, timeout: float) -> Tuple[str, int, str, str, str]:
    """
    Async wrapper for UDP probe. Same pattern as SYN wrapper.
    """
    loop = asyncio.get_running_loop()
    try:
        status, note = await loop.run_in_executor(None, _scapy_udp_once, host, port, timeout)
        return host, port, "udp", status, note
    except Exception as e:
        return host, port, "udp", "filtered", type(e).__name__

class RateLimiter:
    """
    Very simple rate limiter implemented as a fixed-interval token bucket.
    It enforces a minimal interval between operations.
    rate = ops per second. If rate <= 0, unlimited.
    This is per-host limiter in the script.
    """
    def __init__(self, rate: int):
        self.rate = rate
        self._last = 0.0
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if self.rate <= 0:
            return
        async with self._lock:
            t = time.perf_counter()
            wait_for = self._interval - (t - self._last)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
                self._last = time.perf_counter()
            else:
                self._last = t

async def scan_host(
    host: str,
    ports: List[int],
    mode: str,
    timeout: float,
    concurrency: int,
    show_closed: bool,
    banner: bool,
    rate: int
):
    """
    Scan a single resolved host.
    - host: IP string
    - ports: list of ints to scan
    - mode: "connect", "syn", or "udp"
    - concurrency: number of simultaneous port tasks allowed
    - show_closed: if True print closed ports too
    - banner: if True attempt banner grab on TCP connect
    - rate: ops/sec per host (0 = unlimited)
    Returns list of result dicts for ports that included "open" in their status.
    """
    sem = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate)
    results = []
    tasks = []

    async def run_one(p: int):
        async with sem:
            await limiter.wait()
            if mode == "connect":
                return await scan_port_connect(host, p, timeout, banner)
            if mode == "syn":
                return await scan_port_syn(host, p, timeout)
            if mode == "udp":
                return await scan_port_udp(host, p, timeout)
            return host, p, "tcp", "error", "unknown-mode"

    # Schedule all port tasks upfront but they will respect sem and limiter.
    for p in ports:
        tasks.append(asyncio.create_task(run_one(p)))

    # Collect results as tasks complete to stream output.
    for t in asyncio.as_completed(tasks):
        h, p, proto, status, note = await t
        ts = now_utc()
        if status != "closed" or show_closed:
            line_note = f" {note}" if note else ""
            print(f"{ts} {h}:{p}/{proto} {status}{line_note}")
        if "open" in status:
            results.append(dict(host=h, port=p, proto=proto, status=status, note=note, time=ts))
    return results

async def resolve_host(label: str) -> str:
    """
    Resolve a hostname to an IP address.
    Uses getaddrinfo to prefer IPv4 then IPv6. If resolution fails, return input label unchanged.
    The resolved address is used for low-level scans.
    """
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(label, None, type=socket.SOCK_STREAM)
        # Prefer IPv4 results first for stable output.
        for fam in (socket.AF_INET, socket.AF_INET6):
            for af, *_ in infos:
                if af == fam:
                    addr = infos[0][4][0]
                    return addr
        return infos[0][4][0]
    except Exception:
        return label

def require_root_for_scapy(mode: str):
    """
    If user chose syn or udp, ensure scapy is available and process is root.
    Exit with an informative message if requirements not met.
    """
    if mode in ("syn", "udp"):
        if not SCAPY:
            print("Scapy not available. Install with: pip install scapy")
            sys.exit(2)
        if os.geteuid() != 0:
            print("Root privileges required for --syn or --udp. Rerun with sudo.")
            sys.exit(2)

def main():
    """
    CLI, validation, main loop.
    - Parse arguments
    - Expand ports and targets
    - Optionally shuffle ports
    - For each target resolve and scan
    - Dump CSV/JSON files for open results
    """
    p = argparse.ArgumentParser(description="Async port scanner with asyncio + Scapy")
    p.add_argument("--targets", required=False, default=DEFAULTS["HOST"],help="Host/IP/CIDR or a file with one target per line")
    p.add_argument("--start", type=int, default=DEFAULTS["START"], help="Start port")
    p.add_argument("--end", type=int, default=DEFAULTS["END"], help="End port")
    p.add_argument("--ports", default=DEFAULTS["PORTS"],help="Comma list and ranges, e.g. 22,80,8000-8100 (overrides start/end)")
    p.add_argument("-c", "--concurrency", type=int, default=DEFAULTS["CONCURRENCY"], help="Per-host concurrency")
    p.add_argument("--timeout", type=float, default=DEFAULTS["TIMEOUT"], help="Timeout seconds")
    p.add_argument("--csv", help="Write open results to CSV")
    p.add_argument("--json", help="Write open results to JSON")
    p.add_argument("--show-closed", action="store_true", help="Print closed ports too")
    p.add_argument("--shuffle", action="store_true", help="Randomise port order")
    p.add_argument("--banner", action="store_true", help="Grab small banner on TCP connect")
    p.add_argument("--rate", type=int, default=DEFAULTS["RATE"], help="Ops per second (0 = unlimited)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--syn", action="store_true", help="SYN scan (root + scapy)")
    mode.add_argument("--udp", action="store_true", help="UDP scan (root + scapy)")
    args = p.parse_args()

    # Expand port list
    ports = parse_ports(args.start, args.end, args.ports)
    if not ports:
        print("No ports selected.")
        sys.exit(1)
    if args.shuffle:
        random.shuffle(ports)

    # Determine mode string
    mode_str = "connect"
    if args.syn:
        mode_str = "syn"
    if args.udp:
        mode_str = "udp"

    # Validate scapy/root if necessary
    require_root_for_scapy(mode_str)

    # Expand target list (file/CIDR/host)
    targets = parse_targets(args.targets)
    if not targets:
        print("No targets.")
        sys.exit(1)

    print(f"scan start={now_utc()} mode={mode_str} targets={len(targets)} ports={len(ports)} "
          f"concurrency={args.concurrency} timeout={args.timeout}s rate={args.rate}/s")

    try:
        all_results = []
        # Use a fresh event loop for synchronous-style sequential per-target processing.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for t in targets:
            # Resolve target to numeric IP for scanning
            resolved = loop.run_until_complete(resolve_host(t))
            print(f"target {t} -> {resolved}")
            res = loop.run_until_complete(
                scan_host(resolved, ports, mode_str, args.timeout, max(1, args.concurrency),
                          args.show_closed, args.banner, max(0, args.rate))
            )
            all_results.extend(res)
        loop.close()
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)

    print(f"scan end={now_utc()} open_found={len(all_results)}")

    # Persist open results if requested
    if args.csv and all_results:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "port", "proto", "status", "note", "time_utc"])
            for r in all_results:
                w.writerow([r["host"], r["port"], r["proto"], r["status"], r["note"], r["time"]])
        print(f"csv -> {args.csv}")

    if args.json and all_results:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"json -> {args.json}")

if __name__ == "__main__":
    main()
