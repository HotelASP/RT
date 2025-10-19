#!/usr/bin/env python3
# --------------
# Asynchronous port scanner with three modes:
#   + PCAP capture option (--pcap)
#   1) TCP connect scan using asyncio (no root)
#   2) TCP SYN scan using Scapy (root)
#   3) UDP probe using Scapy (root)
# --------------
# - Targets: single host, CIDR block, or file with one target per line.
# - Ports: explicit list or ranges. Optional shuffle.
# - Per-host concurrency and simple rate limiting.
# - Optional banner grab for TCP connect mode.
# - CSV/JSON output with only confirmed "open" results (UDP ambiguity preserved).

from __future__ import annotations

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
from typing import Dict, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Optional Scapy import
# -----------------------------------------------------------------------------

try:
    import scapy.all as scapy
    from scapy.packet import Raw
    SCAPY_AVAILABLE: bool = True
except Exception:
    SCAPY_AVAILABLE = False

# -----------------------------------------------------------------------------
# Defaults 
# -----------------------------------------------------------------------------

DEFAULTS: Dict[str, object] = {
    "HOST": os.environ.get("PORTSCAN_HOST", "160.153.248.110"),
    "PORTS": os.environ.get("PORTSCAN_PORTS", "21,22,135,80,443,445,50920-50930"),
    "START": int(os.environ.get("PORTSCAN_START", "1")),
    "END": int(os.environ.get("PORTSCAN_END", "1024")),
    "CONCURRENCY": int(os.environ.get("PORTSCAN_CONCURRENCY", "1")),
    "TIMEOUT": float(os.environ.get("PORTSCAN_TIMEOUT", "1.0")),
    "RATE": int(os.environ.get("PORTSCAN_RATE", "0")),  # 0 means unlimited
}

# -----------------------------------------------------------------------------
# Small utilities
# -----------------------------------------------------------------------------

def utc_now_str() -> str:
    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp


def read_targets_from_file(path: str) -> List[str]:
    # Read targets from a text file. Return a list with one target per line.
    #   - Ignore empty lines.
    #   - Ignore lines starting with '#'.
    #   - Strip whitespace.
    
    targets: List[str] = []

    with open(path, mode="r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if line == "":
                continue
            if line.startswith("#"):
                continue
            targets.append(line)

    return targets


def expand_cidr(arg: str) -> Optional[List[str]]:
    # Try to interpret 'arg' as a CIDR. If valid, expand and return all host IPs.
    # - Uses ipaddress.ip_network(strict=False).
    # - For IPv4: excludes network and broadcast via .hosts().
    # - If .hosts() is empty (e.g., /32), return the network address.

    try:
        network = ipaddress.ip_network(arg, strict=False)
    except ValueError:
        return None

    host_ips: List[str] = []

    for ip in network.hosts():
        host_ips.append(str(ip))

    if len(host_ips) == 0:
        host_ips.append(str(network.network_address))

    return host_ips


def expand_targets(arg: str) -> List[str]:
    # Produce a list of targets from:
    #   - a file path,
    #   - a CIDR (e.g., '10.0.0.0/24'),
    #   - a single IP or hostname.

    if os.path.isfile(arg):
        file_targets = read_targets_from_file(arg)
        return file_targets

    cidr_targets = expand_cidr(arg)
    if cidr_targets is not None:
        return cidr_targets

    return [arg]


def parse_ports(start_port: int, end_port: int, spec: Optional[str]) -> List[int]:
    # Parse a port specification into a sorted list of unique valid ports.
    # - start_port, end_port: inclusive range used when 'spec' is None.
    # - spec: string like "22,80,8000-8100".
    # - Valid range is 1..65535.
    # - Duplicates removed.

    ports: List[int] = []

    if spec is None:
        current = start_port
        while current <= end_port:
            ports.append(current)
            current += 1
    else:
        parts = spec.split(",")
        for raw in parts:
            token = raw.strip()
            if token == "":
                continue

            if "-" in token:
                left, right = token.split("-", 1)
                try:
                    start = int(left)
                    stop = int(right)
                except ValueError:
                    continue

                current = start
                while current <= stop:
                    ports.append(current)
                    current += 1
            else:
                try:
                    single = int(token)
                    ports.append(single)
                except ValueError:
                    continue

    # Filter invalid, then sort and deduplicate while preserving order.
    filtered: List[int] = []
    seen = set()

    for p in ports:
        if p < 1:
            continue
        if p > 65535:
            continue
        if p in seen:
            continue
        seen.add(p)
        filtered.append(p)

    filtered.sort()
    return filtered


# -----------------------------------------------------------------------------
# DNS/Name resolution
# -----------------------------------------------------------------------------

async def resolve_to_ip(label: str) -> str:
    # Resolve a hostname to an IP address string.
    # - Use asyncio.getaddrinfo with type=SOCK_STREAM.
    # - Prefer IPv4 (AF_INET), then IPv6 (AF_INET6).
    # - On any failure, return the input label unchanged.

    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(label, None, type=socket.SOCK_STREAM)
    except Exception:
        return label

    # Prefer IPv4 first, then IPv6
    preferred_families = (socket.AF_INET, socket.AF_INET6)

    for family in preferred_families:
        for af, _socktype, _proto, _canon, sockaddr in addrinfo:
            if af == family:
                ip = sockaddr[0]
                return ip

    # Fallback to the first entry if ordering is unexpected
    try:
        ip = addrinfo[0][4][0]
        return ip
    except Exception:
        return label


# -----------------------------------------------------------------------------
# TCP connect scan (asyncio)
# -----------------------------------------------------------------------------

async def try_read_banner(reader: asyncio.StreamReader,
                          timeout_seconds: float,
                          max_bytes: int = 128) -> str:
    # Attempt to read up to 'max_bytes' from a connected stream.
    # - Bounded by 'timeout_seconds'.
    # - Decoded as UTF-8 with replacement on errors.
    # - Empty string means no banner or an error.

    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout_seconds)
    except Exception:
        return ""

    if data is None:
        return ""

    text = data.decode("utf-8", errors="replace")
    text = text.strip()
    return text


async def scan_tcp_connect(host: str,
                           port: int,
                           timeout_seconds: float,
                           banner_enabled: bool) -> Tuple[str, int, str, str, str, int]:
    # Perform a TCP connect() style scan for one port.
    # Returns
    # -------
    # (host, port, proto, status, note, time)
    #   - proto  : "tcp"
    #   - status : "open", "closed", or "filtered"
    #   - note   : short reason or banner text
    #   - time : time in milliseconds

    start = time.perf_counter()
    try:
        open_task = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(open_task, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        dur = int((time.perf_counter() - start) * 1000)
        return host, port, "tcp", "filtered", "timeout", dur
    except ConnectionRefusedError:
        dur = int((time.perf_counter() - start) * 1000)
        return host, port, "tcp", "closed", "ECONNREFUSED", dur
    except OSError as os_err:
        errno = getattr(os_err, "errno", None)
        dur = int((time.perf_counter() - start) * 1000)
        if errno in (101, 110, 113):
            message = os.strerror(errno)
            return host, port, "tcp", "filtered", message, dur
        message = getattr(os_err, "strerror", repr(os_err))
        return host, port, "tcp", "closed", message, dur
    except Exception as exc:
        dur = int((time.perf_counter() - start) * 1000)
        return host, port, "tcp", "filtered", type(exc).__name__, dur

    # Connected successfully
    banner_text = ""
    if banner_enabled:
        small_timeout = min(timeout_seconds, 0.5)
        banner_text = await try_read_banner(reader, small_timeout, max_bytes=128)

    try:
        writer.close()
    except Exception:
        pass

    try:
        await writer.wait_closed()
    except Exception:
        pass

    dur = int((time.perf_counter() - start) * 1000)
    return host, port, "tcp", "open", banner_text, dur

# -----------------------------------------------------------------------------
# TCP SYN scan (Scapy in executor)
# -----------------------------------------------------------------------------

def scapy_syn_once(dst_ip: str, 
                   dst_port: int, 
                   timeout_seconds: float) -> Tuple[str, str]:
    # Send one TCP SYN and interpret the response.
    # Responses
    # ---------
    # - None           -> "filtered", "no-response"
    # - SYN+ACK        -> "open"    , "SYN-ACK"    (send RST to avoid full handshake)
    # - RST            -> "closed"  , "RST"
    # - Anything else  -> "filtered", "unexpected"

    ip_layer = scapy.IP(dst=dst_ip)
    tcp_layer = scapy.TCP(dport=dst_port, flags="S")
    packet = ip_layer / tcp_layer

    response = scapy.sr1(packet, timeout=timeout_seconds, verbose=0)

    if response is None:
        return "filtered", "no-response"

    has_tcp = response.haslayer(scapy.TCP)
    if not has_tcp:
        return "filtered", "unexpected"

    flags = response[scapy.TCP].flags
    syn_ack = (flags & 0x12) == 0x12
    rst_any = ((flags & 0x14) == 0x14) or ((flags & 0x04) == 0x04)

    if syn_ack:
        # Politely abort handshake to avoid leaving half-open connections
        rst_packet = scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port, flags="R")
        scapy.send(rst_packet, verbose=0)
        return "open", "SYN-ACK"

    if rst_any:
        return "closed", "RST"

    return "filtered", "unexpected"



async def scan_tcp_syn(host: str,
                       port: int,
                       timeout_seconds: float,
                       retries: int,
                       backoff_seconds: float) -> Tuple[str, int, str, str, str, int]:
    # Run a TCP SYN probe in a thread executor with simple retry logic.
    # Retries
    # -------
    # - Retries only on exceptions in the executor call.
    # - Linear backoff: wait 'backoff_seconds * attempt' between attempts.
    loop = asyncio.get_running_loop()
    attempt = 1
    last_error = ""
    start_total = time.perf_counter()
    while attempt <= max(1, retries):
        try:
            # measure executor call only (keeps timing simple and consistent)
            call_start = time.perf_counter()
            status, note = await loop.run_in_executor(
                None,
                scapy_syn_once,
                host,
                port,
                timeout_seconds
            )
            dur = int((time.perf_counter() - start_total) * 1000)
            return host, port, "tcp", status, note, dur
        except Exception as exc:
            last_error = type(exc).__name__
        if attempt < retries:
            await asyncio.sleep(backoff_seconds * attempt)
        attempt += 1
    dur = int((time.perf_counter() - start_total) * 1000)
    return host, port, "tcp", "filtered", last_error or "error", dur


# -----------------------------------------------------------------------------
# UDP scan (Scapy in executor)
# -----------------------------------------------------------------------------

def build_udp_payload(dst_port: int, probe_kind: str):
    # Build optional UDP payload for protocol-aware probing.
    # Options
    # -------
    # - "empty" : no payload
    # - "dns"   : standard A query for 'example.com' (only for port 53)
    # - "ntp"   : 48-byte client request (only for port 123)

    if probe_kind == "dns" and dst_port == 53:
        return scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))

    if probe_kind == "ntp" and dst_port == 123:
        # LI=0, VN=3, Mode=3 (client): first byte 0x1b followed by zeros to size 48
        payload_bytes = b"\x1b" + (b"\x00" * 47)
        return Raw(payload_bytes)

    return None


def scapy_udp_once(dst_ip: str,
                   dst_port: int,
                   timeout_seconds: float,
                   probe_kind: str) -> Tuple[str, str]:
    # Send one UDP probe and interpret the response.
    # Responses
    # ---------
    # - ICMP type=3 code=3   -> "closed", "icmp-port-unreachable"
    # - UDP/DNS application  -> "open"   , "udp-reply"/"dns-reply"
    # - No response          -> "open|filtered", "no-response" (ambiguous)
    # - Other ICMP           -> "filtered", "icmp type=X code=Y"

    payload = build_udp_payload(dst_port, probe_kind)

    ip_layer = scapy.IP(dst=dst_ip)
    udp_layer = scapy.UDP(dport=dst_port)

    if payload is None:
        packet = ip_layer / udp_layer
    else:
        packet = ip_layer / udp_layer / payload

    response = scapy.sr1(packet, timeout=timeout_seconds, verbose=0)

    if response is None:
        return "open|filtered", "no-response"

    if response.haslayer(scapy.ICMP):
        icmp = response[scapy.ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed", "icmp-port-unreachable"

        message = f"icmp type={icmp.type} code={icmp.code}"
        return "filtered", message

    # Application-level checks
    if probe_kind == "dns" and response.haslayer(scapy.DNS):
        return "open", "dns-reply"

    has_udp = response.haslayer(scapy.UDP)
    if has_udp:
        udp_payload_len = len(bytes(response[scapy.UDP].payload))
        if udp_payload_len > 0:
            return "open", "udp-reply"

    return "open|filtered", "unexpected"

async def scan_udp(host: str,
                   port: int,
                   timeout_seconds: float,
                   probe_kind: str,
                   retries: int,
                   backoff_seconds: float) -> Tuple[str, int, str, str, str, int]:
    # Run a UDP probe in a thread executor with simple retry logic.
    # UDP is often ambiguous. Many services do not respond to empty probes.
    loop = asyncio.get_running_loop()
    attempt = 1
    last_error = ""
    start_total = time.perf_counter()
    while attempt <= max(1, retries):
        try:
            status, note = await loop.run_in_executor(
                None,
                scapy_udp_once,
                host,
                port,
                timeout_seconds,
                probe_kind
            )
            dur = int((time.perf_counter() - start_total) * 1000)
            return host, port, "udp", status, note, dur
        except Exception as exc:
            last_error = type(exc).__name__
        if attempt < retries:
            await asyncio.sleep(backoff_seconds * attempt)
        attempt += 1
    dur = int((time.perf_counter() - start_total) * 1000)
    return host, port, "udp", "filtered", last_error or "error", dur


# -----------------------------------------------------------------------------
# Simple fixed-interval rate limiter
# -----------------------------------------------------------------------------

class FixedRateLimiter:
    # Enforce a minimum interval between operations.
    # rate_ops_per_sec : int
    #     Operations per second. If <= 0, rate limiting is disabled.
    # - Uses a single asyncio.Lock to serialize timestamp updates.
    # - Intended to be used per host to avoid bursts.

    def __init__(self, rate_ops_per_sec: int) -> None:
        self.rate = rate_ops_per_sec
        self._interval = 0.0
        self._last_time = 0.0
        self._lock = asyncio.Lock()

        if self.rate > 0:
            self._interval = 1.0 / float(self.rate)

    async def wait(self) -> None:
        # Sleep if needed so the time since the last operation
        # is at least 'self._interval'.

        if self.rate <= 0:
            return

        async with self._lock:
            now = time.perf_counter()
            elapsed = now - self._last_time
            remaining = self._interval - elapsed

            if remaining > 0.0:
                await asyncio.sleep(remaining)
                self._last_time = time.perf_counter()
            else:
                self._last_time = now


# -----------------------------------------------------------------------------
# Orchestrate a host scan
# -----------------------------------------------------------------------------

async def scan_host_ports(host_ip: str,
                          ports: List[int],
                          mode: str,
                          timeout_seconds: float,
                          max_concurrency: int,
                          show_closed: bool,
                          banner_enabled: bool,
                          ops_per_sec: int,
                          udp_probe_kind: str,
                          retries: int,
                          backoff_seconds: float) -> List[Dict[str, object]]:
    # Scan all ports for a single host based on the chosen mode.
    # Returns
    # -------
    # List[Dict[str, object]]
    #     Only confirmed "open" results are returned in this list.
    #     Each item contains: host, port, proto, status, note, time.

    semaphore = asyncio.Semaphore(max_concurrency)

    limiter = FixedRateLimiter(ops_per_sec)
    
    confirmed_open: List[Dict[str, object]] = []

    async def run_one_port(port: int) -> Tuple[str, int, str, str, str]:
        #Dispatch one port scan according to 'mode'.

        await limiter.wait()

        async with semaphore:
            if mode == "connect":
                result = await scan_tcp_connect(
                    host=host_ip,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    banner_enabled=banner_enabled
                )
                return result

            if mode == "syn":
                result = await scan_tcp_syn(
                    host=host_ip,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    retries=retries,
                    backoff_seconds=backoff_seconds
                )
                return result

            if mode == "udp":
                result = await scan_udp(
                    host=host_ip,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    probe_kind=udp_probe_kind,
                    retries=retries,
                    backoff_seconds=backoff_seconds
                )
                return result

            return host_ip, port, "tcp", "error", "unknown-mode"

    # Schedule all tasks. Concurrency is managed by the semaphore.
    tasks: List[asyncio.Task] = []
    for p in ports:
        task = asyncio.create_task(run_one_port(p))        
        tasks.append(task)

    # Stream results as they complete.
    for finished in asyncio.as_completed(tasks):
        host, port, proto, status, note, duration_ms = await finished
        timestamp = utc_now_str()

        # Print all non-closed or print closed if requested.
        should_print = (status != "closed") or show_closed
        duration_tag = f" [{duration_ms}ms]"
        if should_print:
            if note:
                print(f"# {timestamp}\t| {host}:{port}/{proto}\t= {status} {note}{duration_tag}")
            else:
                print(f"# {timestamp}\t| {host}:{port}/{proto}\t= {status}{duration_tag}")

        # Only record confirmed "open" results.
        if status == "open":
            record: Dict[str, object] = {
                "host": host,
                "port": port,
                "proto": proto,
                "status": status,
                "note": note,
                "time": timestamp,
                "duration_ms": duration_ms,
            }
            confirmed_open.append(record)



    return confirmed_open


# -----------------------------------------------------------------------------
# Preconditions for Scapy modes
# -----------------------------------------------------------------------------

def ensure_prerequisites_for_scapy(mode: str) -> None:
    # Validate that Scapy is available and we have root privileges
    # when mode requires raw sockets ("syn" or "udp").
    # Exits with status 2 on failure.

    if mode not in ("syn", "udp"):
        return

    if not SCAPY_AVAILABLE:
        print("Scapy not available. Install with: pip install scapy")
        sys.exit(2)

    # On Unix-like systems, geteuid exists. On Windows it does not.
    try:
        euid = os.geteuid()
    except AttributeError:
        # Cannot verify. Provide a warning and continue. Raw sockets may fail.
        print("Warning: cannot verify root privileges on this OS. SYN/UDP may fail.")
        return

    if euid != 0:
        print("Root privileges required for --syn or --udp. Rerun with sudo.")
        sys.exit(2)


# -----------------------------------------------------------------------------
# CLI and main program
# -----------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
   # Build and return the CLI argument parser.

    parser = argparse.ArgumentParser(
        description="Readable async port scanner (asyncio + optional Scapy)"
    )

    parser.add_argument(
        "--targets",
        required=False,
        default=str(DEFAULTS["HOST"]),
        help="Host/IP/CIDR or a file with one target per line",
    )

    parser.add_argument(
        "--start",
        type=int,
        default=int(DEFAULTS["START"]),
        help="Start port (inclusive)",
    )

    parser.add_argument(
        "--end",
        type=int,
        default=int(DEFAULTS["END"]),
        help="End port (inclusive)",
    )

    parser.add_argument(
        "--ports",
        default=str(DEFAULTS["PORTS"]),
        help="Comma list and ranges, e.g. 22,80,8000-8100 (overrides start/end)",
    )

    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=int(DEFAULTS["CONCURRENCY"]),
        help="Per-host concurrency",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=float(DEFAULTS["TIMEOUT"]),
        help="Timeout seconds",
    )

    parser.add_argument(
        "--csv",
        help="Write confirmed-open results to CSV file",
    )

    parser.add_argument(
        "--json",
        help="Write confirmed-open results to JSON file",
    )

    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Also print closed ports",
    )

    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomise port order before scanning",
    )

    parser.add_argument(
        "--banner",
        action="store_true",
        help="Grab a small banner on TCP connect",
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=int(DEFAULTS["RATE"]),
        help="Ops per second per host (0 = unlimited)",
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries for SYN/UDP probes",
    )

    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.2,
        help="Seconds; multiplied by attempt number",
    )

    parser.add_argument(
        "--udp-probe",
        choices=["empty", "dns", "ntp"],
        default="empty",
        help="UDP payload strategy",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--syn",
        action="store_true",
        help="SYN scan (root + scapy)",
    )
    mode_group.add_argument(
        "--udp",
        action="store_true",
        help="UDP scan (root + scapy)",
    )

    return parser


def main() -> None:
    # Entry point:
    #   1) Parse arguments.
    #   2) Determine ports and targets.
    #   3) Validate mode prerequisites.
    #   4) Resolve each target, run scan, aggregate results.
    #   5) Persist confirmed-open results if requested.

    parser = build_arg_parser()
    args = parser.parse_args()

    # Ports
    ports = parse_ports(args.start, args.end, args.ports)
    if len(ports) == 0:
        print("No ports selected.")
        sys.exit(1)

    if args.shuffle:
        random.shuffle(ports)

    # Mode
    mode = "connect"
    if args.syn:
        mode = "syn"
    if args.udp:
        mode = "udp"

    ensure_prerequisites_for_scapy(mode)

    # Targets
    targets = expand_targets(args.targets)
    if len(targets) == 0:
        print("No targets.")
        sys.exit(1)

    # Header
    print("*** PORT SCANNER MRIB ***")
    print("")
    print(
        f"SCAN start={utc_now_str()} "
        f"mode={mode} "
        f"targets={len(targets)} "
        f"ports={len(ports)} "
        f"concurrency={args.concurrency} "
        f"timeout={args.timeout}s "
        f"rate={args.rate}/s"
    )
    print("")

    # Run
    all_open_results: List[Dict[str, object]] = []

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        for target_label in targets:
            resolved_ip = loop.run_until_complete(resolve_to_ip(target_label))
            print(f"TARGET {target_label} -> {resolved_ip}")
            print("")

            open_for_host = loop.run_until_complete(
                scan_host_ports(
                    host_ip=resolved_ip,
                    ports=ports,
                    mode=mode,
                    timeout_seconds=args.timeout,
                    max_concurrency=max(1, args.concurrency),
                    show_closed=args.show_closed,
                    banner_enabled=args.banner,
                    ops_per_sec=max(0, args.rate),
                    udp_probe_kind=args.udp_probe,
                    retries=max(1, args.retries),
                    backoff_seconds=max(0.0, args.retry_backoff),
                )
            )

            # Extend the aggregate with open results for this host
            for record in open_for_host:
                all_open_results.append(record)

        loop.close()

    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)

    # Footer
    print("")
    print(f"SCAN end={utc_now_str()} open_found={len(all_open_results)}")

    # Persist results
    if args.csv and len(all_open_results) > 0:
        try:
            with open(args.csv, mode="w", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["host", "port", "proto", "status", "note", "time_utc", "duration_ms"])
                for rec in all_open_results:
                    row = [
                        rec.get("host", ""),
                        rec.get("port", ""),
                        rec.get("proto", ""),
                        rec.get("status", ""),
                        rec.get("note", ""),
                        rec.get("time", ""),
                        rec.get("duration_ms", ""),
                    ]
                    writer.writerow(row)
            print(f"csv -> {args.csv}")
        except Exception as exc:
            print(f"Failed to write CSV: {type(exc).__name__}")

    if args.json and len(all_open_results) > 0:
        try:
            with open(args.json, mode="w") as fh:
                json.dump(all_open_results, fh, indent=2)
            print(f"json -> {args.json}")
        except Exception as exc:
            print(f"Failed to write JSON: {type(exc).__name__}")


if __name__ == "__main__":
    main()
