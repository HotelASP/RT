#!/usr/bin/env python3
# --------------
# Asynchronous port scanner with three modes:
#   + Optional PCAP capture (--pcap)
#   1) TCP connect scan using asyncio (no root required)
#   2) TCP SYN scan using Scapy (root required)
#   3) UDP probe using Scapy (root required)
#
# -------------- EXAMPLES --------------
# sudo -i
# cd /home/kali/Desktop/RT
#########################################################################################
# Scan port 21 and get a banner, save output with specific filenames
# python3 portscanner-mrib.py --targets hotelasp.com --ports "21" --banner --csv results.csv --json results.json --pcap results.pcap
#########################################################################################
# Scan specific ports, save default-named outputs, shuffle port order, limit to 5 ops/s
# python3 portscanner-mrib.py --targets 160.153.248.110 --ports "21,22,53,135,80,443,445,50920-50930" --banner --shuffle --rate 5 --csv --json --pcap
#########################################################################################
# Full TCP SYN scan with high concurrency and rate limiting, save everything
# python3 portscanner-mrib.py --targets hackthissite.org --start 1 --end 65535 --syn --show-closed --rate 10 --concurrency 100 --csv --json --pcap
#########################################################################################
# UDP DNS probe with retries and backoff, write pcap/csv/json auto-named
# python3 portscanner-mrib.py --targets 8.8.8.8 --ports 53 --udp --udp-probe dns --timeout 2 --retries 2 --retry-backoff 0.2 --pcap --csv --json
#########################################################################################
# UDP NTP probe against NIST server, write pcap/csv/json auto-named
# python3 portscanner-mrib.py --targets 129.6.15.28 --ports 123 --udp --udp-probe ntp --timeout 5 --retries 2 --retry-backoff 0.3 --pcap --csv --json
#########################################################################################

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import random
import shlex
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Set

# BATCH MODE:
#   Use --test <specfile>. Each non-empty, non-comment line in <specfile> is a
#   complete CLI spec. Anything before the first '-' option on a line is ignored,
#   so both:
#     python3 portscanner-mrib.py --targets host --ports 21 --csv
#   and:
#   are valid in the spec file. Lines containing only '#', '-' or spaces are skipped.
#
# python3 portscanner-mrib.py --test batch.txt
## batch.txt
# --targets hotelasp.com --ports "21" --banner --csv batch-result1.csv --json batch-result1.json --pcap batch-result1.pcap
# --targets 160.153.248.110 --ports "21,22,53,135,80,443,445,50920-50930" --banner --shuffle --rate 5 --csv batch-result2.csv --json batch-result2.json --pcap batch-result2.pcap
# --targets hackthissite.org --start 1 --end 65 --syn --show-closed --rate 10 --concurrency 100 --csv batch-result3.csv --json batch-result3.json --pcap batch-result3.pcap
# --targets 8.8.8.8 --ports 53 --udp --udp-probe dns --timeout 2 --retries 2 --retry-backoff 0.2 --pcap batch-result4.pcap --csv batch-result4.csv --json batch-result4.json
# --targets 129.6.15.28 --ports 123 --udp --udp-probe ntp --timeout 5 --retries 2 --retry-backoff 0.3 --pcap batch-result5.pcap --csv batch-result5.csv --json batch-result5.json
#
# TEST BATTERY:
#   Use --test-battery <file_of_targets>. Runs a compact suite:
#     - TCP connect on [21, 22,80,443]
#     - If scapy+root: TCP SYN on [21, 22,80,443] and UDP DNS on 53
#   Respects --csv/--json/--pcap persistence.
#
# python3 portscanner-mrib.py --test-battery targets.txt --csv battery.csv --json battery.json --pcap battery.pcap
## targets.txt
# hotelasp.com
# hackthissite.org
# 8.8.8.8
# 129.6.15.28
# -----------------------------------------------------------------------------
# Optional Scapy import and runtime hints
# -----------------------------------------------------------------------------
# Scapy is only required for --syn and --udp modes, and also for --pcap capture.
# For best libpcap-based sniffing performance, scapy.conf.use_pcap = True is set
# if Scapy is importable. If scapy is not available, these modes will be blocked
# at runtime with a clear error.
# -----------------------------------------------------------------------------

try:
    import scapy.all as scapy
    from scapy.packet import Raw
    scapy.conf.use_pcap = True            # Prefer libpcap backend if available
    SCAPY_AVAILABLE: bool = True
except Exception:
    SCAPY_AVAILABLE = False

# -----------------------------------------------------------------------------
# Defaults and environment overrides
# -----------------------------------------------------------------------------

DEFAULTS: Dict[str, object] = {
    "HOST": os.environ.get("PORTSCAN_HOST", "137.74.187.102"),
    "START": int(os.environ.get("PORTSCAN_START", "1")),
    "END": int(os.environ.get("PORTSCAN_END", "1024")),
    "CONCURRENCY": int(os.environ.get("PORTSCAN_CONCURRENCY", "100")),
    "TIMEOUT": float(os.environ.get("PORTSCAN_TIMEOUT", "0.3")),
    "RATE": int(os.environ.get("PORTSCAN_RATE", "0")),  # 0 disables rate limiting
}

# -----------------------------------------------------------------------------
# Time and formatting helpers
# -----------------------------------------------------------------------------

def utc_now_str() -> str:
    # Return current time in UTC formatted for logs.
    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

def ts_utc_compact() -> str:
    # Return a compact timestamp for filenames.
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# -----------------------------------------------------------------------------
# Target expansion helpers
# -----------------------------------------------------------------------------

def read_targets_from_file(file_path: str) -> List[str]:
    # Read targets from a text file. Each non-empty, non-comment line is a target.
    targets: List[str] = []
    with open(file_path, mode="r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            targets.append(line)
    return targets

def expand_cidr_to_hosts(cidr_or_ip: str) -> Optional[List[str]]:
    # Expand a CIDR to host IPs. For /32 or a single address, include the address itself.
    try:
        network = ipaddress.ip_network(cidr_or_ip, strict=False)
    except ValueError:
        return None
    hosts: List[str] = [str(ip) for ip in network.hosts()]
    if not hosts:
        hosts.append(str(network.network_address))
    return hosts

def expand_targets_to_list(target_argument: str) -> List[str]:
    # Accept a filename, a CIDR, or a single hostname/IP.
    if os.path.isfile(target_argument):
        return read_targets_from_file(target_argument)
    cidr_hosts = expand_cidr_to_hosts(target_argument)
    if cidr_hosts is not None:
        return cidr_hosts
    return [target_argument]

# -----------------------------------------------------------------------------
# Fast mode helpers
# -----------------------------------------------------------------------------

def is_external_ip(ip_text: str) -> bool:
    """Return True when ip_text represents a global (external) IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        # Hostnames or unparsable inputs are treated as potentially external.
        return True

    # Python 3.11 exposes "is_global" for both IPv4/IPv6.
    is_global = getattr(ip_obj, "is_global", None)
    if is_global is not None:
        return bool(is_global)

    # Fallback logic for older interpreters.
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return False
    if getattr(ip_obj, "is_reserved", False):
        return False
    return True

def apply_fast_mode_overrides(args: argparse.Namespace) -> Optional[Dict[str, object]]:
    """
    Aggressively tune runtime options when --fast is supplied.
    Returns metadata describing the applied changes, or None when fast mode is off.
    """
    if not getattr(args, "fast", False):
        return None

    metadata: Dict[str, object] = {}

    # Maximise concurrency and disable artificial throttling.
    args.concurrency = max(int(args.concurrency), 1024)
    metadata["concurrency"] = args.concurrency

    if args.timeout <= 0:
        args.timeout = 0.05
    else:
        args.timeout = min(float(args.timeout), 0.15)
    metadata["timeout"] = args.timeout

    args.rate = 0
    metadata["rate"] = args.rate

    # Remove optional extras that slow scanning.
    args.shuffle = True
    metadata["shuffle"] = True

    args.banner = False
    metadata["banner"] = False

    args.retries = 1
    metadata["retries"] = args.retries

    args.retry_backoff = 0.0
    metadata["retry_backoff"] = args.retry_backoff

    auto_syn = False
    if not getattr(args, "udp", False) and not getattr(args, "syn", False) and SCAPY_AVAILABLE:
        try:
            if os.geteuid() == 0:
                args.syn = True
                auto_syn = True
        except AttributeError:
            # Platforms without geteuid(): fall back to connect scans.
            auto_syn = False

    metadata["auto_syn"] = auto_syn
    metadata["mode"] = "syn" if getattr(args, "syn", False) else ("udp" if getattr(args, "udp", False) else "connect")

    return metadata

# -----------------------------------------------------------------------------
# Port list parsing
# -----------------------------------------------------------------------------

def parse_port_specification(start_port: int, end_port: int, port_spec: Optional[str]) -> List[int]:
    # Convert a ports specification into a sorted unique list in [1, 65535].
    ports: List[int] = []
    if port_spec is None:
        # Range [start_port, end_port] inclusive
        for p in range(start_port, end_port + 1):
            ports.append(p)
    else:
        for token in port_spec.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                left, right = token.split("-", 1)
                try:
                    start = int(left)
                    stop = int(right)
                except ValueError:
                    continue
                if start > stop:
                    start, stop = stop, start
                for p in range(start, stop + 1):
                    ports.append(p)
            else:
                try:
                    ports.append(int(token))
                except ValueError:
                    continue

    # Filter invalid and deduplicate then sort
    valid_sorted_unique: List[int] = []
    seen = set()
    for p in ports:
        if p < 1 or p > 65535:
            continue
        if p in seen:
            continue
        seen.add(p)
        valid_sorted_unique.append(p)

    valid_sorted_unique.sort()
    return valid_sorted_unique

# -----------------------------------------------------------------------------
# Name resolution
# -----------------------------------------------------------------------------

async def resolve_dns_label_to_ip(dns_label: str) -> str:
    # Resolve a DNS label to an IP string using asyncio.getaddrinfo.
    # Prefer IPv4 then IPv6. On failure, return the original label.
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(dns_label, None, type=socket.SOCK_STREAM)
    except Exception:
        return dns_label

    preferred_families = (socket.AF_INET, socket.AF_INET6)
    for family in preferred_families:
        for af, _socktype, _proto, _canon, sockaddr in addrinfo:
            if af == family:
                return sockaddr[0]

    try:
        return addrinfo[0][4][0]
    except Exception:
        return dns_label

# -----------------------------------------------------------------------------
# TCP connect scan using asyncio streams
# -----------------------------------------------------------------------------

async def try_read_small_banner(stream_reader: asyncio.StreamReader,
                                timeout_seconds: float,
                                max_bytes: int = 128) -> str:
    # Try to read a small banner without blocking too long.
    try:
        data = await asyncio.wait_for(stream_reader.read(max_bytes), timeout=timeout_seconds)
    except Exception:
        return ""
    if not data:
        return ""
    return data.decode("utf-8", errors="replace").strip()

async def scan_tcp_connect_once(target_ip: str,
                                target_port: int,
                                timeout_seconds: float,
                                banner_enabled: bool) -> Tuple[str, int, str, str, str, int]:
    # Perform a single TCP connect probe and optionally read a banner.
    start = time.perf_counter()
    try:
        open_task = asyncio.open_connection(host=target_ip, port=target_port)
        reader, writer = await asyncio.wait_for(open_task, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return target_ip, target_port, "tcp", "filtered", "timeout", duration_ms
    except ConnectionRefusedError:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return target_ip, target_port, "tcp", "closed", "ECONNREFUSED", duration_ms
    except OSError as os_err:
        errno_val = getattr(os_err, "errno", None)
        duration_ms = int((time.perf_counter() - start) * 1000)
        if errno_val in (101, 110, 113):
            return target_ip, target_port, "tcp", "filtered", os.strerror(errno_val), duration_ms
        message = getattr(os_err, "strerror", repr(os_err))
        return target_ip, target_port, "tcp", "closed", message, duration_ms
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return target_ip, target_port, "tcp", "filtered", type(exc).__name__, duration_ms

    banner_text = ""
    if banner_enabled:
        banner_timeout = min(timeout_seconds, 0.5)
        banner_text = await try_read_small_banner(reader, banner_timeout, max_bytes=128)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    duration_ms = int((time.perf_counter() - start) * 1000)
    return target_ip, target_port, "tcp", "open", banner_text, duration_ms

# -----------------------------------------------------------------------------
# TCP SYN scan using Scapy (requires root)
# -----------------------------------------------------------------------------

def scapy_send_single_syn(dst_ip: str,
                          dst_port: int,
                          timeout_seconds: float) -> Tuple[str, str]:
    # Send one TCP SYN packet and interpret the response.
    # Return a tuple (status, note).
    ip_layer = scapy.IP(dst=dst_ip)
    tcp_layer = scapy.TCP(dport=dst_port, flags="S")
    probe_pkt = ip_layer / tcp_layer

    response = scapy.sr1(probe_pkt, timeout=timeout_seconds, verbose=0)

    if response is None:
        return "filtered", "no-response"
    if not response.haslayer(scapy.TCP):
        return "filtered", "unexpected"

    flags = response[scapy.TCP].flags
    syn_ack = (flags & 0x12) == 0x12
    rst_any = ((flags & 0x14) == 0x14) or ((flags & 0x04) == 0x04)

    if syn_ack:
        # Send a RST to avoid completing the handshake
        rst_pkt = scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port, flags="R")
        scapy.send(rst_pkt, verbose=0)
        return "open", "SYN-ACK"
    if rst_any:
        return "closed", "RST"
    return "filtered", "unexpected"

async def scan_tcp_syn_once(target_ip: str,
                            target_port: int,
                            timeout_seconds: float,
                            retries: int,
                            backoff_seconds: float) -> Tuple[str, int, str, str, str, int]:
    # Perform a TCP SYN probe with retries run in a thread executor.
    loop = asyncio.get_running_loop()
    attempt_index = 1
    last_error_note = ""
    scan_start = time.perf_counter()

    while attempt_index <= max(1, retries):
        try:
            status, note = await loop.run_in_executor(
                None,
                scapy_send_single_syn,
                target_ip,
                target_port,
                timeout_seconds
            )
            duration_ms = int((time.perf_counter() - scan_start) * 1000)
            return target_ip, target_port, "tcp", status, note, duration_ms
        except Exception as exc:
            last_error_note = type(exc).__name__
        if attempt_index < retries:
            await asyncio.sleep(backoff_seconds * attempt_index)
        attempt_index += 1

    duration_ms = int((time.perf_counter() - scan_start) * 1000)
    return target_ip, target_port, "tcp", "filtered", last_error_note or "error", duration_ms

# -----------------------------------------------------------------------------
# UDP scan using Scapy (requires root)
# -----------------------------------------------------------------------------

def build_udp_probe_payload(dst_port: int, probe_kind: str):
    # Create an application-aware UDP payload when possible.
    # "empty" -> None payload
    # "dns"   -> standard query for A record of google.com on port 53
    # "ntp"   -> client request with VN=4 and a transmit timestamp on port 123
    if probe_kind == "dns" and dst_port == 53:
        return scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com"))
    if probe_kind == "ntp" and dst_port == 123:
        import struct
        NTP_EPOCH = 2208988800
        now = time.time() + NTP_EPOCH
        sec = int(now)
        frac = int((now - sec) * (1 << 32)) & 0xFFFFFFFF
        first = bytes([0x23])  # LI=0, VN=4, Mode=3 (client)
        return Raw(first + b"\x00"*39 + struct.pack("!II", sec, frac))
    return None

def scapy_udp_probe_sniff_once(dst_ip: str,
                               dst_port: int,
                               timeout_seconds: float,
                               probe_kind: str) -> Tuple[str, str]:
    # Send one UDP probe and sniff a matching reply using a BPF filter.
    payload = build_udp_probe_payload(dst_port, probe_kind)

    # Choose egress interface as Scapy would route the packet
    try:
        iface_name = scapy.conf.route.route(dst_ip)[0]
    except Exception:
        iface_name = scapy.conf.iface

    src_port = int(scapy.RandShort())
    ip_layer = scapy.IP(dst=dst_ip, ttl=64)
    udp_layer = scapy.UDP(sport=src_port, dport=dst_port)
    probe_pkt = ip_layer / udp_layer / (payload or b"")

    # Only capture the real answer back to our ephemeral src_port
    bpf_filter = f"udp and src host {dst_ip} and src port {dst_port} and dst port {src_port}"

    # Arm a sniffer before sending to avoid race conditions
    sniffer = scapy.AsyncSniffer(filter=bpf_filter, iface=iface_name, store=True, promisc=True)
    sniffer.start()
    time.sleep(0.02)                      # give the sniffer time to arm
    scapy.send(probe_pkt, verbose=0)      # now send the probe
    sniffer.join(timeout_seconds)
    captured_pkts = sniffer.stop()

    if not captured_pkts:
        return "open|filtered", "no-response"

    resp = captured_pkts[0]

    # ICMP interpretation path if any slips through the BPF (rare with filter)
    if resp.haslayer(scapy.ICMP):
        icmp = resp[scapy.ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed", "icmp-port-unreachable"
        return "filtered", f"icmp type={icmp.type} code={icmp.code}"

    # UDP path with possible application payload
    if resp.haslayer(scapy.UDP) and resp[scapy.IP].src == dst_ip and resp[scapy.UDP].sport == dst_port:
        if probe_kind == "dns" and resp.haslayer(scapy.DNS):
            return "open", "dns-reply"
        raw_payload = bytes(resp[scapy.UDP].payload)
        if raw_payload:
            first = raw_payload[0]
            return "open", f"udp-reply first=0x{first:02x}"
        return "open", "udp-reply"

    return "filtered", "unexpected-src-or-proto"

async def scan_udp_once(target_ip: str,
                        target_port: int,
                        timeout_seconds: float,
                        probe_kind: str,
                        retries: int,
                        backoff_seconds: float) -> Tuple[str, int, str, str, str, int]:
    # Perform a UDP probe with retries run in a thread executor.
    loop = asyncio.get_running_loop()
    attempt_index = 1
    last_error_note = ""
    scan_start = time.perf_counter()

    while attempt_index <= max(1, retries):
        try:
            status, note = await loop.run_in_executor(
                None,
                scapy_udp_probe_sniff_once,
                target_ip,
                target_port,
                timeout_seconds,
                probe_kind
            )
            duration_ms = int((time.perf_counter() - scan_start) * 1000)
            return target_ip, target_port, "udp", status, note, duration_ms
        except Exception as exc:
            last_error_note = type(exc).__name__
        if attempt_index < retries:
            await asyncio.sleep(backoff_seconds * attempt_index)
        attempt_index += 1

    duration_ms = int((time.perf_counter() - scan_start) * 1000)
    return target_ip, target_port, "udp", "filtered", last_error_note or "error", duration_ms

# -----------------------------------------------------------------------------
# Fixed-rate limiter for per-host operation pacing
# -----------------------------------------------------------------------------

class FixedRateLimiter:
    # Enforce a minimum interval between operations when rate > 0.
    def __init__(self, rate_ops_per_sec: int) -> None:
        self.rate = max(0, rate_ops_per_sec)
        self._interval = 0.0 if self.rate <= 0 else 1.0 / float(self.rate)
        self._last_time = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        # Sleep to keep at most "rate" operations per second.
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
# Per-host orchestration: run probes, print progress, collect results
# -----------------------------------------------------------------------------

async def scan_all_selected_ports_for_host(target_ip: str,
                                           selected_ports: List[int],
                                           selected_mode: str,
                                           timeout_seconds: float,
                                           max_concurrency: int,
                                           show_closed_in_output: bool,
                                           banner_enabled: bool,
                                           per_host_ops_per_sec: int,
                                           udp_probe_kind: str,
                                           retries: int,
                                           backoff_seconds: float) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    # Scan all selected ports for a single host.
    # Return a tuple (confirmed_open_results, all_results_for_host).
    # Printing behavior:
    #   - Always print "non-closed" events.
    #   - If show_closed_in_output is True, also print "closed".
    # Persistence behavior is handled by the caller based on the same flag.

    semaphore = asyncio.Semaphore(max(1, max_concurrency))
    limiter = FixedRateLimiter(per_host_ops_per_sec)

    confirmed_open_results: List[Dict[str, object]] = []
    all_results_for_host: List[Dict[str, object]] = []

    async def run_one_port_probe(port_number: int) -> Tuple[str, int, str, str, str, int]:
        # Dispatch a single probe according to the selected mode.
        await limiter.wait()
        async with semaphore:
            if selected_mode == "connect":
                return await scan_tcp_connect_once(
                    target_ip,
                    port_number,
                    timeout_seconds,
                    banner_enabled
                )
            if selected_mode == "syn":
                return await scan_tcp_syn_once(
                    target_ip,
                    port_number,
                    timeout_seconds,
                    retries,
                    backoff_seconds
                )
            if selected_mode == "udp":
                return await scan_udp_once(
                    target_ip,
                    port_number,
                    timeout_seconds,
                    udp_probe_kind,
                    retries,
                    backoff_seconds
                )
            return target_ip, port_number, "tcp", "error", "unknown-mode", 0

    tasks: List[asyncio.Task] = [asyncio.create_task(run_one_port_probe(p)) for p in selected_ports]

    for finished in asyncio.as_completed(tasks):
        host, port, proto, status, note, duration_ms = await finished
        timestamp = utc_now_str()

        # Decide whether to print this line based on --show-closed
        # We print all results when show_closed_in_output is True
        # Otherwise, print everything except "closed"
        should_print = show_closed_in_output or (status != "closed")
        if should_print:
            note_suffix = f" {note}" if note else ""
            print(f"# {timestamp}\t| {host}:{port}/{proto}\t= {status}{note_suffix} [{duration_ms}ms]")

        # Persist a record for "all results"
        record: Dict[str, object] = {
            "host": host,
            "port": port,
            "proto": proto,
            "status": status,
            "note": note,
            "time": timestamp,
            "duration_ms": duration_ms,
        }
        all_results_for_host.append(record)

        # Persist a record for "confirmed open results" only when status == "open"
        if status == "open":
            confirmed_open_results.append(record)

    return confirmed_open_results, all_results_for_host

# -----------------------------------------------------------------------------
# Preconditions for Scapy-required modes
# -----------------------------------------------------------------------------

def ensure_prerequisites_for_scapy(selected_mode: str) -> None:
    # Enforce Scapy availability and root privileges when required.
    if selected_mode not in ("syn", "udp"):
        return
    if not SCAPY_AVAILABLE:
        print("Scapy not available. Install with: pip install scapy")
        sys.exit(2)
    try:
        euid = os.geteuid()
    except AttributeError:
        print("Warning: cannot verify root privileges on this OS. SYN/UDP may fail.")
        return
    if euid != 0:
        print("Root privileges required for --syn or --udp. Rerun with sudo.")
        sys.exit(2)

# -----------------------------------------------------------------------------
# PCAP helpers
# -----------------------------------------------------------------------------

def start_pcap_sniffer_for_host(filter_expression: Optional[str] = None) -> Any:
    # Start a Scapy AsyncSniffer with an optional BPF filter. Return the sniffer or None.
    if not SCAPY_AVAILABLE:
        return None
    try:
        sniffer = scapy.AsyncSniffer(filter=filter_expression)
        sniffer.start()
        return sniffer
    except Exception:
        return None

def stop_sniffer_and_write_pcap(sniffer: Any, pcap_filename: str) -> None:
    # Stop the sniffer and write packets to a PCAP file.
    if sniffer is None:
        return
    try:
        captured_packets = sniffer.stop()
        scapy.wrpcap(pcap_filename, captured_packets if captured_packets else [])
    except Exception as exc:
        print(f"Failed to write pcap {pcap_filename}: {type(exc).__name__}")

# -----------------------------------------------------------------------------
# CSV and JSON writers
# -----------------------------------------------------------------------------

def write_results_to_csv(csv_path: str, result_rows: List[Dict[str, object]]) -> None:
    # Write result rows to CSV with a fixed header.
    try:
        with open(csv_path, mode="w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "port", "proto", "status", "note", "time_utc", "duration_ms"])
            for rec in result_rows:
                writer.writerow([
                    rec.get("host", ""),
                    rec.get("port", ""),
                    rec.get("proto", ""),
                    rec.get("status", ""),
                    rec.get("note", ""),
                    rec.get("time", ""),
                    rec.get("duration_ms", ""),
                ])
        print(f"csv -> {csv_path}")
    except Exception as exc:
        print(f"Failed to write CSV: {type(exc).__name__}")

def write_results_to_json(json_path: str, result_rows: List[Dict[str, object]]) -> None:
    # Write result rows to a JSON file, pretty printed.
    try:
        with open(json_path, mode="w") as fh:
            json.dump(result_rows, fh, indent=2)
        print(f"json -> {json_path}")
    except Exception as exc:
        print(f"Failed to write JSON: {type(exc).__name__}")

# -----------------------------------------------------------------------------
# CLI builder
# -----------------------------------------------------------------------------

def build_cli_parser() -> argparse.ArgumentParser:
    # Build and return the CLI argument parser with descriptive help.
    parser = argparse.ArgumentParser(
        description="Readable async port scanner (asyncio + optional Scapy)"
    )

    parser.add_argument(
        "--targets",
        required=False,
        default=str(DEFAULTS["HOST"]),
        help="Host/IP/CIDR or a file with one target per line."
    )

    parser.add_argument(
        "--start",
        type=int,
        default=int(DEFAULTS["START"]),
        help="Start port (inclusive)."
    )

    parser.add_argument(
        "--end",
        type=int,
        default=int(DEFAULTS["END"]),
        help="End port (inclusive)."
    )

    parser.add_argument(
        "--ports",
        help="Explicit list and ranges, e.g. 22,80,8000-8100 (overrides start/end)."
    )

    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=int(DEFAULTS["CONCURRENCY"]),
        help="Per-host concurrency."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=float(DEFAULTS["TIMEOUT"]),
        help="Socket and probe timeout in seconds."
    )

    parser.add_argument(
        "--csv",
        nargs="?",
        const="AUTO",
        help="Write results to CSV. If no filename is given, an auto timestamped one is used."
    )

    parser.add_argument(
        "--json",
        nargs="?",
        const="AUTO",
        help="Write results to JSON. If no filename is given, an auto timestamped one is used."
    )

    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Also print CLOSED results and persist ALL results to CSV/JSON."
    )

    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomize port order before scanning."
    )

    parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt to grab a small banner on TCP connect mode."
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=int(DEFAULTS["RATE"]),
        help="Ops per second per host (0 = unlimited)."
    )

    parser.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Enable the fastest scanning profile. Forces high concurrency, low timeouts, "
            "SYN mode when possible, disables banners/retries, and skips non-external hosts."
        ),
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries for SYN/UDP probes."
    )

    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.2,
        help="Backoff seconds multiplied by attempt number."
    )

    parser.add_argument(
        "--udp-probe",
        choices=["empty", "dns", "ntp"],
        default="empty",
        help="UDP payload strategy for application-aware probing."
    )

    parser.add_argument(
        "--pcap",
        nargs="?",
        const="AUTO",
        help="Write packet captures to pcap file. With multiple targets, writes <base>.<ip>.pcap."
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--syn",
        action="store_true",
        help="TCP SYN scan (root + scapy)."
    )
    mode_group.add_argument(
        "--udp",
        action="store_true",
        help="UDP probe (root + scapy)."
    )

    # ----------------- NEW: Batch and Test Battery -----------------
    parser.add_argument(
        "--test",
        metavar="SPECFILE",
        help="Batch mode. SPECFILE has one full CLI spec per non-comment line. Prefix before first '-' is ignored."
    )
    parser.add_argument(
        "--test-battery",
        metavar="TARGETS_FILE",
        dest="test_battery",
        help="Run a compact test battery against targets listed in TARGETS_FILE."
    )
    # ---------------------------------------------------------------

    return parser

# -----------------------------------------------------------------------------
# Helpers to run a full scan using parsed args (single run)
# -----------------------------------------------------------------------------

def run_full_scan(parsed_args: argparse.Namespace) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    """
    Execute a complete scan flow based on parsed args.
    Returns (aggregate_confirmed_open, aggregate_all_results).
    """
    fast_metadata = apply_fast_mode_overrides(parsed_args)

    # Compute selected ports
    selected_ports = parse_port_specification(parsed_args.start, parsed_args.end, parsed_args.ports)
    if not selected_ports:
        print("No ports selected.")
        sys.exit(1)
    if parsed_args.shuffle:
        random.shuffle(selected_ports)

    # Decide scan mode
    selected_mode = "connect"
    if parsed_args.syn:
        selected_mode = "syn"
    if parsed_args.udp:
        selected_mode = "udp"
    if fast_metadata is not None:
        fast_metadata["mode"] = selected_mode


    # PCAP implies Scapy is needed to capture packets
    if getattr(parsed_args, "pcap", None) and not SCAPY_AVAILABLE:
        print("Scapy required for --pcap. Install with: pip install scapy")
        sys.exit(2)

    # Enforce prerequisites for Scapy modes
    ensure_prerequisites_for_scapy(selected_mode)

    # Expand targets
    target_labels = expand_targets_to_list(parsed_args.targets)
    if not target_labels:
        print("No targets.")
        sys.exit(1)

    # Resolve AUTO filenames once
    ts_compact = ts_utc_compact()
    if parsed_args.csv == "AUTO":
        parsed_args.csv = f"scan_csv_{ts_compact}.csv"
    if parsed_args.json == "AUTO":
        parsed_args.json = f"scan_json_{ts_compact}.json"

    # For PCAP: naming
    if parsed_args.pcap == "AUTO":
        parsed_args.pcap = f"scan_pcap_{ts_compact}"

    # Header
    print("*** PORT SCANNER MRIB ***")
    print("")
    print(
        f"SCAN start={utc_now_str()} "
        f"mode={selected_mode} "
        f"targets={len(target_labels)} "
        f"ports={len(selected_ports)} "
        f"concurrency={parsed_args.concurrency} "
        f"timeout={parsed_args.timeout}s "
        f"rate={parsed_args.rate}/s"
    )
    if fast_metadata is not None:
        rate_desc = "off" if parsed_args.rate <= 0 else f"{parsed_args.rate}/s"
        shuffle_state = "on" if parsed_args.shuffle else "off"
        banner_state = "on" if parsed_args.banner else "off"
        auto_syn_note = " (auto-selected SYN)" if fast_metadata.get("auto_syn") else ""
        print(
            f"[fast]{auto_syn_note} mode={selected_mode} "
            f"concurrency={parsed_args.concurrency} timeout={parsed_args.timeout}s "
            f"rate-limit={rate_desc} shuffle={shuffle_state} banner={banner_state} "
            f"retries={parsed_args.retries} backoff={parsed_args.retry_backoff}s"
        )
        print("[fast] Non-external targets will be skipped automatically.")
    print("")

    aggregate_confirmed_open: List[Dict[str, object]] = []
    aggregate_all_results: List[Dict[str, object]] = []
    scanned_any_target = False

    # Orchestration loop
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Track sniffers per resolved host when --pcap is enabled
        host_sniffers: Dict[str, Tuple[Any, str]] = {}

        for label in target_labels:
            resolved_ip = loop.run_until_complete(resolve_dns_label_to_ip(label))
            if fast_metadata is not None and not is_external_ip(resolved_ip):
                print(f"[fast] Skipping non-external target {label} [{resolved_ip}]")
                print("")
                continue
            # Verbose domain to IP line for readability
            if label != resolved_ip:
                print(f"Targeting DOMAIN {label} [{resolved_ip}]")
            else:
                print(f"TARGET {label} -> {resolved_ip}")
            scanned_any_target = True
            print("")

            # Start PCAP sniffer if requested
            if getattr(parsed_args, "pcap", None):
                if len(target_labels) == 1 and str(parsed_args.pcap).lower().endswith(".pcap"):
                    pcap_filename = parsed_args.pcap
                else:
                    base = parsed_args.pcap[:-5] if str(parsed_args.pcap).lower().endswith(".pcap") else parsed_args.pcap
                    pcap_filename = f"{base}.{resolved_ip}.pcap" if len(target_labels) > 1 else f"{base}.pcap"
                sniffer = start_pcap_sniffer_for_host(filter_expression=f"host {resolved_ip}")
                if sniffer is None:
                    print("Warning: could not start packet sniffer for host", resolved_ip)
                host_sniffers[resolved_ip] = (sniffer, pcap_filename)

            # Run the host scan and gather results
            open_for_host, all_for_host = loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip,
                    selected_ports=selected_ports,
                    selected_mode=selected_mode,
                    timeout_seconds=parsed_args.timeout,
                    max_concurrency=parsed_args.concurrency,
                    show_closed_in_output=parsed_args.show_closed,
                    banner_enabled=parsed_args.banner,
                    per_host_ops_per_sec=parsed_args.rate,
                    udp_probe_kind=parsed_args.udp_probe,
                    retries=max(1, parsed_args.retries),
                    backoff_seconds=max(0.0, parsed_args.retry_backoff),
                )
            )

            aggregate_confirmed_open.extend(open_for_host)
            aggregate_all_results.extend(all_for_host)

            # Stop sniffer and write PCAP file for this host if enabled
            if getattr(parsed_args, "pcap", None):
                sniffer, pcap_path = host_sniffers.get(resolved_ip, (None, None))
                if pcap_path:
                    stop_sniffer_and_write_pcap(sniffer, pcap_path)
                    print(f"pcap -> {pcap_path}")

        if fast_metadata is not None and not scanned_any_target:
            print("[fast] No external targets remained after filtering.")

        loop.close()

    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)

    # Footer and persistence
    print("")
    print(f"SCAN end={utc_now_str()} open_found={len(aggregate_confirmed_open)}")

    # Decide which collection to persist
    rows_for_persistence: List[Dict[str, object]]
    if parsed_args.show_closed:
        rows_for_persistence = aggregate_all_results
    else:
        rows_for_persistence = aggregate_confirmed_open

    # Write CSV if requested
    if parsed_args.csv:
        write_results_to_csv(parsed_args.csv, rows_for_persistence)

    # Write JSON if requested
    if parsed_args.json:
        write_results_to_json(parsed_args.json, rows_for_persistence)

    return aggregate_confirmed_open, aggregate_all_results

# -----------------------------------------------------------------------------
# Batch mode: parse and run multiple CLI specs from a file
# -----------------------------------------------------------------------------

def parse_spec_line_to_argv(line: str) -> Optional[List[str]]:
    """
    Convert one text line into argv tokens.
    - Ignore empty lines, comments (#...), and lines of only '#', '-' or spaces.
    - Drop any tokens before the first '-' option, so both full CLI and flags-only lines work.
    """
    s = line.strip()
    if not s:
        return None
    if s.startswith("#") or set(s) <= {"#", "-", " "}:
        return None
    try:
        tokens = shlex.split(s, comments=False, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    while tokens and not tokens[0].startswith("-"):
        tokens.pop(0)
    return tokens or None

def run_batch_from_file(spec_file: str) -> None:
    """
    Reads SPECFILE and executes each valid CLI spec sequentially.
    Each spec line is parsed against the same CLI as single-run mode.
    """
    parser = build_cli_parser()
    line_no = 0
    with open(spec_file, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line_no += 1
            argv = parse_spec_line_to_argv(raw)
            if argv is None:
                continue
            print(f"\n===== BATCH {line_no}: {' '.join(argv)} =====")
            try:
                args = parser.parse_args(argv)
            except SystemExit:
                print(f"[BATCH-{line_no}] Invalid spec: {raw.strip()}")
                continue
            run_full_scan(args)

# -----------------------------------------------------------------------------
# Test battery: quick probes against a list of targets
# -----------------------------------------------------------------------------

def run_test_battery(targets_file: str,
                     base_args: argparse.Namespace) -> None:

    #Execute a compact test battery for targets in 'targets_file':

    targets = read_targets_from_file(targets_file)
    if not targets:
        print("No targets found in test file.")
        return

    fast_metadata = apply_fast_mode_overrides(base_args)
    if fast_metadata is not None:
        rate_desc = "off" if base_args.rate <= 0 else f"{base_args.rate}/s"
        print(
            f"[fast] Test battery mode: concurrency={base_args.concurrency} "
            f"timeout={base_args.timeout}s rate-limit={rate_desc} "
            f"shuffle={'on' if base_args.shuffle else 'off'} banner={'on' if base_args.banner else 'off'}"
        )

    test_ports_connect = [21, 22, 80, 443]
    test_ports_syn = [21, 22, 80, 443]
    test_ports_udp = [53]

    agg_open: List[Dict[str, object]] = []
    agg_all: List[Dict[str, object]] = []
    scanned_any = False
    skipped_targets: Set[str] = set()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Connect scans (always)
    for label in targets:
        resolved_ip = loop.run_until_complete(resolve_dns_label_to_ip(label))
        skip_key = f"{label}|{resolved_ip}"
        if fast_metadata is not None and not is_external_ip(resolved_ip):
            if skip_key not in skipped_targets:
                print(f"[fast] Skipping non-external target {label} [{resolved_ip}]")
                skipped_targets.add(skip_key)
            continue
        print(f"[TEST] TARGET {label} -> {resolved_ip}")
        open_for_host, all_for_host = loop.run_until_complete(
            scan_all_selected_ports_for_host(
                target_ip=resolved_ip,
                selected_ports=test_ports_connect,
                selected_mode="connect",
                timeout_seconds=base_args.timeout,
                max_concurrency=base_args.concurrency,
                show_closed_in_output=base_args.show_closed,
                banner_enabled=base_args.banner,
                per_host_ops_per_sec=base_args.rate,
                udp_probe_kind=base_args.udp_probe,
                retries=max(1, base_args.retries),
                backoff_seconds=max(0.0, base_args.retry_backoff),
            )
        )
        agg_open.extend(open_for_host)
        agg_all.extend(all_for_host)
        scanned_any = True

    # Scapy-dependent tests
    scapy_ok = SCAPY_AVAILABLE
    try:
        euid = os.geteuid()
    except AttributeError:
        euid = None

    if scapy_ok and euid == 0:
        # SYN scans
        for label in targets:
            resolved_ip = loop.run_until_complete(resolve_dns_label_to_ip(label))
            skip_key = f"{label}|{resolved_ip}"
            if fast_metadata is not None and not is_external_ip(resolved_ip):
                if skip_key not in skipped_targets:
                    print(f"[fast] Skipping non-external target {label} [{resolved_ip}]")
                    skipped_targets.add(skip_key)
                continue
            print(f"[TEST] SYN-target {label} -> {resolved_ip}")
            open_for_host, all_for_host = loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip,
                    selected_ports=test_ports_syn,
                    selected_mode="syn",
                    timeout_seconds=base_args.timeout,
                    max_concurrency=base_args.concurrency,
                    show_closed_in_output=base_args.show_closed,
                    banner_enabled=False,
                    per_host_ops_per_sec=base_args.rate,
                    udp_probe_kind=base_args.udp_probe,
                    retries=max(1, base_args.retries),
                    backoff_seconds=max(0.0, base_args.retry_backoff),
                )
            )
            agg_open.extend(open_for_host)
            agg_all.extend(all_for_host)
            scanned_any = True

        # UDP DNS probes
        for label in targets:
            resolved_ip = loop.run_until_complete(resolve_dns_label_to_ip(label))
            skip_key = f"{label}|{resolved_ip}"
            if fast_metadata is not None and not is_external_ip(resolved_ip):
                if skip_key not in skipped_targets:
                    print(f"[fast] Skipping non-external target {label} [{resolved_ip}]")
                    skipped_targets.add(skip_key)
                continue
            print(f"[TEST] UDP-target {label} -> {resolved_ip}")
            open_for_host, all_for_host = loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip,
                    selected_ports=test_ports_udp,
                    selected_mode="udp",
                    timeout_seconds=base_args.timeout,
                    max_concurrency=base_args.concurrency,
                    show_closed_in_output=base_args.show_closed,
                    banner_enabled=False,
                    per_host_ops_per_sec=base_args.rate,
                    udp_probe_kind="dns",
                    retries=max(1, base_args.retries),
                    backoff_seconds=max(0.0, base_args.retry_backoff),
                )
            )
            agg_open.extend(open_for_host)
            agg_all.extend(all_for_host)
            scanned_any = True
    else:
        if not scapy_ok:
            print("Warning: Scapy not available. Skipping SYN/UDP tests. Install with: pip install scapy")
        elif euid != 0:
            print("Warning: Not running as root. Skipping SYN/UDP tests.")

    if fast_metadata is not None and not scanned_any:
        print("[fast] No external targets remained after filtering.")

    loop.close()

    # Persistence decision same as normal run
    rows_for_persistence = agg_all if base_args.show_closed else agg_open

    # Auto filenames if requested with bare --csv/--json
    ts_compact = ts_utc_compact()
    if base_args.csv:
        csvname = base_args.csv if base_args.csv != "AUTO" else f"test_csv_{ts_compact}.csv"
        write_results_to_csv(csvname, rows_for_persistence)
    if base_args.json:
        jsonname = base_args.json if base_args.json != "AUTO" else f"test_json_{ts_compact}.json"
        write_results_to_json(jsonname, rows_for_persistence)

    print(f"TEST end={utc_now_str()} open_found={len(agg_open)}")

# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------

def main() -> None:
    # Parse arguments
    cli_parser = build_cli_parser()
    args = cli_parser.parse_args()

    # Batch mode: run multiple specs and exit
    if args.test:
        run_batch_from_file(args.test)
        return

    # Test battery mode: quick probes on a list of targets and exit
    if args.test_battery:
        run_test_battery(args.test_battery, args)
        return

    # Single run
    run_full_scan(args)

# -----------------------------------------------------------------------------
# Standard Python entry guard
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()
