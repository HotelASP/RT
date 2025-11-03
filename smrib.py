#!/usr/bin/env python3
#----------------------------------------------------------------------------
# SMRIB – Multi-protocol scanner 
#----------------------------------------------------------------------------
#
# Execution examples:
#
# 1. Targeted TCP connect sweep with banner capture and explicit artifact names.
#    *** PCAP needs root ***
#    Command: sudo python3 smrib.py --targets 'targets.txt' --ports "21,22,80,443" --banner --csv 'logs/results.csv' --json 'logs/results.json' --pcap 'logs/results.pcap'
#    Outcome: establishes full TCP sessions, captures available TLS banners, and stores results in the requested CSV/JSON/PCAP files.
#
# 2. High-concurrency TCP SYN reconnaissance respecting rate guards.
#    Command: sudo python3 smrib.py --targets 10.0.5.2 --start 1 --end 1024 --syn --rate 15 --concurrency 200 --csv 'logs/log_syn_10_0_5_2.csv'
#    Outcome: performs Scapy-powered SYN scans, throttled to fifteen operations per second, while collecting a structured CSV report.
#
# 3. UDP DNS inspection with adaptive retries and packet capture.
#    Command: sudo python3 smrib.py --targets 1.1.1.1 --ports 53 --udp --udp-probe dns --timeout 1.5 --retries 3 --retry-backoff 0.25 --csv 'logs/log_dns_lookup.csv' --pcap 'logs/log_dns_lookup.pcap'
#    Outcome: emits DNS queries with exponential backoff, captures responses, and reports UDP reachability.
#
# 4. UDP NTP probing for time services validation.
#    Command: sudo python3 smrib.py --targets 17.253.84.253 --ports 123 --udp --udp-probe ntp --timeout 4 --retries 2 --csv 'logs/log_ntp_lookup.csv' --pcap 'logs/log_ntp_lookup.pcap'
#    Outcome: verifies NTP listener availability, persisting responses into a CSV report.
#
# 5. Fast mode acceleration with shuffled ports and automatic adjustments.
#    Command: sudo python3 smrib.py --targets 10.0.5.5  --ports "22,80,443,100-200" --fast --show-closed-terminal --csv 'logs/log_fast.csv'
#    Outcome: enforces aggressive timeouts, disables banners, randomizes port order, and prints closed ports while exporting a CSV summary.
#
# 6. Batch-driven multi-run execution from specification file.
#    Command: sudo python3 smrib.py --batch batch.txt
#    Outcome: iterates through each valid CLI line inside batch.txt, executing scans sequentially.
#
# 7. Compact diagnostic battery against a list of endpoints.
#    Command: sudo python3 smrib.py --batch-battery targets.txt --csv 'logs/batch_battery.csv' --json 'logs/batch_battery.json'
#    Outcome: conducts TCP connect, SYN, and UDP checks where permitted, consolidating the diagnostic results.
#
# 8. Web directory listing helper using HTTP wordlists.
#    Command: sudo python3 smrib.py --web-dir --url http://www.hackthissite.org --wordlist 'data/webdir_wordlist.txt'
#    Outcome: probes candidate paths from the wordlist and prints discovered HTTP status codes.

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
import contextlib
import csv
import ipaddress
import json
import os
import platform
import random
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from typing import Awaitable, Callable, Dict, List, Optional, Tuple, Any, Set

if sys.platform != "win32":
    import resource  # type: ignore[attr-defined]
else:
    resource = None  # type: ignore[assignment]


try:
    import scapy.all as scapy
    from scapy.packet import Raw
    scapy.conf.use_pcap = True            # [AUTO]Prefer libpcap backend when available
    SCAPY_AVAILABLE: bool = True
except Exception:
    SCAPY_AVAILABLE = False


# Default runtime configuration when smrib.py is invoked with no CLI flags.
# Environment variables named PORTSCAN_* can override each entry before
# command-line parsing applies further changes.
PORTSCAN_TIMEOUT_ENV_SET: bool = "PORTSCAN_TIMEOUT" in os.environ

DEFAULTS: Dict[str, object] = {
    "HOST": os.environ.get("PORTSCAN_HOST", "hackthissite.org"),
    "START": int(os.environ.get("PORTSCAN_START", "1")),
    "END": int(os.environ.get("PORTSCAN_END", "1024")),
    "CONCURRENCY": int(os.environ.get("PORTSCAN_CONCURRENCY", "100")),
    "TIMEOUT": float(os.environ.get("PORTSCAN_TIMEOUT", "0.3")),
    "RATE": int(os.environ.get("PORTSCAN_RATE", "0")),  # [AUTO]Zero disables rate limiting
}

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATA_DIRECTORY = os.path.join(SCRIPT_DIRECTORY, "data")
LOGS_DIRECTORY = os.path.join(SCRIPT_DIRECTORY, "logs")

DEFAULT_FIND_TARGETS_FILENAME = "targets_internal.txt"


def default_log_artifact_path(filename: str) -> str:
    """Return an absolute path inside the logs directory for auto artifacts."""

    if os.path.isabs(filename):
        return filename
    return os.path.join(LOGS_DIRECTORY, filename)

TOP_PORTS_FILENAME = "top-ports.txt"
DEFAULT_BATCH_BATTERY_TOP_PORTS = 200

SCAPY_CONCURRENCY_LIMIT: int = max(1, int(os.environ.get("PORTSCAN_SCAPY_MAX_CONCURRENCY", "256")))

FD_LIMIT_SAFETY_MARGIN: int = 32

FAST_MODE_MIN_CONCURRENCY: int = 1024


@dataclass
class ScanRecord:
    """Represents a single scan observation for CSV/JSON reporting."""

    host: str
    port: int
    proto: str
    status: str
    note: str
    banner: str
    time: str
    duration_ms: int

    def is_open(self) -> bool:
        """Return ``True`` when the record indicates an open service."""

        return self.status.lower() == "open"

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON/CSV friendly dictionary representation."""

        return asdict(self)


@dataclass
class InterfaceNetwork:
    """Description of an IPv4 network reachable through a local interface."""

    name: str
    network: ipaddress.IPv4Network
    local_ip: ipaddress.IPv4Address
    source: str = "interface"

    def contains_local_ip(self) -> bool:
        """Return True when the local IP belongs to the associated network."""

        return self.local_ip in self.network


@dataclass
class PingObservation:
    """Details extracted from a successful ping probe."""

    success: bool
    latency_ms: Optional[float] = None
    ttl: Optional[int] = None
    packets_transmitted: Optional[int] = None
    packets_received: Optional[int] = None
    raw_output: str = ""
    anomaly_detected: bool = False


@dataclass
class PortScanConfiguration:
    """Parameters required to reuse the port scanner for discovered hosts."""

    ports: List[int]
    mode: str
    concurrency: int
    timeout: float
    show_closed: bool
    show_only_open: bool
    banner: bool
    rate: int
    udp_probe: str
    retries: int
    backoff: float

class StoreValueAndMarkExplicit(argparse.Action):
    """argparse action that records whether a CLI option was provided explicitly."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, values)
        setattr(namespace, f"{self.dest}_explicit", True)

# Return the soft RLIMIT_NOFILE value when available.
def query_process_fd_soft_limit() -> Optional[int]:

    if resource is None:
        return None

    try:
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)  # type: ignore[arg-type]
    except Exception:
        return None

    infinity = getattr(resource, "RLIM_INFINITY", None)
    if infinity is not None and soft_limit == infinity:
        return None
    if soft_limit <= 0:
        return None
    return int(soft_limit)

# Clamp concurrency so it respects the process file descriptor soft limit.
def apply_fd_limit_guardrail(desired_concurrency: int) -> Tuple[int, Optional[int]]:

    sanitized = max(1, int(desired_concurrency))
    soft_limit = query_process_fd_soft_limit()
    if soft_limit is None:
        return sanitized, None

    dynamic_margin = min(max(FD_LIMIT_SAFETY_MARGIN, soft_limit // 10), 256)
    max_allowed = max(1, soft_limit - dynamic_margin)
    if sanitized <= max_allowed:
        return sanitized, None
    return max_allowed, soft_limit

# [AUTO]Return an ISO-like timestamp string in UTC for log entries.
def utc_now_str() -> str:

    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

# [AUTO]Generate a compact UTC timestamp suited for filenames.
def ts_utc_compact() -> str:

    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# [AUTO]Load target entries from a UTF-8 text file, ignoring comments.
def read_targets_from_file(file_path: str) -> List[str]:

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
# [AUTO]Expand a textual CIDR or single IP address into host strings.
def expand_cidr_to_hosts(cidr_or_ip: str) -> Optional[List[str]]:

    try:
        network = ipaddress.ip_network(cidr_or_ip, strict=False)
    except ValueError:
        return None
    hosts: List[str] = [str(ip) for ip in network.hosts()]
    if not hosts:
        hosts.append(str(network.network_address))
    return hosts
# [AUTO]Resolve an argument into targets via file, CIDR range, or literal host.
def expand_targets_to_list(target_argument: str) -> List[str]:

    if os.path.isfile(target_argument):
        return read_targets_from_file(target_argument)

    # Support comma/whitespace separated target lists supplied via CLI.
    # Recurse per token so CIDR/file expansion still applies to individual entries.
    tokens = [segment for segment in re.split(r"[\s,]+", target_argument) if segment]
    if len(tokens) > 1:
        expanded: List[str] = []
        for token in tokens:
            expanded.extend(expand_targets_to_list(token))
        return expanded

    cidr_hosts = expand_cidr_to_hosts(target_argument)
    if cidr_hosts is not None:
        return cidr_hosts
    return [target_argument]

# [AUTO]Detect whether an address should be treated as public internet space.
def _resolve_targets_file_path(file_path: str) -> Optional[str]:

    normalized = os.path.expanduser(str(file_path))
    candidate_paths = [normalized]
    if not os.path.isabs(normalized):
        candidate_paths.append(os.path.join(SCRIPT_DIRECTORY, normalized))

    for candidate in candidate_paths:
        if os.path.isfile(candidate):
            return candidate
    return None


def _parse_targets_file_into_networks(
    resolved_path: str,
    *,
    quiet: bool = False,
) -> Tuple[List[Tuple[ipaddress.IPv4Network, int]], Optional[bool]]:

    networks: List[Tuple[ipaddress.IPv4Network, int]] = []
    include_external_setting: Optional[bool] = None
    seen: Set[str] = set()

    try:
        with open(resolved_path, "r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                candidate = stripped.split("#", 1)[0].strip()
                if not candidate:
                    continue
                if "=" in candidate:
                    key, value = [segment.strip() for segment in candidate.split("=", 1)]
                    if key.lower() == "include_external":
                        try:
                            include_external_setting = interpret_boolean_choice(value)
                        except ValueError:
                            if not quiet:
                                print(
                                    f"[find] Invalid include_external value '{value}' on line {line_number} "
                                    f"of {resolved_path}. Expected yes/no or true/false."
                                )
                        continue
                try:
                    network = ipaddress.IPv4Network(candidate, strict=False)
                except ValueError:
                    if not quiet:
                        print(
                            f"[find] Skipping invalid network '{candidate}' on line {line_number} "
                            f"of {resolved_path}."
                        )
                    continue
                key = network.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                networks.append((network, line_number))
    except OSError as exc:
        if not quiet:
            print(f"[find] Unable to read additional targets file {resolved_path}: {exc}")
        return [], include_external_setting

    return networks, include_external_setting


@lru_cache(maxsize=1)
def _load_internal_ipv4_networks_from_file() -> List[ipaddress.IPv4Network]:

    resolved_path = _resolve_targets_file_path(DEFAULT_FIND_TARGETS_FILENAME)
    if resolved_path is None:
        return []

    entries, _ = _parse_targets_file_into_networks(resolved_path, quiet=True)
    return [network for network, _ in entries]


def is_external_ip(ip_text: str) -> bool:

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return True

    configured_networks: List[ipaddress.IPv4Network] = []
    matched_configured_network = False

    if isinstance(ip_obj, ipaddress.IPv4Address):
        configured_networks = _load_internal_ipv4_networks_from_file()
        matched_configured_network = any(ip_obj in network for network in configured_networks)
        if matched_configured_network:
            return False

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return False

    if getattr(ip_obj, "is_reserved", False):
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return not matched_configured_network
        return False

    is_global_attribute = getattr(ip_obj, "is_global", None)
    if is_global_attribute is not None:
        return bool(is_global_attribute)

    return True


def interpret_boolean_choice(value: str) -> bool:

    normalized = value.strip().lower()
    if normalized in {"1", "true", "t", "yes", "y"}:
        return True
    if normalized in {"0", "false", "f", "no", "n"}:
        return False
    raise ValueError(value)


def argparse_boolean_choice(value: str) -> bool:

    try:
        return interpret_boolean_choice(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid choice '{value}'. Expected yes/no or true/false."
        ) from exc


def gather_local_ipv4_interfaces(include_external: bool = False) -> List[InterfaceNetwork]:

    def add_interface(result: Dict[Tuple[str, str], InterfaceNetwork], name: str,
                      address: str, netmask: str) -> None:
        if not address or not netmask:
            return
        try:
            ipv4_address = ipaddress.IPv4Address(address)
            network = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
        except Exception:
            return
        ip_text = str(ipv4_address)
        if not include_external and is_external_ip(ip_text):
            return
        if ipv4_address.is_loopback:
            return
        key = (name, network.with_prefixlen)
        if key in result:
            return
        result[key] = InterfaceNetwork(name=name, network=network, local_ip=ipv4_address)

    collected: Dict[Tuple[str, str], InterfaceNetwork] = {}
    interface_local_ip: Dict[str, ipaddress.IPv4Address] = {}

    try:
        import psutil  # type: ignore
    except Exception:
        psutil = None  # type: ignore

    if psutil is not None:
        try:
            for interface_name, addresses in psutil.net_if_addrs().items():  # type: ignore[attr-defined]
                for address in addresses:
                    if getattr(address, "family", None) != socket.AF_INET:
                        continue
                    ip_value = getattr(address, "address", "") or ""
                    netmask_value = getattr(address, "netmask", "") or ""
                    before = len(collected)
                    add_interface(collected, interface_name, ip_value, netmask_value)
                    if len(collected) != before:
                        try:
                            interface_local_ip[interface_name] = ipaddress.IPv4Address(ip_value)
                        except Exception:
                            pass
        except Exception:
            pass

    if not collected:
        try:
            output = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in output.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                name = parts[1]
                address_cidr = parts[3]
                if "/" not in address_cidr:
                    continue
                try:
                    ipv4_interface = ipaddress.IPv4Interface(address_cidr)
                except Exception:
                    continue
                before = len(collected)
                add_interface(collected, name, str(ipv4_interface.ip), str(ipv4_interface.network.netmask))
                if len(collected) != before:
                    interface_local_ip.setdefault(name, ipv4_interface.ip)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

    if not collected:
        try:
            output = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            output = None
        if output is not None:
            current_interface = ""
            for line in output.stdout.splitlines():
                if line and not line[0].isspace():
                    current_interface = line.split(":", 1)[0].strip()
                    continue
                line = line.strip()
                if not line or not current_interface:
                    continue
                match = re.search(r"inet (?!6)([0-9.]+)(?:\s+netmask\s+([^\s]+))?", line)
                if not match:
                    continue
                address = match.group(1)
                netmask = match.group(2) or ""
                if netmask.lower().startswith("0x"):
                    try:
                        int_mask = int(netmask, 16)
                        netmask = socket.inet_ntoa(int_mask.to_bytes(4, byteorder="big"))
                    except Exception:
                        netmask = ""
                before = len(collected)
                add_interface(collected, current_interface, address, netmask)
                if len(collected) != before:
                    try:
                        interface_local_ip[current_interface] = ipaddress.IPv4Address(address)
                    except Exception:
                        pass

    routed: Dict[Tuple[str, str], InterfaceNetwork] = {}

    def add_routed_network(interface_name: str, network: ipaddress.IPv4Network,
                           local_ip: Optional[ipaddress.IPv4Address]) -> None:
        if local_ip is None:
            return
        key = (interface_name, network.with_prefixlen)
        if key in collected or key in routed:
            return
        representative = str(network.network_address)
        if not include_external and is_external_ip(representative):
            return
        routed[key] = InterfaceNetwork(
            name=interface_name,
            network=network,
            local_ip=local_ip,
            source="route",
        )

    try:
        output = subprocess.run(
            ["ip", "-f", "inet", "route", "show"],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in output.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            destination = parts[0]
            if destination in {"default", "broadcast", "unreachable", "prohibit", "throw"}:
                continue
            if destination.count("/") == 0:
                destination = f"{destination}/32"
            try:
                network = ipaddress.IPv4Network(destination, strict=False)
            except Exception:
                continue
            dev_index = None
            src_index = None
            for index, token in enumerate(parts):
                if token == "dev" and index + 1 < len(parts):
                    dev_index = index + 1
                if token == "src" and index + 1 < len(parts):
                    src_index = index + 1
            if dev_index is None:
                continue
            interface_name = parts[dev_index]
            local_ip = None
            if src_index is not None:
                try:
                    local_ip = ipaddress.IPv4Address(parts[src_index])
                except Exception:
                    local_ip = None
            if local_ip is None:
                local_ip = interface_local_ip.get(interface_name)
            add_routed_network(interface_name, network, local_ip)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    if not routed:
        try:
            output = subprocess.run(
                ["route", "-n"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            output = None
        if output is not None:
            for line in output.stdout.splitlines():
                tokens = line.split()
                if len(tokens) < 8 or tokens[0].lower() == "destination":
                    continue
                destination, gateway, netmask, _, _, _, _, interface_name = tokens[:8]
                if destination == "0.0.0.0":
                    continue
                try:
                    network = ipaddress.IPv4Network(f"{destination}/{netmask}", strict=False)
                except Exception:
                    continue
                add_routed_network(interface_name, network, interface_local_ip.get(interface_name))

    combined = list(collected.values()) + list(routed.values())
    return sorted(
        combined,
        key=lambda item: (
            item.name,
            int(item.network.network_address),
            item.network.prefixlen,
            int(item.local_ip),
        ),
    )


def determine_ping_command() -> Optional[List[str]]:

    ping_path = shutil.which("ping")
    if not ping_path:
        return None
    system_name = platform.system().lower()
    if system_name == "windows":
        return [ping_path, "-n", "1", "-w", "1000"]
    if system_name == "darwin":
        return [ping_path, "-n", "-c", "1", "-W", "1000"]
    return [ping_path, "-n", "-c", "1", "-W", "1"]


def _parse_latency_from_ping(output_text: str) -> Optional[float]:

    latency_pattern = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*([a-z]+)")
    match = latency_pattern.search(output_text)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2)
    if unit == "ms":
        return value
    if unit == "s":
        return value * 1000.0
    if unit == "us":
        return value / 1000.0
    return value


def _parse_ttl_from_ping(output_text: str) -> Optional[int]:

    ttl_pattern = re.compile(r"ttl[= ](\d+)")
    match = ttl_pattern.search(output_text)
    if not match:
        return None
    return int(match.group(1))


def _parse_packet_stats_from_ping(output_text: str) -> Tuple[Optional[int], Optional[int]]:

    transmitted_pattern = re.compile(r"(\d+)\s+(?:packets\s+)?transmitted")
    received_pattern = re.compile(r"(\d+)\s+(?:packets\s+)?received")
    transmitted_match = transmitted_pattern.search(output_text)
    received_match = received_pattern.search(output_text)
    transmitted = int(transmitted_match.group(1)) if transmitted_match else None
    received = int(received_match.group(1)) if received_match else None
    return transmitted, received


async def run_ping_probe(
    ip_text: str, ping_command: List[str], timeout_seconds: float
) -> PingObservation:

    try:
        process = await asyncio.create_subprocess_exec(
            *ping_command,
            ip_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        return PingObservation(success=False)

    try:
        stdout_data, stderr_data = await asyncio.wait_for(
            process.communicate(), timeout_seconds
        )
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        return PingObservation(success=False)
    if process.returncode != 0:
        return PingObservation(success=False)

    output_blob = (stdout_data or b"") + (stderr_data or b"")
    raw_output = output_blob.decode("utf-8", errors="ignore")
    if not output_blob:
        return PingObservation(success=False)

    output_text_lower = raw_output.lower()

    packet_loss_pattern = re.compile(r"(\d+)\s+(?:packets\s+)?received")
    packet_loss_match = packet_loss_pattern.search(output_text_lower)
    if packet_loss_match and packet_loss_match.group(1).isdigit():
        if int(packet_loss_match.group(1)) == 0:
            return PingObservation(success=False, raw_output=raw_output)

    if "destination host unreachable" in output_text_lower:
        return PingObservation(success=False, raw_output=raw_output)
    if "100% packet loss" in output_text_lower:
        return PingObservation(success=False, raw_output=raw_output)

    success_markers = (
        "ttl=",
        "time=",
        "time<",
        "reply from",
        "bytes from",
    )
    has_success_marker = any(marker in output_text_lower for marker in success_markers)
    if not has_success_marker:
        return PingObservation(success=False, raw_output=raw_output)

    anomaly_markers = (
        "wrong data byte",
        "invalid tv_usec",
        "time of day goes back",
    )
    anomaly_detected = any(marker in output_text_lower for marker in anomaly_markers)

    latency_ms = _parse_latency_from_ping(output_text_lower)
    ttl = _parse_ttl_from_ping(output_text_lower)
    transmitted, received = _parse_packet_stats_from_ping(output_text_lower)

    if latency_ms is not None and latency_ms <= 0.0:
        return PingObservation(
            success=False,
            latency_ms=latency_ms,
            ttl=ttl,
            packets_transmitted=transmitted,
            packets_received=received,
            raw_output=raw_output,
        )

    return PingObservation(
        success=True,
        latency_ms=latency_ms,
        ttl=ttl,
        packets_transmitted=transmitted,
        packets_received=received,
        raw_output=raw_output,
        anomaly_detected=anomaly_detected,
    )


def format_ping_observation(observation: PingObservation) -> str:

    if not observation.success:
        return " (ping failed)"

    details: List[str] = []
    if observation.latency_ms is not None:
        details.append(f"latency={observation.latency_ms:.2f} ms")
    if observation.ttl is not None:
        details.append(f"ttl={observation.ttl}")
    if (
        observation.packets_transmitted is not None
        and observation.packets_received is not None
    ):
        details.append(
            f"tx/rx={observation.packets_transmitted}/{observation.packets_received}"
        )
    if observation.anomaly_detected:
        details.append("warnings")
    if not details:
        details.append("success")
    return " (ping " + ", ".join(details) + ")"


async def discover_hosts_on_interface(interface: InterfaceNetwork,
                                       ping_command: List[str],
                                       on_host_found: Callable[[str, PingObservation], Awaitable[None]],
                                       max_concurrency: int = 128,
                                       ping_timeout: float = 1.5) -> None:

    semaphore = asyncio.Semaphore(max(1, max_concurrency))
    skip_local_ip = interface.source != "file" and interface.contains_local_ip()
    local_ip = interface.local_ip if skip_local_ip else None
    tasks: List[asyncio.Task] = []

    async def probe(address: ipaddress.IPv4Address) -> None:
        if local_ip is not None and address == local_ip:
            return
        ip_text = str(address)
        try:
            async with semaphore:
                observation = await run_ping_probe(ip_text, ping_command, ping_timeout)
        except Exception:
            return
        if observation.success:
            await on_host_found(ip_text, observation)

    candidate_addresses: List[ipaddress.IPv4Address] = list(interface.network.hosts())

    if not candidate_addresses:
        candidate_addresses.append(interface.network.network_address)
        if interface.network.num_addresses > 1:
            broadcast = interface.network.broadcast_address
            if broadcast not in candidate_addresses:
                candidate_addresses.append(broadcast)

    for candidate in candidate_addresses:
        tasks.append(asyncio.create_task(probe(candidate)))

    if not tasks:
        return

    await asyncio.gather(*tasks, return_exceptions=False)


def load_additional_find_networks(
    file_path: str,
    *,
    quiet_missing: bool = False,
    source_label: str = "file",
) -> Tuple[List[InterfaceNetwork], Optional[bool]]:

    resolved_path = _resolve_targets_file_path(file_path)
    if resolved_path is None:
        if not quiet_missing:
            print(f"[find] Additional targets file not found: {file_path}")
        return [], None

    parsed_networks, include_external_setting = _parse_targets_file_into_networks(
        resolved_path,
        quiet=False,
    )

    networks: List[InterfaceNetwork] = [
        InterfaceNetwork(
            name=f"{source_label}:{os.path.basename(resolved_path)}:{line_number}",
            network=network,
            local_ip=network.network_address,
            source=source_label,
        )
        for network, line_number in parsed_networks
    ]

    if networks:
        print(
            f"[find] Loaded {len(networks)} additional network(s) from {resolved_path}."
        )
    else:
        print(f"[find] No additional networks found in {resolved_path}.")
    return networks, include_external_setting

# [AUTO]Tune parameters aggressively when --fast is active.
def apply_fast_mode_overrides(parsed_arguments: argparse.Namespace) -> Optional[Dict[str, object]]:

    if not getattr(parsed_arguments, "fast", False):
        return None

    fast_mode_adjustments: Dict[str, object] = {}

    requested_concurrency = int(getattr(parsed_arguments, "concurrency", 0))
    fast_target = max(requested_concurrency, FAST_MODE_MIN_CONCURRENCY)
    optimized_concurrency, fd_limit = apply_fd_limit_guardrail(fast_target)
    parsed_arguments.concurrency = optimized_concurrency
    fast_mode_adjustments["concurrency"] = optimized_concurrency
    if fd_limit is not None and optimized_concurrency < fast_target:
        fast_mode_adjustments["concurrency_guardrail_notice"] = (
            f"Concurrency capped at {optimized_concurrency} due to file descriptor soft limit {fd_limit}."
        )

    configured_timeout = float(getattr(parsed_arguments, "timeout", 0.0))
    timeout_explicit = bool(getattr(parsed_arguments, "timeout_explicit", False))
    if timeout_explicit and configured_timeout > 0.0:
        optimized_timeout = configured_timeout
    elif configured_timeout <= 0.0:
        optimized_timeout = 0.3
    else:
        optimized_timeout = min(configured_timeout, 0.3)
    parsed_arguments.timeout = optimized_timeout
    fast_mode_adjustments["timeout"] = optimized_timeout

    parsed_arguments.rate = 0
    fast_mode_adjustments["rate"] = 0

    parsed_arguments.shuffle = True
    fast_mode_adjustments["shuffle"] = True

    parsed_arguments.banner = False
    fast_mode_adjustments["banner"] = False

    parsed_arguments.retries = 1
    fast_mode_adjustments["retries"] = 1

    parsed_arguments.retry_backoff = 0.0
    fast_mode_adjustments["retry_backoff"] = 0.0

    fast_mode_adjustments["includes_private_targets"] = True

    auto_syn_enabled = False
    if not getattr(parsed_arguments, "syn", False) and not getattr(parsed_arguments, "udp", False):
        # Attempt to promote fast mode to SYN scanning when prerequisites hold.
        auto_syn_reason = ""
        if SCAPY_AVAILABLE:
            try:
                if os.geteuid() == 0:
                    parsed_arguments.syn = True
                    auto_syn_enabled = True
                else:
                    auto_syn_reason = "root-required"
            except AttributeError:
                auto_syn_reason = "privilege-unknown"
        else:
            auto_syn_reason = "scapy-missing"
        if auto_syn_reason:
            fast_mode_adjustments["auto_syn_reason"] = auto_syn_reason

    fast_mode_adjustments["auto_syn"] = auto_syn_enabled
    fast_mode_adjustments["mode"] = "syn" if getattr(parsed_arguments, "syn", False) else (
        "udp" if getattr(parsed_arguments, "udp", False) else "connect"
    )

    return fast_mode_adjustments

# [AUTO]Enforce safe concurrency bounds for the chosen scan strategy.
def normalize_concurrency_for_mode(requested_concurrency: int, selected_mode: str) -> Tuple[int, Optional[str]]:

    initial_value = max(1, int(requested_concurrency))
    adjusted_value = initial_value
    reason_parts: List[str] = []

    if selected_mode in ("syn", "udp") and adjusted_value > SCAPY_CONCURRENCY_LIMIT:
        reason_parts.append(f"SYN/UDP worker cap {SCAPY_CONCURRENCY_LIMIT}")
        adjusted_value = SCAPY_CONCURRENCY_LIMIT

    fd_guarded_value, fd_limit = apply_fd_limit_guardrail(adjusted_value)
    if fd_guarded_value != adjusted_value:
        adjusted_value = fd_guarded_value
        if fd_limit is not None:
            reason_parts.append(f"file descriptor soft limit {fd_limit}")
        else:
            reason_parts.append("file descriptor guardrail")

    if adjusted_value != initial_value:
        if not reason_parts:
            reason = "internal guardrails"
        elif len(reason_parts) == 1:
            reason = reason_parts[0]
        else:
            reason = ", ".join(reason_parts[:-1]) + f", and {reason_parts[-1]}"
        message = (
            f"{selected_mode.upper()} concurrency adjusted from {initial_value} to {adjusted_value} "
            f"to respect {reason}."
        )
        return adjusted_value, message

    return adjusted_value, None

# [AUTO]Load the top ports list and return the requested number of entries.
def resolve_data_path(preferred_filename: str) -> str:

    if os.path.isabs(preferred_filename):
        return preferred_filename
    return os.path.join(DATA_DIRECTORY, preferred_filename)


def first_existing_path(candidate_paths: List[str]) -> Optional[str]:

    for candidate in candidate_paths:
        if os.path.isfile(candidate):
            return candidate
    return None


def load_top_ports_from_file(max_ports: int, explicit_path: Optional[str] = None) -> List[int]:

    if max_ports <= 0:
        return []

    resolved_path: Optional[str]
    if explicit_path:
        candidate_paths: List[str] = []
        if not os.path.isabs(explicit_path):
            candidate_paths.append(resolve_data_path(explicit_path))
        candidate_paths.append(explicit_path)
        resolved_path = first_existing_path(candidate_paths)
        if resolved_path is None:
            resolved_path = candidate_paths[0]
    else:
        resolved_path = resolve_data_path(TOP_PORTS_FILENAME)

    ports: List[int] = []
    seen: Set[int] = set()

    try:
        with open(resolved_path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                token = line.split()[0]
                try:
                    port = int(token)
                except ValueError:
                    continue

                if port < 1 or port > 65535:
                    continue
                if port in seen:
                    continue

                seen.add(port)
                ports.append(port)
                if len(ports) >= max_ports:
                    break
    except FileNotFoundError:
        print(f"Top ports file not found: {resolved_path}")
        return []
    except Exception as exc:
        print(f"Error reading top ports file {resolved_path}: {exc}")
        return []

    return ports


PORT_RANGE_TOKEN_PATTERN = re.compile(r"^\s*(\d*)\s*(?:-|:|\.\.)\s*(\d*)\s*$")


def _expand_port_token(token: str, default_start: int, default_end: int) -> List[int]:

    token = token.strip()
    if not token:
        return []

    range_match = PORT_RANGE_TOKEN_PATTERN.match(token)
    if range_match:
        left_text, right_text = range_match.groups()
        try:
            start_value = int(left_text) if left_text else default_start
        except ValueError:
            start_value = default_start
        try:
            end_value = int(right_text) if right_text else default_end
        except ValueError:
            end_value = default_end

        if start_value > end_value:
            start_value, end_value = end_value, start_value

        return list(range(start_value, end_value + 1))

    try:
        single_value = int(token)
    except ValueError:
        return []

    return [single_value]


# [AUTO]Translate CLI port expressions into a validated, sorted list.
def parse_port_specification(start_port: int, end_port: int, port_spec: Optional[str]) -> List[int]:

    sanitized_start = max(1, min(65535, int(start_port)))
    sanitized_end = max(1, min(65535, int(end_port)))
    if sanitized_start > sanitized_end:
        sanitized_start, sanitized_end = sanitized_end, sanitized_start

    ports: List[int] = []
    if port_spec is None:
        ports.extend(range(sanitized_start, sanitized_end + 1))
    else:
        for token in port_spec.split(","):
            expanded = _expand_port_token(token, sanitized_start, sanitized_end)
            if expanded:
                ports.extend(expanded)

    valid_sorted_unique: List[int] = []
    seen: Set[int] = set()
    for p in ports:
        if p < 1 or p > 65535:
            continue
        if p in seen:
            continue
        seen.add(p)
        valid_sorted_unique.append(p)

    valid_sorted_unique.sort()
    return valid_sorted_unique


def select_ports_for_arguments(parsed_arguments: argparse.Namespace) -> Tuple[List[int], Optional[int]]:

    top_ports_requested = getattr(parsed_arguments, "top_ports", None)
    if top_ports_requested is not None:
        ignored_parts = ["--start/--end range"]
        if getattr(parsed_arguments, "ports", None):
            ignored_parts.append("--ports specification")
        ignored_text = " and ".join(ignored_parts)
        print(f"[info] Using top ports list; ignoring {ignored_text}.")
        ports_selected = load_top_ports_from_file(
            top_ports_requested,
            getattr(parsed_arguments, "top_ports_file", None),
        )
        return ports_selected, top_ports_requested

    ports_selected = parse_port_specification(
        parsed_arguments.start,
        parsed_arguments.end,
        getattr(parsed_arguments, "ports", None),
    )
    return ports_selected, None


async def resolve_dns_label_to_ip(dns_label: str) -> str:
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


async def try_read_banner(stream_reader: asyncio.StreamReader,
                          idle_timeout_seconds: float,
                          max_bytes: int = 4096) -> str:
    # Read as much banner data as possible until the connection goes idle.

    if idle_timeout_seconds <= 0:
        return ""

    collected = bytearray()
    deadline = time.monotonic() + idle_timeout_seconds

    while len(collected) < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                stream_reader.read(max_bytes - len(collected)),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            break
        except Exception:
            break
        if not chunk:
            break
        collected.extend(chunk)
        deadline = time.monotonic() + idle_timeout_seconds

    if not collected:
        return ""

    return collected.decode("utf-8", errors="replace").strip()

async def scan_tcp_connect_once(target_ip: str,
                                target_port: int,
                                timeout_seconds: float,
                                banner_enabled: bool) -> Tuple[str, int, str, str, str, int]:
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
        banner_timeout = max(0.5, min(5.0, timeout_seconds * 2))
        banner_text = await try_read_banner(reader, banner_timeout, max_bytes=4096)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    duration_ms = int((time.perf_counter() - start) * 1000)
    return target_ip, target_port, "tcp", "open", banner_text, duration_ms

# [AUTO]Send one SYN probe and classify the TCP response semantics.
def scapy_send_single_syn(dst_ip: str,
                          dst_port: int,
                          timeout_seconds: float) -> Tuple[str, str]:

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
                            backoff_seconds: float,
                            executor: Optional[ThreadPoolExecutor] = None) -> Tuple[str, int, str, str, str, int]:
    loop = asyncio.get_running_loop()
    attempt_index = 1
    last_error_note = ""
    scan_start = time.perf_counter()

    while attempt_index <= max(1, retries):
        try:
            status, note = await loop.run_in_executor(
                executor,
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

# [AUTO]Craft protocol-aware UDP payloads when probes require content.
def build_udp_probe_payload(dst_port: int, probe_kind: str):

    if probe_kind == "dns" and dst_port == 53:
        return scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com"))
    if probe_kind == "ntp" and dst_port == 123:
        import struct

        ntp_epoch = 2208988800
        now = time.time() + ntp_epoch
        sec = int(now)
        frac = int((now - sec) * (1 << 32)) & 0xFFFFFFFF
        first = bytes([0x23])  # [AUTO]LI=0, VN=4, Mode=3 (client request)
        return Raw(first + b"\x00" * 39 + struct.pack("!II", sec, frac))
    return None

def scapy_udp_probe_sniff_once(dst_ip: str,
                               dst_port: int,
                               timeout_seconds: float,
                               probe_kind: str) -> Tuple[str, str]:
    # [AUTO]Send a UDP probe and sniff for replies or ICMP errors.

    payload = build_udp_probe_payload(dst_port, probe_kind)

    try:
        iface_name = scapy.conf.route.route(dst_ip)[0]
    except Exception:
        iface_name = scapy.conf.iface

    src_port = int(scapy.RandShort())
    ip_layer = scapy.IP(dst=dst_ip, ttl=64)
    udp_layer = scapy.UDP(sport=src_port, dport=dst_port)
    probe_pkt = ip_layer / udp_layer / (payload or b"")

    bpf_filter = f"udp and src host {dst_ip} and src port {dst_port} and dst port {src_port}"

    sniffer = scapy.AsyncSniffer(filter=bpf_filter, iface=iface_name, store=True, promisc=True)
    sniffer.start()
    time.sleep(0.02)                      # [AUTO]Allow capture backend to prime itself
    scapy.send(probe_pkt, verbose=0)      # [AUTO]Dispatch the crafted probe packet
    sniffer.join(timeout_seconds)
    captured_pkts = sniffer.stop()

    if not captured_pkts:
        return "open|filtered", "no-response"

    resp = captured_pkts[0]

    if resp.haslayer(scapy.ICMP):
        icmp = resp[scapy.ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed", "icmp-port-unreachable"
        return "filtered", f"icmp type={icmp.type} code={icmp.code}"

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
                        backoff_seconds: float,
                        executor: Optional[ThreadPoolExecutor] = None) -> Tuple[str, int, str, str, str, int]:
    loop = asyncio.get_running_loop()
    attempt_index = 1
    last_error_note = ""
    scan_start = time.perf_counter()

    while attempt_index <= max(1, retries):
        try:
            status, note = await loop.run_in_executor(
                executor,
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


# [AUTO]Minimal asyncio-based rate limiter to cap per-host throughput.
class FixedRateLimiter:

    def __init__(self, rate_ops_per_sec: int) -> None:
        # [AUTO]Prepare limiter intervals from the requested operations per second.

        self.rate = max(0, rate_ops_per_sec)
        self._interval = 0.0 if self.rate <= 0 else 1.0 / float(self.rate)
        self._last_time = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        # [AUTO]Sleep just enough to respect the configured rate.

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


async def scan_all_selected_ports_for_host(target_ip: str,
                                           selected_ports: List[int],
                                           selected_mode: str,
                                           timeout_seconds: float,
                                           max_concurrency: int,
                                           show_closed_in_output: bool,
                                           show_only_open_in_output: bool,
                                           banner_enabled: bool,
                                           per_host_ops_per_sec: int,
                                           udp_probe_kind: str,
                                           retries: int,
                                           backoff_seconds: float) -> Tuple[List[ScanRecord], List[ScanRecord]]:
    """Scan *target_ip* across *selected_ports* and return (open_only, all_results)."""

    effective_concurrency = max(1, max_concurrency)
    scapy_executor: Optional[ThreadPoolExecutor] = None
    if selected_mode in ("syn", "udp"):
        if effective_concurrency > SCAPY_CONCURRENCY_LIMIT:
            effective_concurrency = SCAPY_CONCURRENCY_LIMIT
        scapy_executor = ThreadPoolExecutor(max_workers=effective_concurrency)

    semaphore = asyncio.Semaphore(effective_concurrency)
    limiter = FixedRateLimiter(per_host_ops_per_sec)

    confirmed_open_results: List[ScanRecord] = []
    all_results_for_host: List[ScanRecord] = []

    async def run_one_port_probe(port_number: int) -> Tuple[str, int, str, str, str, int]:
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
                    backoff_seconds,
                    scapy_executor
                )
            if selected_mode == "udp":
                return await scan_udp_once(
                    target_ip,
                    port_number,
                    timeout_seconds,
                    udp_probe_kind,
                    retries,
                    backoff_seconds,
                    scapy_executor
                )
            return target_ip, port_number, "tcp", "error", "unknown-mode", 0

    tasks: List[asyncio.Task] = [asyncio.create_task(run_one_port_probe(p)) for p in selected_ports]

    try:
        for finished in asyncio.as_completed(tasks):
            host, port, proto, status, note, duration_ms = await finished
            timestamp = utc_now_str()

            should_print = show_closed_in_output or (status != "closed")
            if show_only_open_in_output:
                should_print = status == "open"
            if should_print:
                note_suffix = f" {note}" if note else ""
                print(f"# {timestamp}\t| {host}:{port}/{proto}\t= {status}{note_suffix} [{duration_ms}ms]")

            banner_text: str = ""
            if (
                selected_mode == "connect"
                and banner_enabled
                and status == "open"
                and isinstance(note, str)
                and note
            ):
                banner_text = note

            record = ScanRecord(
                host=host,
                port=port,
                proto=proto,
                status=status,
                note=note,
                banner=banner_text,
                time=timestamp,
                duration_ms=duration_ms,
            )
            all_results_for_host.append(record)

            if record.is_open():
                confirmed_open_results.append(record)
    finally:
        if scapy_executor is not None:
            scapy_executor.shutdown(wait=True)

    return confirmed_open_results, all_results_for_host


async def run_port_scan_for_host(target_ip: str,
                                 configuration: PortScanConfiguration) -> Tuple[List[ScanRecord], List[ScanRecord]]:

    try:
        open_results, all_results = await scan_all_selected_ports_for_host(
            target_ip=target_ip,
            selected_ports=configuration.ports,
            selected_mode=configuration.mode,
            timeout_seconds=configuration.timeout,
            max_concurrency=configuration.concurrency,
            show_closed_in_output=configuration.show_closed,
            show_only_open_in_output=configuration.show_only_open,
            banner_enabled=configuration.banner,
            per_host_ops_per_sec=configuration.rate,
            udp_probe_kind=configuration.udp_probe,
            retries=configuration.retries,
            backoff_seconds=configuration.backoff,
        )
    except Exception as exc:
        print(f"[find] Error scanning {target_ip}: {exc}")
        return [], []

    emit_summary_for_suppressed_results(
        host_label=target_ip,
        ip_address=target_ip,
        show_only_open_flag=configuration.show_only_open,
        open_results=open_results,
        all_results=all_results,
    )

    return open_results, all_results

# Provide a hint when --show-only-open hides every result for a host.
def emit_summary_for_suppressed_results(host_label: str,
                                        ip_address: str,
                                        show_only_open_flag: bool,
                                        open_results: List[ScanRecord],
                                        all_results: List[ScanRecord]) -> None:
    """Print a hint when open results are hidden yet other responses were observed."""
    if not show_only_open_flag:
        return
    if open_results or not all_results:
        return

    status_note_pairs = [(record.status, record.note) for record in all_results]
    if not status_note_pairs:
        return

    most_common_pair, _ = Counter(status_note_pairs).most_common(1)[0]
    status_text, note_text = most_common_pair
    if note_text:
        description = f"{status_text} ({note_text})"
    else:
        description = status_text or "unknown"

    if host_label == ip_address:
        identifier = ip_address
    else:
        identifier = f"{host_label} [{ip_address}]"

    print(
        f"[info] {identifier}: no open ports reported. "
        f"Most frequent response: {description}. "
        f"Re-run without --show-only-open to review all results."
    )


def ports_requested_explicitly(parsed_arguments: argparse.Namespace) -> bool:

    explicit_flags = (
        getattr(parsed_arguments, "ports_explicit", False),
        getattr(parsed_arguments, "top_ports_explicit", False),
        getattr(parsed_arguments, "start_explicit", False),
        getattr(parsed_arguments, "end_explicit", False),
    )
    return any(bool(flag) for flag in explicit_flags)


def prepare_port_scan_configuration(parsed_arguments: argparse.Namespace) -> Optional[PortScanConfiguration]:

    ports_selected, top_ports_requested = select_ports_for_arguments(parsed_arguments)
    if not ports_selected:
        print("No ports selected; port scanning disabled for discovered hosts.")
        return None

    if getattr(parsed_arguments, "shuffle", False):
        random.shuffle(ports_selected)

    scan_mode = "connect"
    if getattr(parsed_arguments, "syn", False):
        scan_mode = "syn"
    elif getattr(parsed_arguments, "udp", False):
        scan_mode = "udp"

    normalized_concurrency, concurrency_notice = normalize_concurrency_for_mode(
        parsed_arguments.concurrency,
        scan_mode,
    )
    parsed_arguments.concurrency = normalized_concurrency
    if concurrency_notice:
        print(concurrency_notice)

    ensure_prerequisites_for_scapy(scan_mode)

    if top_ports_requested is not None:
        print(f"[find] Scanning discovered hosts using the top {len(ports_selected)} ports.")
    else:
        print(f"[find] Scanning discovered hosts across {len(ports_selected)} configured port(s).")

    return PortScanConfiguration(
        ports=ports_selected,
        mode=scan_mode,
        concurrency=normalized_concurrency,
        timeout=float(parsed_arguments.timeout),
        show_closed=bool(
            getattr(parsed_arguments, "show_closed_terminal", False)
            or getattr(parsed_arguments, "show_closed_terminal_only", False)
        ),
        show_only_open=bool(getattr(parsed_arguments, "show_only_open", False)),
        banner=bool(getattr(parsed_arguments, "banner", False)),
        rate=int(getattr(parsed_arguments, "rate", 0)),
        udp_probe=str(getattr(parsed_arguments, "udp_probe", "empty")),
        retries=int(getattr(parsed_arguments, "retries", 1)),
        backoff=float(getattr(parsed_arguments, "retry_backoff", 0.0)),
    )


async def perform_find_machines_discovery(interfaces: List[InterfaceNetwork],
                                          ping_command: List[str],
                                          port_configuration: Optional[PortScanConfiguration],
                                          ping_timeout: float) -> Tuple[List[Tuple[InterfaceNetwork, List[str]]], List[ScanRecord], List[ScanRecord]]:

    aggregated: List[Tuple[InterfaceNetwork, List[str]]] = []
    aggregated_open_results: List[ScanRecord] = []
    aggregated_all_results: List[ScanRecord] = []
    seen_hosts: Set[str] = set()

    for interface in interfaces:
        network = interface.network
        if network.prefixlen >= 31:
            potential_hosts = network.num_addresses
        else:
            potential_hosts = max(0, network.num_addresses - 2)

        if interface.contains_local_ip():
            binding = f"{interface.local_ip}/{network.prefixlen}"
        else:
            binding = f"{interface.local_ip}"
        if interface.source == "route":
            origin = " (routed)"
        elif interface.source == "file":
            origin = " (file)"
        else:
            origin = ""
        print(
            f"[find] Interface {interface.name}{origin} -> {binding} "
            f"network {network.network_address}/{network.prefixlen} ({potential_hosts} host candidates)"
        )

        if potential_hosts <= 0:
            print(f"[find] {interface.name}: no addressable peers in this network.\n")
            aggregated.append((interface, []))
            continue

        hosts_for_interface: List[str] = []
        scan_tasks: List[asyncio.Task] = []

        async def handle_host(ip_text: str, ping_observation: PingObservation) -> None:
            if ip_text in seen_hosts:
                return
            seen_hosts.add(ip_text)
            hosts_for_interface.append(ip_text)
            ping_summary = format_ping_observation(ping_observation)
            print(f"[find] responsive host: {ip_text}{ping_summary}")
            if port_configuration is not None:

                async def scan_and_collect(target_ip: str) -> None:
                    open_results, all_results = await run_port_scan_for_host(
                        target_ip, port_configuration
                    )
                    aggregated_open_results.extend(open_results)
                    aggregated_all_results.extend(all_results)

                    open_ports = sorted({record.port for record in open_results})
                    if open_ports:
                        ports_text = ", ".join(str(port) for port in open_ports)
                        print(
                            f"[find] responsive host: {target_ip} (open ports: {ports_text})"
                        )
                    else:
                        print(
                            f"[find] responsive host: {target_ip} (no open ports reported)"
                        )

                scan_tasks.append(asyncio.create_task(scan_and_collect(ip_text)))

        await discover_hosts_on_interface(
            interface,
            ping_command,
            handle_host,
            ping_timeout=ping_timeout,
        )

        if scan_tasks:
            await asyncio.gather(*scan_tasks, return_exceptions=False)

        hosts_for_interface.sort(key=lambda value: ipaddress.IPv4Address(value))
        aggregated.append((interface, hosts_for_interface))

        if hosts_for_interface:
            print(f"[find] {interface.name}: {len(hosts_for_interface)} host(s) responsive.\n")
        else:
            print(f"[find] {interface.name}: no responsive hosts detected.\n")

    return aggregated, aggregated_open_results, aggregated_all_results


def persist_discovered_targets(results: List[Tuple[InterfaceNetwork, List[str]]]) -> Optional[str]:

    target_path = os.path.join(SCRIPT_DIRECTORY, "targets_found.txt")
    try:
        with open(target_path, "w", encoding="utf-8") as handle:
            for interface, hosts in results:
                network = interface.network
                if interface.contains_local_ip():
                    binding = f"{interface.local_ip}/{network.prefixlen}"
                else:
                    binding = str(interface.local_ip)
                if interface.source == "route":
                    binding = f"{binding} (routed)"
                handle.write(
                    f"# interface {interface.name} address {binding} "
                    f"network {network.network_address}/{network.prefixlen}\n"
                )
                for host in hosts:
                    handle.write(f"{host}\n")
                handle.write("\n")
    except Exception as exc:
        print(f"[find] Unable to write discovered targets to {target_path}: {exc}")
        return None

    return target_path


# [AUTO]Discover responsive hosts across internal interfaces and optionally scan them.
def run_find_machines_mode(parsed_arguments: argparse.Namespace) -> None:

    include_external_cli = getattr(parsed_arguments, "find_include_external", None)

    additional_targets_path = getattr(
        parsed_arguments,
        "find_machines_from_targets_file",
        None,
    )
    additional_targets_explicit = bool(
        getattr(parsed_arguments, "find_machines_from_targets_file_explicit", False)
    )
    ping_targets_flag = bool(
        getattr(parsed_arguments, "find_machines_from_targets_and_ping", False)
    )

    additional_interfaces: List[InterfaceNetwork] = []
    ping_file_interfaces: List[InterfaceNetwork] = []
    include_external_request: Optional[bool] = None
    include_external_request_source: Optional[str] = None

    def register_include_external(request: Optional[bool], source_label: str) -> None:
        nonlocal include_external_request, include_external_request_source
        if request is None:
            return
        if include_external_request is None:
            include_external_request = request
            include_external_request_source = source_label
            return
        if include_external_request != request:
            desired_state = "enabled" if request else "disabled"
            original_state = "enabled" if include_external_request else "disabled"
            print(
                f"[find] Ignoring include_external request from {source_label} ({desired_state}) "
                f"because {include_external_request_source} already requested it be {original_state}."
            )

    targets_file_to_use = additional_targets_path
    quiet_missing_targets_file = False

    if additional_targets_explicit:
        if not targets_file_to_use:
            targets_file_to_use = DEFAULT_FIND_TARGETS_FILENAME
        if targets_file_to_use == DEFAULT_FIND_TARGETS_FILENAME:
            quiet_missing_targets_file = True
    else:
        targets_file_to_use = DEFAULT_FIND_TARGETS_FILENAME
        quiet_missing_targets_file = True

    include_external_from_targets: Optional[bool] = None
    if targets_file_to_use:
        additional_interfaces, include_external_from_targets = load_additional_find_networks(
            targets_file_to_use,
            quiet_missing=quiet_missing_targets_file,
            source_label="file",
        )
        register_include_external(
            include_external_from_targets,
            f"targets file {targets_file_to_use}",
        )

    ping_targets_to_use: Optional[str] = None
    quiet_missing_ping_targets = False
    if ping_targets_flag:
        ping_targets_to_use = targets_file_to_use
        quiet_missing_ping_targets = quiet_missing_targets_file

    include_external_from_ping: Optional[bool] = None
    if ping_targets_to_use:
        ping_file_interfaces, include_external_from_ping = load_additional_find_networks(
            ping_targets_to_use,
            quiet_missing=quiet_missing_ping_targets,
            source_label="file-ping",
        )
        register_include_external(
            include_external_from_ping,
            f"ping targets file {ping_targets_to_use}",
        )

    include_external_setting: Optional[bool]
    if include_external_cli is not None:
        include_external_setting = include_external_cli
    else:
        include_external_setting = include_external_request

    include_external = True if include_external_setting is None else bool(include_external_setting)

    if include_external_cli is None and include_external_request is not None:
        state = "enabled" if include_external else "disabled"
        print(
            f"[find] {include_external_request_source} requests include_external be {state}."
        )

    interfaces = gather_local_ipv4_interfaces(include_external=include_external)

    existing_networks: Set[str] = {
        interface.network.with_prefixlen for interface in interfaces
    }

    def merge_interfaces(new_interfaces: List[InterfaceNetwork]) -> None:
        nonlocal existing_networks
        if not new_interfaces:
            return
        origin_label = new_interfaces[0].source
        origin_description = {
            "file": "additional targets",
            "file-ping": "ping targets",
        }.get(origin_label, origin_label or "additional targets")

        filtered_additional: List[InterfaceNetwork] = []
        skipped_external = 0
        for candidate in new_interfaces:
            representative = str(candidate.network.network_address)
            if not include_external and is_external_ip(representative):
                skipped_external += 1
                continue
            filtered_additional.append(candidate)
        if skipped_external:
            print(
                f"[find] Skipping {skipped_external} non-internal network(s) from {origin_description} "
                "because external discovery is disabled."
            )

        if not filtered_additional:
            return

        duplicates = 0
        for candidate in filtered_additional:
            key = candidate.network.with_prefixlen
            if key in existing_networks:
                duplicates += 1
                continue
            interfaces.append(candidate)
            existing_networks.add(key)
        if duplicates:
            print(
                f"[find] Skipped {duplicates} duplicate network(s) already covered by interface discovery "
                f"from {origin_description}."
            )

    merge_interfaces(additional_interfaces)
    merge_interfaces(ping_file_interfaces)

    ping_timeout_value = getattr(parsed_arguments, "find_machines_ping_timeout", 1.5)
    try:
        ping_timeout = float(ping_timeout_value)
    except (TypeError, ValueError):
        print(
            f"[find] Invalid ping timeout {ping_timeout_value!r}; defaulting to 1.5 seconds."
        )
        ping_timeout = 1.5
    if ping_timeout <= 0:
        print("[find] Ping timeout must be positive; defaulting to 1.5 seconds.")
        ping_timeout = 1.5

    if not interfaces:
        print("[find] No internal IPv4 interfaces or additional networks detected.")
        return

    ping_command = determine_ping_command()
    if ping_command is None:
        print("[find] Unable to locate the system ping command. Install 'ping' to use --find-machines.")
        sys.exit(1)

    if getattr(parsed_arguments, "pcap", None):
        print("[find] Warning: --pcap is not supported alongside --find-machines and will be ignored.")

    auto_show_only_open = False
    if (
        not getattr(parsed_arguments, "show_only_open", False)
        and not getattr(parsed_arguments, "show_closed_terminal", False)
        and not getattr(parsed_arguments, "show_closed_terminal_only", False)
    ):
        parsed_arguments.show_only_open = True
        auto_show_only_open = True

    port_configuration: Optional[PortScanConfiguration] = None
    if ports_requested_explicitly(parsed_arguments):
        fast_mode_adjustments = apply_fast_mode_overrides(parsed_arguments)
        if fast_mode_adjustments is not None:
            print("[fast] Fast mode adjustments applied for discovered host port scans.")
            guardrail = fast_mode_adjustments.get("concurrency_guardrail_notice")
            if guardrail:
                print(f"[fast] {guardrail}")
            auto_syn_reason = fast_mode_adjustments.get("auto_syn_reason")
            if auto_syn_reason == "scapy-missing":
                print("[fast] Scapy not available, unable to auto-select SYN mode.")
            elif auto_syn_reason == "root-required":
                print("[fast] Run with elevated privileges to allow SYN auto-selection.")
            elif auto_syn_reason == "privilege-unknown":
                print("[fast] Could not verify privileges; SYN auto-selection disabled.")

        port_configuration = prepare_port_scan_configuration(parsed_arguments)
    else:
        print("[find] Port scanning disabled (no explicit port options supplied).")
        if getattr(parsed_arguments, "csv", None):
            print("[find] Warning: CSV output requires configured ports; no file will be generated.")
        if getattr(parsed_arguments, "json", None):
            print("[find] Warning: JSON output requires configured ports; no file will be generated.")

    event_loop = asyncio.new_event_loop()
    results: List[Tuple[InterfaceNetwork, List[str]]] = []
    aggregated_open_results: List[ScanRecord] = []
    aggregated_all_results: List[ScanRecord] = []
    try:
        asyncio.set_event_loop(event_loop)
        results, aggregated_open_results, aggregated_all_results = event_loop.run_until_complete(
            perform_find_machines_discovery(
                interfaces,
                ping_command,
                port_configuration,
                ping_timeout,
            )
        )
    finally:
        asyncio.set_event_loop(None)
        event_loop.close()

    total_hosts = sum(len(hosts) for _, hosts in results)
    if total_hosts == 0:
        print("[find] No responsive hosts discovered across internal interfaces.")
    else:
        print(f"[find] Discovery complete: {total_hosts} responsive host(s) located.")

    persisted_path = persist_discovered_targets(results)
    if persisted_path:
        print(f"[find] Saved discovered targets to {persisted_path}.")

    if port_configuration is None:
        return

    timestamp_for_auto_files = ts_utc_compact()
    show_only_open_in_terminal = bool(getattr(parsed_arguments, "show_only_open", False))

    persist_all_results = should_persist_all_results(
        bool(parsed_arguments.show_closed_terminal),
        bool(getattr(parsed_arguments, "show_closed_terminal_only", False)),
        parsed_arguments.csv,
        parsed_arguments.json,
    )

    rows_for_persistence, artifacts_show_only_open = determine_artifact_rows(
        show_only_open_in_terminal,
        persist_all_results,
        aggregated_open_results,
        aggregated_all_results,
    )

    csv_destination: Optional[str] = parsed_arguments.csv
    if csv_destination == "AUTO":
        csv_destination = default_log_artifact_path(
            f"find_csv_{timestamp_for_auto_files}.csv"
        )
    if csv_destination:
        write_results_to_csv(
            csv_destination,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )

    json_destination: Optional[str] = parsed_arguments.json
    if json_destination == "AUTO":
        json_destination = default_log_artifact_path(
            f"find_json_{timestamp_for_auto_files}.json"
        )
    if json_destination:
        write_results_to_json(
            json_destination,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )

    if auto_show_only_open and not aggregated_open_results and aggregated_all_results:
        print("[find] Tip: --show-only-open was enabled automatically; rerun with --show-closed-terminal to review all results.")


# [AUTO]Abort early when Scapy-driven modes cannot operate.
def ensure_prerequisites_for_scapy(selected_mode: str) -> None:

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

# [AUTO]Spin up an AsyncSniffer for the optional BPF filter.
def start_pcap_sniffer_for_host(filter_expression: Optional[str] = None) -> Any:

    if not SCAPY_AVAILABLE:
        return None
    try:
        sniffer = scapy.AsyncSniffer(filter=filter_expression)
        sniffer.start()
        return sniffer
    except Exception:
        return None

def ensure_parent_directory_exists(file_path: str) -> None:
    """Create the parent directory for *file_path* when it is missing."""

    directory = os.path.dirname(os.path.abspath(file_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)


def stop_sniffer_and_write_pcap(sniffer: Any, pcap_filename: str) -> None:
    # [AUTO]Terminate a running sniffer and persist packets to disk.

    if sniffer is None:
        return
    try:
        ensure_parent_directory_exists(pcap_filename)
        captured_packets = sniffer.stop()
        scapy.wrpcap(pcap_filename, captured_packets if captured_packets else [])
    except Exception as exc:
        print(f"Failed to write pcap {pcap_filename}: {type(exc).__name__}")


def filter_open_records(result_rows: List[ScanRecord]) -> List[ScanRecord]:
    """Return only entries that indicate an open service."""

    return [record for record in result_rows if record.is_open()]


def should_persist_all_results(show_closed_terminal: bool,
                               show_closed_terminal_only: bool,
                               csv_path: Optional[str],
                               json_path: Optional[str]) -> bool:
    # Decide if artifact writers should include closed ports in their output.

    if show_closed_terminal:
        return True
    if show_closed_terminal_only:
        return False
    return bool(csv_path) or bool(json_path)


def determine_artifact_rows(show_only_open: bool,
                            persist_all: bool,
                            open_rows: List[ScanRecord],
                            all_rows: List[ScanRecord]) -> Tuple[List[ScanRecord], bool]:
    # Choose which scan records to persist and whether to filter for open entries.

    if show_only_open:
        return open_rows, True
    if persist_all:
        return all_rows, False
    return open_rows, False


def write_results_to_csv(
    csv_path: str,
    result_rows: List[ScanRecord],
    *,
    only_open: bool = False,
) -> None:
    """Emit scanner results in a tabular CSV format."""

    try:
        ensure_parent_directory_exists(csv_path)
        with open(csv_path, mode="w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "port", "proto", "status", "note", "banner", "time_utc", "duration_ms"])
            rows_to_write = filter_open_records(result_rows) if only_open else result_rows
            for rec in rows_to_write:
                writer.writerow([
                    rec.host,
                    rec.port,
                    rec.proto,
                    rec.status,
                    rec.note,
                    rec.banner,
                    rec.time,
                    rec.duration_ms,
                ])
        print(f"csv -> {csv_path}")
    except Exception as exc:
        print(f"Failed to write CSV: {type(exc).__name__}")

def write_results_to_json(
    json_path: str,
    result_rows: List[ScanRecord],
    *,
    only_open: bool = False,
) -> None:
    """Persist scanner results as structured JSON."""

    try:
        ensure_parent_directory_exists(json_path)
        with open(json_path, mode="w") as fh:
            rows_to_persist = filter_open_records(result_rows) if only_open else result_rows
            json.dump([record.to_dict() for record in rows_to_persist], fh, indent=2)
        print(f"json -> {json_path}")
    except Exception as exc:
        print(f"Failed to write JSON: {type(exc).__name__}")


def run_web_directory_listing_tool(base_url: Optional[str],
                                   wordlist_path: Optional[str],
                                   request_timeout: float = 10.0) -> bool:
    # Run a simple web directory listing enumeration based on a wordlist.

    if not base_url:
        print("Error: --url/-u is required when using --web-dir.")
        return False
    if not wordlist_path:
        print("Error: --wordlist/-w is required when using --web-dir.")
        return False

    candidate_paths: List[str] = []
    if wordlist_path:
        if not os.path.isabs(wordlist_path):
            candidate_paths.append(resolve_data_path(wordlist_path))
        candidate_paths.append(wordlist_path)

    resolved_wordlist = first_existing_path(candidate_paths)
    if resolved_wordlist is None:
        print(f"Error: wordlist not found: {wordlist_path}")
        return False

    normalized_base = base_url.strip()
    if not normalized_base:
        print("Error: the provided URL is empty.")
        return False

    parsed = urllib.parse.urlparse(normalized_base)
    if not parsed.scheme:
        normalized_base = f"http://{normalized_base}"
        parsed = urllib.parse.urlparse(normalized_base)
    if not parsed.netloc:
        print(f"Error: invalid URL '{base_url}'.")
        return False

    base_for_join = normalized_base.rstrip("/") + "/"

    try:
        with open(resolved_wordlist, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                candidate = raw_line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                candidate_path = candidate.lstrip("/")
                if not candidate_path:
                    continue

                full_url = urllib.parse.urljoin(base_for_join, candidate_path)
                display_path = "/" + candidate_path
                request = urllib.request.Request(
                    full_url,
                    method="GET",
                    headers={"User-Agent": "smrib/dirlist"},
                )

                status_code: Optional[int] = None
                try:
                    with urllib.request.urlopen(request, timeout=request_timeout) as response:
                        status_code = getattr(response, "status", None)
                        if status_code is None:
                            status_code = response.getcode()
                except urllib.error.HTTPError as http_err:
                    status_code = http_err.code
                except urllib.error.URLError as url_err:
                    print(f"[error] {display_path} -> {url_err.reason}")
                    continue
                except Exception as exc:
                    print(f"[error] {display_path} -> {exc}")
                    continue

                if status_code is None:
                    print(f"[unknown] {display_path}")
                else:
                    print(f"[{status_code}] {display_path}")
    except Exception as exc:
        print(f"Error processing wordlist: {exc}")
        return False

    return True

# [AUTO]Construct the command-line interface for SMRIB.
def build_cli_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Readable async port scanner (asyncio + optional Scapy). "
            "Running without CLI flags uses the default target and timings listed per option."
        )
    )

    parser.add_argument(
        "--targets",
        required=False,
        default=str(DEFAULTS["HOST"]),
        help=(
            "Host/IP/CIDR or a file with one target per line. "
            "Default: %(default)s (override via PORTSCAN_HOST)."
        )
    )

    parser.add_argument(
        "--start",
        type=int,
        default=int(DEFAULTS["START"]),
        action=StoreValueAndMarkExplicit,
        help="Start port (inclusive). Default: %(default)s (PORTSCAN_START)."
    )

    parser.add_argument(
        "--end",
        type=int,
        default=int(DEFAULTS["END"]),
        action=StoreValueAndMarkExplicit,
        help="End port (inclusive). Default: %(default)s (PORTSCAN_END)."
    )

    parser.add_argument(
        "--ports",
        action=StoreValueAndMarkExplicit,
        help="Explicit list and ranges, e.g. 22,80,8000-8100 (overrides start/end)."
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        metavar="COUNT",
        action=StoreValueAndMarkExplicit,
        help="Use first COUNT entries from top-ports.txt (overrides start/end/--ports)."
    )

    parser.add_argument(
        "--top-ports-file",
        dest="top_ports_file",
        help="Optional path to a custom top ports file (default: bundled top-ports.txt)."
    )

    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=int(DEFAULTS["CONCURRENCY"]),
        help="Per-host concurrency. Default: %(default)s (PORTSCAN_CONCURRENCY)."
    )

    parser.set_defaults(
        timeout_explicit=PORTSCAN_TIMEOUT_ENV_SET,
        start_explicit=False,
        end_explicit=False,
        ports_explicit=False,
        top_ports_explicit=False,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(DEFAULTS["TIMEOUT"]),
        action=StoreValueAndMarkExplicit,
        help="Socket and probe timeout in seconds. Default: %(default)s (PORTSCAN_TIMEOUT)."
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
        "--show-closed-terminal",
        action="store_true",
        help=(
            "Also print CLOSED results in the terminal. Output artifacts already include CLOSED entries when generated."
        ),
    )

    parser.add_argument(
        "--show-closed-terminal-only",
        action="store_true",
        help="Print CLOSED results in the terminal without persisting them."
    )

    parser.add_argument(
        "--show-only-open",
        action="store_true",
        help="Only print OPEN results in the terminal output."
    )

    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomize port order before scanning."
    )

    parser.add_argument(
        "--banner",
        "--show-banner",
        action="store_true",
        dest="banner",
        help="Attempt to grab the most banner data possible on open TCP connect scans."
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=int(DEFAULTS["RATE"]),
        help="Ops per second per host (0 = unlimited). Default: %(default)s (PORTSCAN_RATE)."
    )

    parser.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Enable the fastest scanning profile. Forces high concurrency, low timeouts, "
            "prefers SYN mode when possible, disables banners/retries, and automatically "
            "includes private/internal targets."
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

    parser.add_argument(
        "--batch",
        metavar="SPECFILE",
        help="Batch mode. SPECFILE has one full CLI spec per non-comment line. Prefix before first '-' is ignored."
    )
    parser.add_argument(
        "--batch-battery",
        metavar="TARGETS_OR_COUNT",
        dest="batch_battery",
        help=(
            "Run a compact test battery. Provide a targets file or an integer COUNT to "
            "use the --targets argument with the top ports list."
        )
    )

    parser.add_argument(
        "--web-dir",
        action="store_true",
        help="Run the web directory listing tool using -u/--url and -w/--wordlist, then exit."
    )

    parser.add_argument(
        "-u", "--url",
        dest="url",
        help="Base URL for --web-dir mode."
    )

    parser.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        help="Wordlist file for --web-dir mode."
    )

    parser.add_argument(
        "--find-machines",
        action="store_true",
        help="Discover responsive hosts across internal networks and optionally scan configured ports."
    )
    parser.add_argument(
        "--find-include-external",
        metavar="{yes,no}",
        dest="find_include_external",
        type=argparse_boolean_choice,
        default=None,
        help=(
            "Allow --find-machines to include non-private IPv4 networks discovered from interfaces or routes. "
            "Accepts yes/no or true/false."
        )
    )
    parser.add_argument(
        "--find-machines-from-targets-file",
        metavar="FILE",
        dest="find_machines_from_targets_file",
        nargs="?",
        action=StoreValueAndMarkExplicit,
        const=DEFAULT_FIND_TARGETS_FILENAME,
        default=None,
        help=(
            "Optional file containing additional CIDR ranges to explore during --find-machines. "
            f"Defaults to {DEFAULT_FIND_TARGETS_FILENAME!r} when omitted. Lines starting with # are ignored."
        ),
    )
    parser.add_argument(
        "--find-machines-from-targets-and-ping",
        action="store_true",
        help=(
            "When supplied, hosts sourced from --find-machines-from-targets-file will also be validated "
            "with a ping probe during discovery."
        ),
    )
    parser.add_argument(
        "--find-machines-ping-timeout",
        metavar="SECONDS",
        dest="find_machines_ping_timeout",
        type=float,
        default=1.5,
        help="Timeout in seconds for each ping probe performed during --find-machines discovery. Defaults to 1.5 seconds.",
    )

    return parser

# [AUTO]Execute the complete scanning workflow for supplied arguments.
def run_full_scan(parsed_arguments: argparse.Namespace) -> Tuple[List[ScanRecord], List[ScanRecord]]:

    fast_mode_adjustments = apply_fast_mode_overrides(parsed_arguments)
    show_closed_in_terminal = bool(
        parsed_arguments.show_closed_terminal
        or getattr(parsed_arguments, "show_closed_terminal_only", False)
    )
    show_only_open_in_terminal = bool(getattr(parsed_arguments, "show_only_open", False))

    ports_selected_for_scan, top_ports_requested = select_ports_for_arguments(parsed_arguments)
    if not ports_selected_for_scan:
        print("No ports selected.")
        sys.exit(1)
    if parsed_arguments.shuffle:
        random.shuffle(ports_selected_for_scan)

    scan_mode_selected = "connect"
    if parsed_arguments.syn:
        scan_mode_selected = "syn"
    if parsed_arguments.udp:
        scan_mode_selected = "udp"
    if fast_mode_adjustments is not None:
        fast_mode_adjustments["mode"] = scan_mode_selected

    normalized_concurrency, concurrency_notice = normalize_concurrency_for_mode(
        parsed_arguments.concurrency,
        scan_mode_selected,
    )
    parsed_arguments.concurrency = normalized_concurrency
    if fast_mode_adjustments is not None:
        fast_mode_adjustments["concurrency"] = parsed_arguments.concurrency

    if getattr(parsed_arguments, "pcap", None) and not SCAPY_AVAILABLE:
        print("Scapy required for --pcap. Install with: pip install scapy")
        sys.exit(2)

    ensure_prerequisites_for_scapy(scan_mode_selected)

    target_labels_provided_by_user = expand_targets_to_list(parsed_arguments.targets)
    if not target_labels_provided_by_user:
        print("No targets.")
        sys.exit(1)

    timestamp_for_auto_files = ts_utc_compact()
    if parsed_arguments.csv == "AUTO":
        parsed_arguments.csv = default_log_artifact_path(
            f"scan_csv_{timestamp_for_auto_files}.csv"
        )
    if parsed_arguments.json == "AUTO":
        parsed_arguments.json = default_log_artifact_path(
            f"scan_json_{timestamp_for_auto_files}.json"
        )

    if parsed_arguments.pcap == "AUTO":
        parsed_arguments.pcap = default_log_artifact_path(
            f"scan_pcap_{timestamp_for_auto_files}"
        )

    print("*** SMRIB PORT SCANNER ***")
    print("")
    scan_started_at = utc_now_str()
    rate_display = "unlimited" if parsed_arguments.rate <= 0 else f"{parsed_arguments.rate}/s"
    print(
        f"SCAN start={scan_started_at} "
        f"mode={scan_mode_selected} "
        f"targets={len(target_labels_provided_by_user)} "
        f"ports={len(ports_selected_for_scan)} "
        f"concurrency={parsed_arguments.concurrency} "
        f"timeout={parsed_arguments.timeout}s "
        f"rate={rate_display}"
    )

    def describe_bool(flag_value: bool) -> str:
        return "on" if flag_value else "off"

    parameter_overview_parts = [
        "PARAMS",
        f"start_port={parsed_arguments.start}",
        f"end_port={parsed_arguments.end}",
        f"ports_arg={parsed_arguments.ports if parsed_arguments.ports else 'none'}",
        f"top_ports={top_ports_requested if top_ports_requested is not None else 'none'}",
        f"total_ports={len(ports_selected_for_scan)}",
        f"udp_probe={parsed_arguments.udp_probe if scan_mode_selected == 'udp' else 'n/a'}",
        f"retries={parsed_arguments.retries}",
        f"retry_backoff={parsed_arguments.retry_backoff}s",
        f"shuffle={describe_bool(parsed_arguments.shuffle)}",
        f"banner={describe_bool(parsed_arguments.banner)}",
        f"fast_mode={describe_bool(parsed_arguments.fast)}",
        f"show_closed_terminal={describe_bool(getattr(parsed_arguments, 'show_closed_terminal', False))}",
        f"show_closed_terminal_only={describe_bool(getattr(parsed_arguments, 'show_closed_terminal_only', False))}",
        f"show_only_open={describe_bool(getattr(parsed_arguments, 'show_only_open', False))}",
        f"csv={parsed_arguments.csv if parsed_arguments.csv else 'none'}",
        f"json={parsed_arguments.json if parsed_arguments.json else 'none'}",
        f"pcap={parsed_arguments.pcap if parsed_arguments.pcap else 'none'}",
    ]
    print(" ".join(parameter_overview_parts))
    if concurrency_notice:
        print(concurrency_notice)
    if fast_mode_adjustments is not None:
        rate_description = "off" if parsed_arguments.rate <= 0 else f"{parsed_arguments.rate}/s"
        shuffle_state_description = "on" if parsed_arguments.shuffle else "off"
        banner_state_description = "on" if parsed_arguments.banner else "off"
        auto_syn_message = " (auto-selected SYN)" if fast_mode_adjustments.get("auto_syn") else ""
        print(
            f"[fast]{auto_syn_message} mode={scan_mode_selected} "
            f"concurrency={parsed_arguments.concurrency} timeout={parsed_arguments.timeout}s "
            f"rate-limit={rate_description} shuffle={shuffle_state_description} banner={banner_state_description} "
            f"retries={parsed_arguments.retries} backoff={parsed_arguments.retry_backoff}s"
        )
        guardrail_notice = fast_mode_adjustments.get("concurrency_guardrail_notice")
        if guardrail_notice:
            print(f"[fast] {guardrail_notice}")
        auto_syn_reason = fast_mode_adjustments.get("auto_syn_reason")
        if auto_syn_reason == "scapy-missing":
            print("[fast] Scapy not available, unable to auto-select SYN mode.")
        elif auto_syn_reason == "root-required":
            print("[fast] Run as root to allow fast mode to auto-select SYN scanning.")
        elif auto_syn_reason == "privilege-unknown":
            print("[fast] Could not verify privileges; leaving SYN auto-selection disabled.")
        print("[fast] Private and internal networks are included automatically.")
    print("")

    aggregate_open_results: List[ScanRecord] = []
    aggregate_all_scan_results: List[ScanRecord] = []
    has_scanned_at_least_one_target = False

    try:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

        per_host_sniffer_details: Dict[str, Tuple[Any, str]] = {}

        for target_label_text in target_labels_provided_by_user:
            resolved_ip_address = event_loop.run_until_complete(resolve_dns_label_to_ip(target_label_text))
            if fast_mode_adjustments is not None and not is_external_ip(resolved_ip_address):
                print(f"[fast] Target {target_label_text} [{resolved_ip_address}] identified as private/internal and will be scanned.")
            if target_label_text != resolved_ip_address:
                print(f"Targeting DOMAIN {target_label_text} [{resolved_ip_address}]")
            else:
                print(f"TARGET {target_label_text} -> {resolved_ip_address}")
            has_scanned_at_least_one_target = True
            print("")

            if getattr(parsed_arguments, "pcap", None):
                if len(target_labels_provided_by_user) == 1 and str(parsed_arguments.pcap).lower().endswith(".pcap"):
                    pcap_filename_for_host = parsed_arguments.pcap
                else:
                    base_name = parsed_arguments.pcap[:-5] if str(parsed_arguments.pcap).lower().endswith(".pcap") else parsed_arguments.pcap
                    pcap_filename_for_host = f"{base_name}.{resolved_ip_address}.pcap" if len(target_labels_provided_by_user) > 1 else f"{base_name}.pcap"
                sniffer_instance = start_pcap_sniffer_for_host(filter_expression=f"host {resolved_ip_address}")
                if sniffer_instance is None:
                    print("Warning: could not start packet sniffer for host", resolved_ip_address)
                per_host_sniffer_details[resolved_ip_address] = (sniffer_instance, pcap_filename_for_host)

            confirmed_open_results_for_host, all_results_for_host = event_loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip_address,
                    selected_ports=ports_selected_for_scan,
                    selected_mode=scan_mode_selected,
                    timeout_seconds=parsed_arguments.timeout,
                    max_concurrency=parsed_arguments.concurrency,
                    show_closed_in_output=show_closed_in_terminal,
                    show_only_open_in_output=show_only_open_in_terminal,
                    banner_enabled=parsed_arguments.banner,
                    per_host_ops_per_sec=parsed_arguments.rate,
                    udp_probe_kind=parsed_arguments.udp_probe,
                    retries=max(1, parsed_arguments.retries),
                    backoff_seconds=max(0.0, parsed_arguments.retry_backoff),
                )
            )

            aggregate_open_results.extend(confirmed_open_results_for_host)
            aggregate_all_scan_results.extend(all_results_for_host)

            emit_summary_for_suppressed_results(
                host_label=target_label_text,
                ip_address=resolved_ip_address,
                show_only_open_flag=show_only_open_in_terminal,
                open_results=confirmed_open_results_for_host,
                all_results=all_results_for_host,
            )

            if getattr(parsed_arguments, "pcap", None):
                sniffer_instance, pcap_path = per_host_sniffer_details.get(resolved_ip_address, (None, None))
                if pcap_path:
                    stop_sniffer_and_write_pcap(sniffer_instance, pcap_path)
                    print(f"pcap -> {pcap_path}")

        if fast_mode_adjustments is not None and not has_scanned_at_least_one_target:
            print("[fast] No targets were scanned. Verify the supplied targets list.")

        event_loop.close()

    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(130)

    print("")
    print(f"SCAN end={utc_now_str()} open_found={len(aggregate_open_results)}")

    persist_all_results = should_persist_all_results(
        bool(parsed_arguments.show_closed_terminal),
        bool(getattr(parsed_arguments, "show_closed_terminal_only", False)),
        parsed_arguments.csv,
        parsed_arguments.json,
    )

    rows_for_persistence, artifacts_show_only_open = determine_artifact_rows(
        show_only_open_in_terminal,
        persist_all_results,
        aggregate_open_results,
        aggregate_all_scan_results,
    )

    if parsed_arguments.csv:
        write_results_to_csv(
            parsed_arguments.csv,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )

    if parsed_arguments.json:
        write_results_to_json(
            parsed_arguments.json,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )

    return aggregate_open_results, aggregate_all_scan_results

# Convert one text line into argv tokens.
# - Ignore empty lines, comments (#...), and lines of only '#', '-' or spaces.
# - Drop any tokens before the first '-' option, so both full CLI and flags-only lines work.
def parse_spec_line_to_argv(line: str) -> Optional[List[str]]:
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
# Read SPECFILE and execute each valid CLI spec sequentially.
# Each spec line is parsed against the same CLI as single-run mode.
def run_batch_from_file(spec_file: str) -> None:
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

def determine_batch_battery_ports(
    base_arguments: argparse.Namespace,
    top_ports_override: Optional[int],
) -> List[int]:

    explicit_ports = getattr(base_arguments, "ports", None)
    top_ports_file_override = getattr(base_arguments, "top_ports_file", None)
    if explicit_ports:
        ports = parse_port_specification(base_arguments.start, base_arguments.end, explicit_ports)
        if ports:
            print(
                f"[TEST] Using {len(ports)} port(s) from --ports specification for batch battery."
            )
        else:
            print("[TEST] --ports specification produced no valid ports for batch battery.")
        return ports

    top_ports_requested = getattr(base_arguments, "top_ports", None)
    if top_ports_requested is not None:
        count = int(top_ports_requested)
        if count <= 0:
            count = DEFAULT_BATCH_BATTERY_TOP_PORTS
        ports = load_top_ports_from_file(count, top_ports_file_override)
        print(
            f"[TEST] Using top {len(ports)} ports from the top ports file for batch battery."
        )
        return ports

    if top_ports_override is not None:
        count = int(top_ports_override)
        if count <= 0:
            count = DEFAULT_BATCH_BATTERY_TOP_PORTS
        ports = load_top_ports_from_file(count, top_ports_file_override)
        print(
            f"[TEST] Using top {len(ports)} ports requested via --batch-battery ({count})."
        )
        return ports

    start_default = int(DEFAULTS["START"])
    end_default = int(DEFAULTS["END"])
    if base_arguments.start != start_default or base_arguments.end != end_default:
        ports = parse_port_specification(base_arguments.start, base_arguments.end, None)
        print(
            f"[TEST] Using port range {base_arguments.start}-{base_arguments.end} for batch battery."
        )
        return ports

    ports = load_top_ports_from_file(
        DEFAULT_BATCH_BATTERY_TOP_PORTS,
        top_ports_file_override,
    )
    if ports:
        print(
            f"[TEST] Using default top {len(ports)} ports list from the top ports file for batch battery."
        )
        return ports

    ports = parse_port_specification(base_arguments.start, base_arguments.end, None)
    if ports:
        print(
            f"[TEST] Top ports file unavailable; falling back to range {base_arguments.start}-{base_arguments.end}."
        )
    else:
        print("[TEST] No ports available for batch battery.")
    return ports


# [AUTO]Execute a compact verification suite against provided targets.
def run_batch_battery(targets_file: str,
                      base_arguments: argparse.Namespace) -> None:

    top_ports_override_from_batch: Optional[int] = None
    normalized_path = os.path.expanduser(str(targets_file))
    targets_list: List[str]

    if os.path.isfile(normalized_path):
        try:
            targets_list = read_targets_from_file(normalized_path)
        except Exception as exc:
            print(f"Error reading targets file {normalized_path}: {exc}")
            return
        if not targets_list:
            print("No targets found in test file.")
            return
    else:
        try:
            top_ports_override_from_batch = int(str(targets_file))
        except (TypeError, ValueError):
            print(f"Targets file not found: {targets_file}")
            return
        targets_list = expand_targets_to_list(base_arguments.targets)
        if not targets_list:
            print("No targets found from --targets argument.")
            return
        print(
            f"[TEST] Using targets supplied via --targets ({len(targets_list)} entries)."
        )

    selected_ports_for_battery = determine_batch_battery_ports(
        base_arguments,
        top_ports_override_from_batch,
    )
    if not selected_ports_for_battery:
        print("No ports selected for batch battery.")
        return

    fast_mode_adjustments = apply_fast_mode_overrides(base_arguments)
    show_closed_in_terminal = bool(
        base_arguments.show_closed_terminal
        or getattr(base_arguments, "show_closed_terminal_only", False)
    )
    show_only_open_in_terminal = bool(getattr(base_arguments, "show_only_open", False))
    if fast_mode_adjustments is not None:
        rate_description = "off" if base_arguments.rate <= 0 else f"{base_arguments.rate}/s"
        auto_syn_note = " (auto-selected SYN)" if fast_mode_adjustments.get("auto_syn") else ""
        print(
            f"[fast]{auto_syn_note} Test battery mode: concurrency={base_arguments.concurrency} "
            f"timeout={base_arguments.timeout}s rate-limit={rate_description} "
            f"shuffle={'on' if base_arguments.shuffle else 'off'} banner={'on' if base_arguments.banner else 'off'}"
        )
        guardrail_notice = fast_mode_adjustments.get("concurrency_guardrail_notice")
        if guardrail_notice:
            print(f"[fast] {guardrail_notice}")
        auto_syn_reason = fast_mode_adjustments.get("auto_syn_reason")
        if auto_syn_reason == "scapy-missing":
            print("[fast] Scapy not available, unable to auto-select SYN mode for tests.")
        elif auto_syn_reason == "root-required":
            print("[fast] Run the batch battery as root to allow SYN auto-selection.")
        elif auto_syn_reason == "privilege-unknown":
            print("[fast] Could not verify privileges; skipping SYN auto-selection in tests.")
        print("[fast] Private and internal networks are included automatically during the battery.")

    test_ports_connect = selected_ports_for_battery
    test_ports_syn = selected_ports_for_battery
    test_ports_udp = selected_ports_for_battery

    aggregated_open_results: List[ScanRecord] = []
    aggregated_all_results: List[ScanRecord] = []
    any_scan_completed = False

    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)

    connect_concurrency, connect_notice = normalize_concurrency_for_mode(base_arguments.concurrency, "connect")
    syn_concurrency, syn_notice = normalize_concurrency_for_mode(base_arguments.concurrency, "syn")
    udp_concurrency, udp_notice = normalize_concurrency_for_mode(base_arguments.concurrency, "udp")
    for notice in (connect_notice, syn_notice, udp_notice):
        if notice:
            print(f"[TEST] {notice}")

    for target_label_text in targets_list:
        resolved_ip_address = event_loop.run_until_complete(resolve_dns_label_to_ip(target_label_text))
        if fast_mode_adjustments is not None and not is_external_ip(resolved_ip_address):
            print(f"[fast] Target {target_label_text} [{resolved_ip_address}] identified as private/internal and will be scanned in test mode.")
        print(f"[TEST] TARGET {target_label_text} -> {resolved_ip_address}")
        open_results_for_host, all_results_for_host = event_loop.run_until_complete(
            scan_all_selected_ports_for_host(
                target_ip=resolved_ip_address,
                selected_ports=test_ports_connect,
                selected_mode="connect",
                timeout_seconds=base_arguments.timeout,
                max_concurrency=connect_concurrency,
                show_closed_in_output=show_closed_in_terminal,
                show_only_open_in_output=show_only_open_in_terminal,
                banner_enabled=base_arguments.banner,
                per_host_ops_per_sec=base_arguments.rate,
                udp_probe_kind=base_arguments.udp_probe,
                retries=max(1, base_arguments.retries),
                backoff_seconds=max(0.0, base_arguments.retry_backoff),
            )
        )
        aggregated_open_results.extend(open_results_for_host)
        aggregated_all_results.extend(all_results_for_host)
        any_scan_completed = True

        emit_summary_for_suppressed_results(
            host_label=target_label_text,
            ip_address=resolved_ip_address,
            show_only_open_flag=show_only_open_in_terminal,
            open_results=open_results_for_host,
            all_results=all_results_for_host,
        )

    scapy_available = SCAPY_AVAILABLE
    try:
        effective_user_id = os.geteuid()
    except AttributeError:
        effective_user_id = None

    if scapy_available and effective_user_id == 0:
        for target_label_text in targets_list:
            resolved_ip_address = event_loop.run_until_complete(resolve_dns_label_to_ip(target_label_text))
            if fast_mode_adjustments is not None and not is_external_ip(resolved_ip_address):
                print(f"[fast] Target {target_label_text} [{resolved_ip_address}] identified as private/internal and will be scanned in SYN mode.")
            print(f"[TEST] SYN-target {target_label_text} -> {resolved_ip_address}")
            open_results_for_host, all_results_for_host = event_loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip_address,
                    selected_ports=test_ports_syn,
                    selected_mode="syn",
                    timeout_seconds=base_arguments.timeout,
                    max_concurrency=syn_concurrency,
                    show_closed_in_output=show_closed_in_terminal,
                    show_only_open_in_output=show_only_open_in_terminal,
                    banner_enabled=False,
                    per_host_ops_per_sec=base_arguments.rate,
                    udp_probe_kind=base_arguments.udp_probe,
                    retries=max(1, base_arguments.retries),
                    backoff_seconds=max(0.0, base_arguments.retry_backoff),
                )
            )
            aggregated_open_results.extend(open_results_for_host)
            aggregated_all_results.extend(all_results_for_host)
            any_scan_completed = True

            emit_summary_for_suppressed_results(
                host_label=target_label_text,
                ip_address=resolved_ip_address,
                show_only_open_flag=show_only_open_in_terminal,
                open_results=open_results_for_host,
                all_results=all_results_for_host,
            )

        for target_label_text in targets_list:
            resolved_ip_address = event_loop.run_until_complete(resolve_dns_label_to_ip(target_label_text))
            if fast_mode_adjustments is not None and not is_external_ip(resolved_ip_address):
                print(f"[fast] Target {target_label_text} [{resolved_ip_address}] identified as private/internal and will be scanned in UDP mode.")
            print(f"[TEST] UDP-target {target_label_text} -> {resolved_ip_address}")
            open_results_for_host, all_results_for_host = event_loop.run_until_complete(
                scan_all_selected_ports_for_host(
                    target_ip=resolved_ip_address,
                    selected_ports=test_ports_udp,
                    selected_mode="udp",
                    timeout_seconds=base_arguments.timeout,
                    max_concurrency=udp_concurrency,
                    show_closed_in_output=show_closed_in_terminal,
                    show_only_open_in_output=show_only_open_in_terminal,
                    banner_enabled=False,
                    per_host_ops_per_sec=base_arguments.rate,
                    udp_probe_kind="dns",
                    retries=max(1, base_arguments.retries),
                    backoff_seconds=max(0.0, base_arguments.retry_backoff),
                )
            )
            aggregated_open_results.extend(open_results_for_host)
            aggregated_all_results.extend(all_results_for_host)
            any_scan_completed = True

            emit_summary_for_suppressed_results(
                host_label=target_label_text,
                ip_address=resolved_ip_address,
                show_only_open_flag=show_only_open_in_terminal,
                open_results=open_results_for_host,
                all_results=all_results_for_host,
            )
    else:
        if not scapy_available:
            print("Warning: Scapy not available. Skipping SYN/UDP tests. Install with: pip install scapy")
        elif effective_user_id != 0:
            print("Warning: Not running as root. Skipping SYN/UDP tests.")

    if fast_mode_adjustments is not None and not any_scan_completed:
        print("[fast] No targets were scanned during the battery. Verify the supplied list.")

    event_loop.close()

    persist_all_results = should_persist_all_results(
        bool(base_arguments.show_closed_terminal),
        bool(getattr(base_arguments, "show_closed_terminal_only", False)),
        base_arguments.csv,
        base_arguments.json,
    )

    rows_for_persistence, artifacts_show_only_open = determine_artifact_rows(
        show_only_open_in_terminal,
        persist_all_results,
        aggregated_open_results,
        aggregated_all_results,
    )

    timestamp_for_auto_files = ts_utc_compact()

    if base_arguments.csv:
        csv_filename = (
            base_arguments.csv
            if base_arguments.csv != "AUTO"
            else default_log_artifact_path(
                f"test_csv_{timestamp_for_auto_files}.csv"
            )
        )
        write_results_to_csv(
            csv_filename,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )
    if base_arguments.json:
        json_filename = (
            base_arguments.json
            if base_arguments.json != "AUTO"
            else default_log_artifact_path(
                f"test_json_{timestamp_for_auto_files}.json"
            )
        )
        write_results_to_json(
            json_filename,
            rows_for_persistence,
            only_open=artifacts_show_only_open,
        )

    print(f"TEST end={utc_now_str()} open_found={len(aggregated_open_results)}")

# [AUTO]Entry point bridging CLI parsing and execution modes.

def main() -> None:

    cli_parser = build_cli_parser()

    provided_arguments = sys.argv[1:]
    if not provided_arguments:
        implicit_defaults = [
            "--show-only-open",
            "--banner",
            "--top-ports",
            "100",
            "--csv",
            "logs/results.csv",
            "--json",
            "logs/results.json",
        ]
        args = cli_parser.parse_args(implicit_defaults)
    else:
        args = cli_parser.parse_args(provided_arguments)

    if getattr(args, "web_dir", False):
        success = run_web_directory_listing_tool(args.url, args.wordlist)
        if not success:
            sys.exit(1)
        return

    if getattr(args, "find_machines", False):
        run_find_machines_mode(args)
        return

    if args.batch:
        run_batch_from_file(args.batch)
        return

    if args.batch_battery:
        run_batch_battery(args.batch_battery, args)
        return

    run_full_scan(args)


if __name__ == "__main__":
    main()
