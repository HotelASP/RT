#!/usr/bin/env python3
# PORTSCANNER MRIB
#   python3 portscan.py --host 160.153.248.110 --start 1 --end 1024 --concurrency 1 --timeout 1
#   python3 portscan.py --host hotelasp.com --ports 21,80,443,445,1801,2103-2107 --concurrency 200
# *** FLAGS TCP ***
# SYN = inicia conexão (0x02)
# ACK = reconhecimento (0x10)
# RST = reset (abort) (0x04)
# FIN = fim de envio (0x01)
# PSH = push (dados imediatos) (0x08)
# URG = urgente (0x20)
# ECE = Explicit Congestion (0x40)
# CWR = Congestion Window Reduced (0x80)
# Comuns combinados:
# SYN (0x02)
# SYN,ACK (0x12)
# RST,ACK (0x14)
# FIN,ACK (0x11)
# ACK só (0x10) — pacote normal de dados/ack.
# *** ESTADOS TCP ***
# CLOSED — sem socket
# LISTEN — servidor espera SYN
# SYN-SENT — cliente enviou SYN, espera SYN/ACK
# SYN-RECEIVED — recebeu SYN, respondeu SYN/ACK, espera ACK
# ESTABLISHED — conexão aberta, troca de dados
# FIN-WAIT-1 — iniciou fechamento (envia FIN)
# FIN-WAIT-2 — aguardando FIN remoto
# CLOSING — ambos fecharam quase simultâneo
# TIME-WAIT — espera para garantir fim seguro (2×MSL)
# CLOSE-WAIT — recebeu FIN, esperando app fechar
# LAST-ACK — enviou FIN, espera ACK final

import argparse
import asyncio
import csv
import socket
from datetime import datetime, UTC, timezone
import os
import errno, time

DEFAULTS = {
    "HOST": os.environ.get("PORTSCAN_HOST", "160.153.248.110"),
    "START": int(os.environ.get("PORTSCAN_START", "1")),
    "END": int(os.environ.get("PORTSCAN_END", "65535")),
    "CONCURRENCY": int(os.environ.get("PORTSCAN_CONCURRENCY", "100")),
    "TIMEOUT": float(os.environ.get("PORTSCAN_TIMEOUT", "1.0")),
}


async def scan_port(semaphore, host, port, timeout, retries=2):
    async with semaphore:
        last_exc = None
        for attempt in range(1, retries+1):
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, "open", ""
            except asyncio.TimeoutError:
                last_exc = "timeout"
                # se for a última tentativa marca filtered, senão espera e tenta outra vez
                if attempt < retries:
                    await asyncio.sleep(0.1 * attempt)
                    continue
                return port, "filtered", "timeout"
            except ConnectionRefusedError:
                return port, "closed", "ECONNREFUSED"
            except OSError as e:
                last_exc = e
                if e.errno in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN):
                    if attempt < retries:
                        await asyncio.sleep(0.1 * attempt)
                        continue
                    return port, "filtered", errno.errorcode.get(e.errno, str(e.errno))
                else:
                    return port, "closed", errno.errorcode.get(e.errno, str(e.errno))
            except Exception as e:
                last_exc = e
                if attempt < retries:
                    await asyncio.sleep(0.1 * attempt)
                    continue
                return port, "filtered", type(e).__name__


async def run_scan(host, ports, concurrency, timeout, show_closed):
    semaphore = asyncio.Semaphore(concurrency)
    
    tasks = [asyncio.create_task(scan_port(semaphore, host, p, timeout, retries=2)) for p in ports]
    
    results = []

    for task in asyncio.as_completed(tasks):
        port, status, reason = await task
        
        #ts = datetime.now(UTC).isoformat() + 'Z'

        ts = datetime.now(timezone.utc).isoformat() + 'Z'

        if status != "closed" or show_closed:
            note = f" {reason}" if reason else ""
            print(f"{ts} {host}:{port} {status}{note}")

        if status == "open":
            results.append((port, status, reason))
            
    return results

def parse_ports(range_start, range_end, single_ports):
    ports = []
    if single_ports:
        for part in single_ports.split(','):
            part = part.strip()
            if '-' in part:
                a,b = part.split('-',1)
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(part))
    else:
        ports = list(range(range_start, range_end+1))
    return sorted(set(p for p in ports if 1 <= p <= 65535))

def main():

    parser = argparse.ArgumentParser(description='Async TCP port scanner (minimal dependencies).')
    parser.add_argument('--host', default=DEFAULTS["HOST"], help='Target host or IP')
    parser.add_argument('--start', type=int, default=DEFAULTS["START"], help='Start port (default 1)')
    parser.add_argument('--end', type=int, default=DEFAULTS["END"], help='End port (default 1024)')
    parser.add_argument('--ports', help='Comma or range list, e.g. 22,80,8000-8100 (overrides start/end)')
    parser.add_argument('--concurrency', type=int, default=DEFAULTS["CONCURRENCY"], help='Concurrent connections (default 500)')
    parser.add_argument('--timeout', type=float, default=DEFAULTS["TIMEOUT"], help='Connect timeout seconds (default 1.0)')
    parser.add_argument('--csv', help='Write results to CSV file')
    parser.add_argument('--show-closed', action='store_true', help='Print closed ports too (verbose)')

    args = parser.parse_args()

    ports = parse_ports(args.start, args.end, args.ports)
    
    if not ports:
        print("No ports to scan"); return
    
    args.concurrency = max(1, args.concurrency)

    try:
        socket.getaddrinfo(args.host, None)
    except socket.gaierror as e:
        print('DNS resolution failed for host:', args.host, '->', e)
        return

    #start_time = datetime.now(UTC)

    start_time = datetime.now(timezone.utc)

    print(f"Scanning {args.host} ports {ports[0]}-{ports[-1]} concurrency={args.concurrency} timeout={args.timeout}s")
    
    try:
        results = asyncio.run(run_scan(args.host, ports, args.concurrency, args.timeout, args.show_closed))
    except KeyboardInterrupt:
        print("Scan cancelled by user")
        return   

    elapsed = (datetime.now(UTC) - start_time).total_seconds()

    print(f"Scan finished in {elapsed:.2f}s. Open ports: {len(results)}")

    if args.csv and results:
        with open(args.csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['host','port','status','note','scantime_utc'])
            for port, status, note in results:
                writer.writerow([args.host, port, status, note, datetime.now(UTC).isoformat() + 'Z'])
        print('Results written to', args.csv)

if __name__ == '__main__':
    main()
