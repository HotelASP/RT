#!/usr/bin/env bash
set -euo pipefail

# target networks
networks=(
  "10.0.5.0/24"
  "192.168.0.0/24"
  "10.0.15.0/24"
)

outdir="nmap_scans"
ts=$(date '+%Y%m%d_%H%M%S')
mkdir -p "$outdir"

combined="$outdir/scan_summary_${ts}.txt"
echo "Scan timestamp: $(date -Iseconds)" > "$combined"
echo >> "$combined"

for net in "${networks[@]}"; do
  safe_net=${net//\//_}
  raw_file="$outdir/nmap_${safe_net}_${ts}.gnmap"
  parsed_file="$outdir/hosts_${safe_net}_${ts}.txt"

  echo "==> Scanning $net" | tee -a "$combined"
  # run quick host discovery and save greppable output
  sudo nmap -sn "$net" -oG "$raw_file" --reason

  # parse IPs and optional hostnames from greppable output
  awk '
    /Up$/ {
      for(i=1;i<=NF;i++){
        if ($i=="Host:") { ip=$(i+1) }
        if ($i=="(" && $(i+1)!=")") { host=$(i+1) }
      }
      if (ip!="") {
        if (host=="") { print ip } else { print ip " " host }
      }
      ip=""; host=""
    }' "$raw_file" | tee "$parsed_file" >> "$combined"

  echo >> "$combined"
done

echo "Results saved in: $outdir/"
echo "Summary file: $combined"
