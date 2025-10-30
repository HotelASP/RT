#!/usr/bin/env bash
set -euo pipefail

# recolhe CIDRs das interfaces IPv4
mapfile -t nets < <(ip -4 -o addr show | awk '{print $4}' | sort -u)

# fallback: se não encontrou nada, tenta redes RFC1918 comuns (opcional)
if [ ${#nets[@]} -eq 0 ]; then
  nets=(10.0.5.0/24 10.0.15.0/24 192.168.0.0/16)
fi

for net in "${nets[@]}"; do
  echo
  echo "==> Scanning ${net}"
  sudo nmap -sn "${net}" -oN "nmap_${net//\//_}.txt" --reason
done

echo
echo "Done. Resultados em nmap_*.txt"
