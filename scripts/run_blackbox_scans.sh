#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET_URL="${1:-}"
PROFILE="${2:-local}"
AUTHZ_TICKET="${3:-}"

if [[ -z "${TARGET_URL}" ]]; then
  if [[ "${PROFILE}" == "prod" ]]; then
    TARGET_URL="https://app.lattix.io"
  else
    TARGET_URL="http://app.prod-blue.localtest.me"
  fi
fi

TARGET_DNS="$(python3 - <<'PY' "$TARGET_URL"
from urllib.parse import urlparse
import sys
print((urlparse(sys.argv[1]).hostname or "").strip())
PY
)"

if [[ ("${PROFILE}" == "prod" || "${PROFILE}" == "ci") && ! "${TARGET_URL}" =~ ^https:// ]]; then
  echo "[!] ${PROFILE} profile requires an https target URL" >&2
  exit 1
fi

OUT_DIR="reports/raw"
TS="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${PENTEST_RUN_DIR:-${OUT_DIR}/${TS}}"
mkdir -p "$RUN_DIR"
RUN_DIR_ABS="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$RUN_DIR")"

echo "[+] Black-box scan profile: ${PROFILE}"
echo "[+] Black-box scan target: ${TARGET_URL}"
echo "[+] Output directory: ${RUN_DIR}"

EXTRA_DOCKER_ARGS=()
if [[ "${PROFILE}" == "local" ]]; then
  EXTRA_DOCKER_ARGS+=(--add-host "${TARGET_DNS}:host-gateway")
fi

# 1) Port and service discovery (public attack surface only)
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" instrumentisto/nmap -Pn -sV -O -T4 "$TARGET_DNS" -oN /out/nmap.txt || true

# 2) HTTP tech fingerprinting
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" bberastegui/whatweb "$TARGET_URL" --log-json /out/whatweb.json || true

# 3) Nuclei template scan (known vulns/misconfig)
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" projectdiscovery/nuclei:latest \
  -u "$TARGET_URL" \
  -severity critical,high,medium,low,info \
  -json-export /out/nuclei.json \
  -silent || true

# 4) OWASP ZAP baseline (passive web checks)
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET_URL" -J zap.json -r zap.html -m 5 || true

# 5) Nikto web server checks
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" alpine/nikto \
  -h "$TARGET_URL" -output /out/nikto.txt || true

# 6) Katana crawl for endpoint discovery
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" projectdiscovery/katana:latest \
  -u "$TARGET_URL" -silent -o /out/katana.txt || true

# 7) TLS and header posture quick checks (via nmap scripts)
docker run --rm "${EXTRA_DOCKER_ARGS[@]}" -v "${RUN_DIR_ABS}:/out" instrumentisto/nmap \
  -Pn --script ssl-cert,ssl-enum-ciphers,http-security-headers -p 80,443 "$TARGET_DNS" -oN /out/nmap_tls_headers.txt || true

cat > "${RUN_DIR}/scan_meta.json" <<EOF
{
  "profile": "${PROFILE}",
  "target_dns": "${TARGET_DNS}",
  "target_url": "${TARGET_URL}",
  "authorization_ticket": "${AUTHZ_TICKET}",
  "timestamp": "${TS}",
  "mode": "black-box-public-dns-only",
  "tools": ["nmap", "whatweb", "nuclei", "owasp-zap-baseline", "nikto", "katana"]
}
EOF

echo "[+] Raw scan artifacts saved under: ${RUN_DIR}"
