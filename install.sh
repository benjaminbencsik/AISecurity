#!/usr/bin/env bash
# One-time setup: checks Python, offers to install nuclei, runs the doctor.
set -e
cd "$(dirname "$0")"

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  echo "Python 3.10 or newer is required (python3 --version)."; exit 1
fi

if ! command -v nuclei >/dev/null 2>&1 && command -v go >/dev/null 2>&1 && [ -t 0 ]; then
  read -r -p "nuclei is not installed. Install it now with go? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    export PATH="$(go env GOPATH)/bin:$PATH"
    nuclei -ut || echo "Template download failed; run 'nuclei -ut' later."
  fi
fi

python3 -m redswarm doctor || true
echo
echo "Ready. Scan an authorized target:"
echo "  python3 -m redswarm go https://YOUR-AUTHORIZED-TARGET/"
echo "Run it on a VPS instead:"
echo "  python3 -m redswarm vps setup user@your-vps && python3 -m redswarm go https://... --via user@your-vps"
