#!/usr/bin/env bash
# Smoke test: install.sh syntactically valid + shellcheck clean across
# 3 distros (Ubuntu 22.04, Debian 11, Rocky 9). Full e2e install requires
# GH Releases (Plan 09) — deferido.

set -euo pipefail

cd "$(dirname "$0")"

# Copia o install.sh pro contexto de build pra cada Dockerfile poder
# fazer COPY (build context é este diretório).
cp ../install.sh ./install.sh
trap 'rm -f ./install.sh' EXIT

for distro in ubuntu-22.04 debian-11 rocky-9; do
    echo "=== Testing $distro ==="
    docker build -f "Dockerfile.${distro}" -t "ispwatch-install-test:${distro}" .
    docker run --rm "ispwatch-install-test:${distro}"
    echo "OK: $distro"
done

echo ""
echo "All distros passed syntax + shellcheck."
