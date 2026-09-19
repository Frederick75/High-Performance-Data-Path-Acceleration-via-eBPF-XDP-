#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/oran"

mkdir -p "$OUT"

CC="${CC:-gcc}"
CLANG="${CLANG:-clang}"

MULTIARCH="$($CC -dumpmachine)"

BPF_INC=""

if [ -d "/usr/include/$MULTIARCH" ]; then
    BPF_INC="-I/usr/include/$MULTIARCH"
fi

echo "=== Building O-RAN O-DU XDP program ==="

$CLANG \
    -O2 \
    -g \
    -Wall \
    -target bpf \
    $BPF_INC \
    -I/usr/include \
    -c "$ROOT/oran/oran_du_xdp.c" \
    -o "$OUT/oran_du_xdp.o"

echo "=== Building XDP loader ==="

$CC \
    -O2 \
    -g \
    -Wall \
    "$ROOT/common/xdp_loader.c" \
    -o "$OUT/xdp_loader" \
    $(pkg-config --cflags --libs libbpf)

echo "=== Building O-RAN policy controller ==="

$CC \
    -O2 \
    -g \
    -Wall \
    "$ROOT/oran/oran_policy_ctl.c" \
    -o "$OUT/oran_policy_ctl" \
    $(pkg-config --cflags --libs libbpf)

echo "=== Building AF_XDP O-DU worker ==="

$CC \
    -O3 \
    -g \
    -Wall \
    "$ROOT/common/afxdp_worker.c" \
    -o "$OUT/afxdp_worker" \
    $(pkg-config --cflags --libs libxdp libbpf)

echo
echo "O-RAN build complete:"
ls -lh "$OUT"
