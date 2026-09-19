#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/5g"

mkdir -p "$OUT"

CC="${CC:-gcc}"
CLANG="${CLANG:-clang}"

MULTIARCH="$($CC -dumpmachine)"

BPF_INC=""

if [ -d "/usr/include/$MULTIARCH" ]; then
    BPF_INC="-I/usr/include/$MULTIARCH"
fi

echo "=== Building 5G XDP kernel program ==="

$CLANG \
    -O2 \
    -g \
    -Wall \
    -target bpf \
    $BPF_INC \
    -I/usr/include \
    -c "$ROOT/5g/5g_upf_xdp.c" \
    -o "$OUT/5g_upf_xdp.o"

echo "=== Building generic XDP loader ==="

$CC \
    -O2 \
    -g \
    -Wall \
    "$ROOT/common/xdp_loader.c" \
    -o "$OUT/xdp_loader" \
    $(pkg-config --cflags --libs libbpf)

echo "=== Building 5G policy controller ==="

$CC \
    -O2 \
    -g \
    -Wall \
    "$ROOT/5g/5g_policy_ctl.c" \
    -o "$OUT/5g_policy_ctl" \
    $(pkg-config --cflags --libs libbpf)

echo "=== Building AF_XDP worker ==="

$CC \
    -O3 \
    -g \
    -Wall \
    "$ROOT/common/afxdp_worker.c" \
    -o "$OUT/afxdp_worker" \
    $(pkg-config --cflags --libs libxdp libbpf)

echo
echo "Build complete:"
ls -lh "$OUT"
