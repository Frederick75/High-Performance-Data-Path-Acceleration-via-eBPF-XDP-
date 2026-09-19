****Typical Ubuntu development dependencies are:****

sudo apt install \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    libbpf-dev \
    libxdp-dev \
    bpftool \
    pkg-config

****Running the 5G accelerator****

  Load independent program instances so N3 and N6 can have separate AF_XDP maps and workers:

  sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

  sudo ./build/5g/xdp_loader detach ens2f0
  
  sudo ./build/5g/xdp_loader detach ens2f1

  sudo ./build/5g/xdp_loader \
    attach \
    ./build/5g/5g_upf_xdp.o \
    ens2f0 \
    /sys/fs/bpf/upf_n3

  sudo ./build/5g/xdp_loader \
    attach \
    ./build/5g/5g_upf_xdp.o \
    ens2f1 \
    /sys/fs/bpf/upf_n6

**Install an example TEID:**

sudo ./build/5g/5g_policy_ctl \
    teid \
    /sys/fs/bpf/upf_n3/teid_policy \
    0x1001 \
    accel

**Install the UE's downlink address:**

sudo ./build/5g/5g_policy_ctl \
    ue \
    /sys/fs/bpf/upf_n6/ue_v4_policy \
    10.45.0.2 \
    accel

**Start N3 queue 0 AF_XDP worker:**

sudo ./build/5g/afxdp_worker \
    ens2f0 \
    0 \
    0 \
    /sys/fs/bpf/upf_n3/xsks_map \
    /sys/fs/bpf/upf_n3/queue_to_slot

**N6 worker:**

sudo ./build/5g/afxdp_worker \
    ens2f1 \
    0 \
    0 \
    /sys/fs/bpf/upf_n6/xsks_map \
    /sys/fs/bpf/upf_n6/queue_to_slot

**Running the O-RAN accelerator******

Load XDP:

sudo ./build/oran/xdp_loader \
    detach \
    ens3f0

sudo ./build/oran/xdp_loader \
    attach \
    ./build/oran/oran_du_xdp.o \
    ens3f0 \
    /sys/fs/bpf/oran_f1u

**Install a DRB/TEID policy:**

sudo ./build/oran/oran_policy_ctl \
    /sys/fs/bpf/oran_f1u/drb_by_teid \
    0x2001 \
    accel \
    1 \
    5 \
    0
    
**  Start AF_XDP: **

sudo ./build/oran/afxdp_worker \
    ens3f0 \
    0 \
    0 \
    /sys/fs/bpf/oran_f1u/xsks_map \
    /sys/fs/bpf/oran_f1u/queue_to_slot

