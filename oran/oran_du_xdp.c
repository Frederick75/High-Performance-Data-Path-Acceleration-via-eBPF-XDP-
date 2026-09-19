// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT          2152
#define GTPU_G_PDU         0xff

#define DRB_ACCEL          (1U << 0)
#define DRB_DROP           (1U << 1)

#define MAX_XSKS           256

struct gtpu_hdr {
    __u8 flags;
    __u8 message_type;
    __be16 length;
    __be32 teid;
};

struct drb_policy {
    __u32 flags;

    __u16 slice_id;
    __u8  priority;
    __u8  qos_class;

    __u32 worker_id;
};

struct xsk_binding_key {
    __u32 ifindex;
    __u32 queue;
};


struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_XSKS);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_XSKS);
    __type(key, struct xsk_binding_key);
    __type(value, __u32);
} queue_to_slot SEC(".maps");


/*
 * F1-U TEID -> DRB/UE/slice policy
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct drb_policy);
} drb_by_teid SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");


static __always_inline void count(__u32 index)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &index);

    if (v)
        (*v)++;
}


static __always_inline int redirect_to_worker(
        struct xdp_md *ctx)
{
    struct xsk_binding_key key = {
        .ifindex = ctx->ingress_ifindex,
        .queue   = ctx->rx_queue_index,
    };

    __u32 *slot;

    slot = bpf_map_lookup_elem(&queue_to_slot,
                               &key);

    if (!slot)
        return XDP_PASS;

    count(1);

    return bpf_redirect_map(&xsks_map,
                            *slot,
                            XDP_PASS);
}


SEC("xdp")
int xdp_oran_f1u(struct xdp_md *ctx)
{
    void *data =
        (void *)(long)ctx->data;

    void *data_end =
        (void *)(long)ctx->data_end;

    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct gtpu_hdr *gtp;

    struct drb_policy *policy;

    __u32 ihl;
    __u32 teid;

    eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->ihl < 5)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    ihl = ip->ihl * 4;

    udp = (void *)ip + ihl;

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    if (udp->dest != bpf_htons(GTPU_PORT) &&
        udp->source != bpf_htons(GTPU_PORT))
        return XDP_PASS;

    gtp = (void *)(udp + 1);

    if ((void *)(gtp + 1) > data_end)
        return XDP_DROP;

    if (gtp->message_type != GTPU_G_PDU)
        return XDP_PASS;

    teid = bpf_ntohl(gtp->teid);

    policy = bpf_map_lookup_elem(&drb_by_teid,
                                 &teid);

    /*
     * Unknown F1-U TEID:
     *
     * Leave to the existing DU slow path.
     */
    if (!policy) {
        count(2);
        return XDP_PASS;
    }

    if (policy->flags & DRB_DROP) {
        count(3);
        return XDP_DROP;
    }

    if (policy->flags & DRB_ACCEL)
        return redirect_to_worker(ctx);

    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";
