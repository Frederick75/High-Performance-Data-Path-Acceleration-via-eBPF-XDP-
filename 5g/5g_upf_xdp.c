// SPDX-License-Identifier: GPL-2.0
//
// 5G UPF XDP accelerator
//
// N3:
//   Ethernet -> IPv4 -> UDP -> GTP-U -> TEID lookup
//
// N6:
//   Ethernet -> IPv4 -> UE IPv4 lookup
//
// Selected packets are redirected to AF_XDP.
// Complex PDR/FAR/QER/URR processing is intentionally left
// to the UPF worker.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT          2152
#define GTPU_G_PDU         0xff

#define ROLE_N3            1
#define ROLE_N6            2

#define POLICY_ACCEL       (1U << 0)
#define POLICY_DROP        (1U << 1)

#define MAX_XSKS           256

enum stat_index {
    STAT_PASS = 0,
    STAT_REDIRECT,
    STAT_DROP,
    STAT_BAD_PACKET,
    STAT_NO_SESSION,
    STAT_MAX
};

struct gtpu_hdr {
    __u8   flags;
    __u8   message_type;
    __be16 length;
    __be32 teid;
};

struct upf_policy {
    __u32 flags;
    __u32 qos_profile;
    __u32 far_id;
    __u32 reserved;
};

struct xsk_binding_key {
    __u32 ifindex;
    __u32 queue;
};


/*
 * AF_XDP socket table.
 *
 * value = AF_XDP socket FD inserted from user space.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_XSKS);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");


/*
 * Map <interface, RX queue> -> XSKMAP slot.
 *
 * This allows queue 0 of N3 and queue 0 of N6 to use
 * different XSKMAP slots.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_XSKS);
    __type(key, struct xsk_binding_key);
    __type(value, __u32);
} queue_to_slot SEC(".maps");


/*
 * TEID -> UPF policy.
 *
 * Normally populated by the PFCP/control-plane agent.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct upf_policy);
} teid_policy SEC(".maps");


/*
 * UE IPv4 address -> policy.
 *
 * Used on N6 downlink traffic.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, struct upf_policy);
} ue_v4_policy SEC(".maps");


/*
 * Interface role:
 *
 * ifindex -> ROLE_N3 / ROLE_N6
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} if_role SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");


static __always_inline void count_stat(__u32 index)
{
    __u64 *v;

    v = bpf_map_lookup_elem(&stats, &index);
    if (v)
        (*v)++;
}


static __always_inline int redirect_to_xsk(struct xdp_md *ctx)
{
    struct xsk_binding_key key = {
        .ifindex = ctx->ingress_ifindex,
        .queue   = ctx->rx_queue_index,
    };

    __u32 *slot;

    slot = bpf_map_lookup_elem(&queue_to_slot, &key);

    if (!slot) {
        count_stat(STAT_PASS);
        return XDP_PASS;
    }

    count_stat(STAT_REDIRECT);

    /*
     * If the XSK entry is missing or incompatible,
     * fall back to XDP_PASS.
     */
    return bpf_redirect_map(&xsks_map, *slot, XDP_PASS);
}


static __always_inline int parse_ipv4(
        void *data,
        void *data_end,
        struct iphdr **iph_out)
{
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u32 ihl_len;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 1;

    iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->ihl < 5)
        return -1;

    ihl_len = iph->ihl * 4;

    if ((void *)iph + ihl_len > data_end)
        return -1;

    *iph_out = iph;

    return 0;
}


static __always_inline int process_n3(
        struct xdp_md *ctx,
        void *data,
        void *data_end,
        struct iphdr *iph)
{
    struct udphdr *udp;
    struct gtpu_hdr *gtp;
    struct upf_policy *policy;

    __u32 ihl_len;
    __u32 teid;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    ihl_len = iph->ihl * 4;
    udp = (void *)iph + ihl_len;

    if ((void *)(udp + 1) > data_end)
        goto malformed;

    if (udp->dest != bpf_htons(GTPU_PORT) &&
        udp->source != bpf_htons(GTPU_PORT))
        return XDP_PASS;

    gtp = (void *)(udp + 1);

    if ((void *)(gtp + 1) > data_end)
        goto malformed;

    /*
     * Fast path handles G-PDU only.
     *
     * Echo Request, Error Indication, End Marker, etc.
     * are passed to the normal control/slow path.
     */
    if (gtp->message_type != GTPU_G_PDU)
        return XDP_PASS;

    teid = bpf_ntohl(gtp->teid);

    policy = bpf_map_lookup_elem(&teid_policy, &teid);

    if (!policy) {
        count_stat(STAT_NO_SESSION);
        return XDP_PASS;
    }

    if (policy->flags & POLICY_DROP) {
        count_stat(STAT_DROP);
        return XDP_DROP;
    }

    if (policy->flags & POLICY_ACCEL)
        return redirect_to_xsk(ctx);

    return XDP_PASS;

malformed:

    count_stat(STAT_BAD_PACKET);
    return XDP_DROP;
}


static __always_inline int process_n6(
        struct xdp_md *ctx,
        struct iphdr *iph)
{
    struct upf_policy *policy;

    /*
     * On N6 ingress, destination IP normally identifies
     * the UE/PDU-session for downlink traffic.
     */
    policy = bpf_map_lookup_elem(&ue_v4_policy,
                                 &iph->daddr);

    if (!policy) {
        count_stat(STAT_NO_SESSION);
        return XDP_PASS;
    }

    if (policy->flags & POLICY_DROP) {
        count_stat(STAT_DROP);
        return XDP_DROP;
    }

    if (policy->flags & POLICY_ACCEL)
        return redirect_to_xsk(ctx);

    return XDP_PASS;
}


SEC("xdp")
int xdp_5g_upf(struct xdp_md *ctx)
{
    void *data;
    void *data_end;

    struct iphdr *iph;

    __u32 ifindex;
    __u32 *role;

    int rc;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    rc = parse_ipv4(data, data_end, &iph);

    if (rc > 0)
        return XDP_PASS;

    if (rc < 0) {
        count_stat(STAT_BAD_PACKET);
        return XDP_DROP;
    }

    ifindex = ctx->ingress_ifindex;

    role = bpf_map_lookup_elem(&if_role, &ifindex);

    if (!role)
        return XDP_PASS;

    switch (*role) {
    case ROLE_N3:
        return process_n3(ctx, data, data_end, iph);

    case ROLE_N6:
        return process_n6(ctx, iph);

    default:
        return XDP_PASS;
    }
}


char LICENSE[] SEC("license") = "GPL";
