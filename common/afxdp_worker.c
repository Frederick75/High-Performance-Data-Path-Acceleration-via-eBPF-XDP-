#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/mman.h>
#include <sys/resource.h>

#include <net/if.h>

#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf.h>

/*
 * Newer xdp-tools/libxdp distributions:
 */
#include <xdp/xsk.h>

/*
 * On older distributions this can instead be:
 *
 * #include <bpf/xsk.h>
 */

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define RX_SIZE    2048
#define BATCH_SIZE 64

struct xsk_binding_key {
    uint32_t ifindex;
    uint32_t queue;
};

struct worker {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;

    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;

    struct xsk_ring_cons rx;

    void *buffer;

    uint64_t packets;
    uint64_t bytes;
};


static void raise_memlock(void)
{
    struct rlimit r = {
        RLIM_INFINITY,
        RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_MEMLOCK, &r))
        perror("setrlimit");
}


static int register_xsk(
        const char *xsk_map_path,
        const char *binding_map_path,
        const char *ifname,
        uint32_t queue,
        uint32_t slot,
        int xsk_fd)
{
    int xsk_map;
    int binding_map;

    struct xsk_binding_key key;

    uint32_t ifindex =
        if_nametoindex(ifname);

    if (!ifindex)
        return -1;

    xsk_map = bpf_obj_get(xsk_map_path);

    if (xsk_map < 0) {
        perror("open xsks_map");
        return -1;
    }

    binding_map =
        bpf_obj_get(binding_map_path);

    if (binding_map < 0) {
        perror("open queue_to_slot");
        return -1;
    }

    /*
     * XSKMAP slot -> AF_XDP FD
     */
    if (bpf_map_update_elem(
            xsk_map,
            &slot,
            &xsk_fd,
            BPF_ANY)) {

        perror("update XSKMAP");
        return -1;
    }

    key.ifindex = ifindex;
    key.queue   = queue;

    /*
     * <interface,queue> -> XSKMAP slot
     */
    if (bpf_map_update_elem(
            binding_map,
            &key,
            &slot,
            BPF_ANY)) {

        perror("update binding map");
        return -1;
    }

    return 0;
}


static void process_packet(
        struct worker *w,
        void *packet,
        uint32_t len)
{
    /*
     * Replace this function by the real platform worker.
     *
     * 5G:
     *
     *   parse GTP-U
     *   PDR lookup
     *   FAR action
     *   QER policing
     *   URR accounting
     *   decapsulation
     *   NAT/routing
     *   transmit N6
     *
     * O-RAN:
     *
     *   identify TEID / UE / DRB
     *   GTP-U decap
     *   PDCP ingress
     *   RLC ingress
     *   QoS queue
     *   scheduler interface
     */

    (void)packet;

    w->packets++;
    w->bytes += len;
}


int main(int argc, char **argv)
{
    struct worker w = {};

    struct xsk_umem_config ucfg = {
        .fill_size      = NUM_FRAMES,
        .comp_size      = NUM_FRAMES,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };

    struct xsk_socket_config xcfg = {
        .rx_size      = RX_SIZE,
        .tx_size      = 0,

        /*
         * We already loaded our custom XDP program.
         * Do not let libxdp install another one.
         */
        .libbpf_flags =
            XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,

        .xdp_flags = 0,

        .bind_flags =
            XDP_USE_NEED_WAKEUP
    };

    const char *ifname;
    const char *xsk_map_path;
    const char *binding_map_path;

    uint32_t queue;
    uint32_t slot;

    uint32_t idx;

    size_t buffer_size =
        NUM_FRAMES * FRAME_SIZE;

    int ret;

    if (argc != 6) {
        fprintf(stderr,
            "Usage:\n"
            "%s <ifname> <queue> <slot> "
            "<xsks_map> <queue_to_slot>\n",
            argv[0]);

        return 1;
    }

    ifname = argv[1];

    queue = strtoul(argv[2], NULL, 0);
    slot  = strtoul(argv[3], NULL, 0);

    xsk_map_path = argv[4];
    binding_map_path = argv[5];

    raise_memlock();

    /*
     * UMEM must be suitably aligned.
     */
    ret = posix_memalign(
        &w.buffer,
        getpagesize(),
        buffer_size);

    if (ret) {
        fprintf(stderr,
                "posix_memalign failed\n");
        return 1;
    }

    memset(w.buffer, 0, buffer_size);

    ret = xsk_umem__create(
        &w.umem,
        w.buffer,
        buffer_size,
        &w.fill,
        &w.comp,
        &ucfg);

    if (ret) {
        fprintf(stderr,
                "xsk_umem__create: %s\n",
                strerror(-ret));
        return 1;
    }

    /*
     * Create an RX-only AF_XDP socket.
     */
    ret = xsk_socket__create(
        &w.xsk,
        ifname,
        queue,
        w.umem,
        &w.rx,
        NULL,
        &xcfg);

    if (ret) {
        fprintf(stderr,
                "xsk_socket__create: %s\n",
                strerror(-ret));
        return 1;
    }

    /*
     * Initially populate the fill ring with all UMEM frames.
     */
    while (xsk_ring_prod__reserve(
               &w.fill,
               NUM_FRAMES,
               &idx) != NUM_FRAMES) {
        usleep(100);
    }

    for (uint32_t i = 0;
         i < NUM_FRAMES;
         i++) {

        *xsk_ring_prod__fill_addr(
            &w.fill,
            idx + i) =
                (uint64_t)i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(
        &w.fill,
        NUM_FRAMES);

    ret = register_xsk(
        xsk_map_path,
        binding_map_path,
        ifname,
        queue,
        slot,
        xsk_socket__fd(w.xsk));

    if (ret) {
        fprintf(stderr,
                "Cannot register XSK\n");
        return 1;
    }

    printf(
        "AF_XDP worker started: %s queue=%u slot=%u\n",
        ifname,
        queue,
        slot);

    struct pollfd pfd = {
        .fd = xsk_socket__fd(w.xsk),
        .events = POLLIN
    };

    for (;;) {

        uint32_t rx_index;

        unsigned int received =
            xsk_ring_cons__peek(
                &w.rx,
                BATCH_SIZE,
                &rx_index);

        if (!received) {

            poll(&pfd, 1, 100);

            continue;
        }

        uint64_t recycle[BATCH_SIZE];

        for (unsigned int i = 0;
             i < received;
             i++) {

            const struct xdp_desc *desc;

            uint64_t base_addr;
            uint64_t data_addr;

            void *packet;

            desc =
                xsk_ring_cons__rx_desc(
                    &w.rx,
                    rx_index + i);

            base_addr =
                xsk_umem__extract_addr(
                    desc->addr);

            data_addr =
                xsk_umem__add_offset_to_addr(
                    desc->addr);

            packet =
                xsk_umem__get_data(
                    w.buffer,
                    data_addr);

            process_packet(
                &w,
                packet,
                desc->len);

            recycle[i] = base_addr;
        }

        xsk_ring_cons__release(
            &w.rx,
            received);

        uint32_t fill_index;

        while (xsk_ring_prod__reserve(
                   &w.fill,
                   received,
                   &fill_index) != received) {

            usleep(10);
        }

        for (unsigned int i = 0;
             i < received;
             i++) {

            *xsk_ring_prod__fill_addr(
                &w.fill,
                fill_index + i) =
                    recycle[i];
        }

        xsk_ring_prod__submit(
            &w.fill,
            received);

        if ((w.packets & 0xfffff) == 0) {

            printf(
                "packets=%llu bytes=%llu\n",
                (unsigned long long)w.packets,
                (unsigned long long)w.bytes);
        }
    }
}
