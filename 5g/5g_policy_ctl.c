#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <linux/types.h>

#include <bpf/bpf.h>

#define ROLE_N3      1
#define ROLE_N6      2

#define POLICY_ACCEL (1U << 0)
#define POLICY_DROP  (1U << 1)

struct upf_policy {
    __u32 flags;
    __u32 qos_profile;
    __u32 far_id;
    __u32 reserved;
};

static __u32 parse_action(const char *s)
{
    if (!strcmp(s, "accel"))
        return POLICY_ACCEL;

    if (!strcmp(s, "drop"))
        return POLICY_DROP;

    fprintf(stderr, "Unknown action: %s\n", s);
    exit(EXIT_FAILURE);
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s role <map> <interface> n3|n6\n"
        "  %s teid <map> <TEID> accel|drop\n"
        "  %s ue   <map> <IPv4> accel|drop\n",
        p, p, p);
}

int main(int argc, char **argv)
{
    int fd;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "role")) {

        __u32 ifindex;
        __u32 role;

        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }

        fd = bpf_obj_get(argv[2]);

        if (fd < 0) {
            perror("bpf_obj_get");
            return 1;
        }

        ifindex = if_nametoindex(argv[3]);

        if (!ifindex) {
            perror("if_nametoindex");
            return 1;
        }

        role = !strcmp(argv[4], "n3")
             ? ROLE_N3
             : ROLE_N6;

        if (bpf_map_update_elem(fd,
                                &ifindex,
                                &role,
                                BPF_ANY)) {
            perror("bpf_map_update_elem");
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "teid")) {

        __u32 teid;
        struct upf_policy policy = {};

        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }

        fd = bpf_obj_get(argv[2]);

        teid = strtoul(argv[3], NULL, 0);
        policy.flags = parse_action(argv[4]);

        if (bpf_map_update_elem(fd,
                                &teid,
                                &policy,
                                BPF_ANY)) {
            perror("update TEID");
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "ue")) {

        struct in_addr ip;
        struct upf_policy policy = {};

        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }

        fd = bpf_obj_get(argv[2]);

        if (inet_pton(AF_INET, argv[3], &ip) != 1) {
            fprintf(stderr, "Invalid IP\n");
            return 1;
        }

        policy.flags = parse_action(argv[4]);

        if (bpf_map_update_elem(fd,
                                &ip.s_addr,
                                &policy,
                                BPF_ANY)) {
            perror("update UE");
            return 1;
        }

        return 0;
    }

    usage(argv[0]);
    return 1;
}
