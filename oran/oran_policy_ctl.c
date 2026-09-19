#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>

#include <bpf/bpf.h>

#define DRB_ACCEL (1U << 0)
#define DRB_DROP  (1U << 1)

struct drb_policy {
    __u32 flags;

    __u16 slice_id;
    __u8 priority;
    __u8 qos_class;

    __u32 worker_id;
};

int main(int argc, char **argv)
{
    int fd;

    __u32 teid;

    struct drb_policy p = {};

    if (argc != 7) {
        fprintf(stderr,
            "Usage:\n"
            "%s <map> <teid> accel|drop "
            "<slice> <priority> <worker>\n",
            argv[0]);

        return 1;
    }

    fd = bpf_obj_get(argv[1]);

    if (fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    teid = strtoul(argv[2], NULL, 0);

    if (!strcmp(argv[3], "accel"))
        p.flags = DRB_ACCEL;
    else
        p.flags = DRB_DROP;

    p.slice_id =
        strtoul(argv[4], NULL, 0);

    p.priority =
        strtoul(argv[5], NULL, 0);

    p.worker_id =
        strtoul(argv[6], NULL, 0);

    if (bpf_map_update_elem(
            fd,
            &teid,
            &p,
            BPF_ANY)) {

        perror("bpf_map_update_elem");
        return 1;
    }

    printf(
        "TEID=%u slice=%u priority=%u worker=%u installed\n",
        teid,
        p.slice_id,
        p.priority,
        p.worker_id);

    return 0;
}
