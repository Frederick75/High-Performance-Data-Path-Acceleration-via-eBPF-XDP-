#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <unistd.h>

#include <net/if.h>

#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int attach_program(
        const char *object_file,
        const char *ifname,
        const char *pin_dir)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;

    int ifindex;
    int err;

    char path[512];

    ifindex = if_nametoindex(ifname);

    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    mkdir(pin_dir, 0755);

    obj = bpf_object__open_file(
        object_file,
        NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr,
                "Cannot open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr,
                "BPF load failed: %d\n",
                err);
        return 1;
    }

    /*
     * Pin maps for:
     *
     * policy manager
     * AF_XDP worker
     * telemetry process
     */
    bpf_object__for_each_map(map, obj) {

        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            pin_dir,
            bpf_map__name(map));

        unlink(path);

        err = bpf_map__pin(map, path);

        if (err) {
            fprintf(stderr,
                    "Cannot pin map %s: %d\n",
                    path,
                    err);

            return 1;
        }
    }

    prog = bpf_object__next_program(
        obj,
        NULL);

    if (!prog) {
        fprintf(stderr,
                "No XDP program\n");
        return 1;
    }

    /*
     * Try native/driver XDP first.
     */
    err = bpf_xdp_attach(
        ifindex,
        bpf_program__fd(prog),
        XDP_FLAGS_DRV_MODE,
        NULL);

    if (err) {

        fprintf(stderr,
            "Native XDP unavailable; "
            "trying generic XDP\n");

        err = bpf_xdp_attach(
            ifindex,
            bpf_program__fd(prog),
            XDP_FLAGS_SKB_MODE,
            NULL);
    }

    if (err) {
        fprintf(stderr,
                "XDP attach failed: %d\n",
                err);
        return 1;
    }

    printf(
        "XDP attached to %s; maps pinned at %s\n",
        ifname,
        pin_dir);

    bpf_object__close(obj);

    return 0;
}


static int detach_program(const char *ifname)
{
    int ifindex =
        if_nametoindex(ifname);

    if (!ifindex)
        return 1;

    bpf_xdp_detach(
        ifindex,
        XDP_FLAGS_DRV_MODE,
        NULL);

    bpf_xdp_detach(
        ifindex,
        XDP_FLAGS_SKB_MODE,
        NULL);

    return 0;
}


int main(int argc, char **argv)
{
    if (argc >= 2 &&
        !strcmp(argv[1], "detach")) {

        if (argc != 3)
            return 1;

        return detach_program(argv[2]);
    }

    if (argc != 5 ||
        strcmp(argv[1], "attach")) {

        fprintf(stderr,
            "Usage:\n"
            "%s attach <object.o> <interface> <pin-dir>\n"
            "%s detach <interface>\n",
            argv[0],
            argv[0]);

        return 1;
    }

    return attach_program(
        argv[2],
        argv[3],
        argv[4]);
}
