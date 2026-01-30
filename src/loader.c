// This program loads the TC BPF program, attaches it to container veth
// interfaces, and manages the container_map entries.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tc_redirect.skel.h"

#define PIN_PATH "/sys/fs/bpf/tc_redirect"
#define CONTAINER_MAP_PIN PIN_PATH "/container_map"
#define STATS_MAP_PIN PIN_PATH "/stats_map"

// Print libbpf errors
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// Increase RLIMIT_MEMLOCK for BPF maps
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return -1;
    }
    return 0;
}

// Attach TC BPF program to interface
static int attach_tc_prog(int prog_fd, const char *ifname)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .attach_point = BPF_TC_INGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd,
    );
    int err;

    hook.ifindex = if_nametoindex(ifname);
    if (!hook.ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", 
                ifname, strerror(errno));
        return -1;
    }

    // Create clsact qdisc
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook for %s: %s\n",
                ifname, strerror(-err));
        return err;
    }

    // Attach BPF program
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC prog to %s: %s\n",
                ifname, strerror(-err));
        return err;
    }

    printf("Attached TC BPF program to %s (ifindex %d)\n", 
           ifname, hook.ifindex);
    
    return 0;
}

// Detach TC BPF program from interface
static int detach_tc_prog(const char *ifname)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .attach_point = BPF_TC_INGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts);

    hook.ifindex = if_nametoindex(ifname);
    if (!hook.ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s\n", ifname);
        return -1;
    }

    // Detach and destroy
    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);

    printf("Detached TC BPF program from %s\n", ifname);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [args...]\n", prog);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  attach <iface>    Attach BPF program to interface\n");
    fprintf(stderr, "  detach <iface>    Detach BPF program from interface\n");
    fprintf(stderr, "  cleanup           Remove pinned maps\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s attach veth1234567\n", prog);
    fprintf(stderr, "  %s detach veth1234567\n", prog);
}

int main(int argc, char **argv)
{
    struct tc_redirect_bpf *skel = NULL;
    int err = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK
    if (bump_memlock_rlimit()) {
        return 1;
    }

    if (strcmp(argv[1], "attach") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s attach <iface>\n", argv[0]);
            return 1;
        }

        // Open and load BPF skeleton
        skel = tc_redirect_bpf__open_and_load();
        if (!skel) {
            fprintf(stderr, "Failed to open and load BPF skeleton\n");
            return 1;
        }

        // Create pin directory
        mkdir(PIN_PATH, 0755);

        // Pin maps for persistence
        err = bpf_map__pin(skel->maps.container_map, CONTAINER_MAP_PIN);
        if (err && err != -EEXIST) {
            fprintf(stderr, "Failed to pin container_map: %s\n", strerror(-err));
            goto cleanup;
        }
        
        err = bpf_map__pin(skel->maps.stats_map, STATS_MAP_PIN);
        if (err && err != -EEXIST) {
            fprintf(stderr, "Failed to pin stats_map: %s\n", strerror(-err));
            goto cleanup;
        }
        
        printf("Maps pinned at %s\n", PIN_PATH);

        // Attach to interface
        int prog_fd = bpf_program__fd(skel->progs.tc_redirect);
        err = attach_tc_prog(prog_fd, argv[2]);

cleanup:
        tc_redirect_bpf__destroy(skel);
        return err ? 1 : 0;
    }
    else if (strcmp(argv[1], "detach") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s detach <iface>\n", argv[0]);
            return 1;
        }
        return detach_tc_prog(argv[2]) ? 1 : 0;
    }
    else if (strcmp(argv[1], "cleanup") == 0) {
        unlink(CONTAINER_MAP_PIN);
        unlink(STATS_MAP_PIN);
        rmdir(PIN_PATH);
        printf("Cleaned up pinned maps\n");
        return 0;
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        usage(argv[0]);
        return 1;
    }
}