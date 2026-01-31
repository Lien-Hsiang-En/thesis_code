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

// Add container to map
static int add_container(int map_fd, const char *ip_str, const char *ifname)
{
    struct in_addr addr;
    __u32 ifindex;

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                ifname, strerror(errno));
        return -1;
    }

    if (bpf_map_update_elem(map_fd, &addr.s_addr, &ifindex, BPF_ANY)) {
        fprintf(stderr, "Failed to add container to map: %s\n",
                strerror(errno));
        return -1;
    }

    printf("Added container: %s -> %s (ifindex %u)\n", ip_str, ifname, ifindex);
    return 0;
}

// Remove container from map
static int del_container(int map_fd, const char *ip_str)
{
    struct in_addr addr;

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }

    if (bpf_map_delete_elem(map_fd, &addr.s_addr)) {
        fprintf(stderr, "Failed to delete container from map: %s\n",
                strerror(errno));
        return -1;
    }

    printf("Deleted container: %s\n", ip_str);
    return 0;
}

// List all containers in map
static void list_containers(int map_fd)
{
    __be32 key, next_key;
    __u32 value;
    char ip_str[INET_ADDRSTRLEN];
    char ifname[IF_NAMESIZE];

    printf("\nContainer Map Contents:\n");
    printf("%-20s %-20s %s\n", "IP Address", "Interface", "ifindex");
    printf("%-20s %-20s %s\n", "----------", "---------", "-------");

    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str));
            if (if_indextoname(value, ifname) == NULL)
                snprintf(ifname, sizeof(ifname), "unknown");
            printf("%-20s %-20s %u\n", ip_str, ifname, value);
        }
        key = next_key;
    }
    printf("\n");
}

// Print statistics
static void print_stats(int stats_map_fd)
{
    __u32 key, next_key;
    int num_cpus = libbpf_num_possible_cpus();
    char ifname[IF_NAMESIZE];
    
    if (num_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs\n");
        return;
    }

    struct {
        __u64 packets;
        __u64 bytes;
        __u64 redirected;
        __u64 passed;
    } *values;
    
    values = calloc(num_cpus, sizeof(*values));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for stats\n");
        return;
    }

    printf("\nStatistics:\n");
    printf("%-10s %-16s %-15s %-15s %-15s %-15s\n", 
           "ifindex", "Interface", "Packets", "Bytes", "Redirected", "Passed");
    printf("%-10s %-16s %-15s %-15s %-15s %-15s\n",
           "-------", "---------", "-------", "-----", "----------", "------");

    key = 0;
    while (bpf_map_get_next_key(stats_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(stats_map_fd, &next_key, values) == 0) {
            // Aggregate stats from all CPUs
            __u64 total_packets = 0, total_bytes = 0;
            __u64 total_redirected = 0, total_passed = 0;
            
            for (int i = 0; i < num_cpus; i++) {
                total_packets += values[i].packets;
                total_bytes += values[i].bytes;
                total_redirected += values[i].redirected;
                total_passed += values[i].passed;
            }
            
            if (if_indextoname(next_key, ifname) == NULL)
                snprintf(ifname, sizeof(ifname), "unknown");
            
            printf("%-10u %-16s %-15llu %-15llu %-15llu %-15llu\n",
                   next_key, ifname, total_packets, total_bytes,
                   total_redirected, total_passed);
        }
        key = next_key;
    }
    printf("\n");
    free(values);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [args...]\n", prog);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  attach <iface>           Attach BPF program to interface\n");
    fprintf(stderr, "  detach <iface>           Detach BPF program from interface\n");
    fprintf(stderr, "  add <ip> <iface>         Add container mapping\n");
    fprintf(stderr, "  del <ip>                 Delete container mapping\n");
    fprintf(stderr, "  list                     List all container mappings\n");
    fprintf(stderr, "  stats                    Show statistics\n");
    fprintf(stderr, "  cleanup                  Remove pinned maps\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s attach veth1234567\n", prog);
    fprintf(stderr, "  %s add 172.17.0.2 veth1234567\n", prog);
}

int main(int argc, char **argv)
{
    struct tc_redirect_bpf *skel = NULL;
    int err = 0;
    int container_map_fd = -1;
    int stats_map_fd = -1;

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

    // attach command: load BPF and pin maps (or reuse existing)
    if (strcmp(argv[1], "attach") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s attach <iface>\n", argv[0]);
            return 1;
        }

        // Check if maps already exist (pinned by previous attach)
        int existing_container_map = bpf_obj_get(CONTAINER_MAP_PIN);
        int existing_stats_map = bpf_obj_get(STATS_MAP_PIN);
        
        if (existing_container_map >= 0 && existing_stats_map >= 0) {
            // Maps exist, reuse them
            printf("Reusing existing pinned maps\n");
            
            skel = tc_redirect_bpf__open();
            if (!skel) {
                fprintf(stderr, "Failed to open BPF skeleton\n");
                close(existing_container_map);
                close(existing_stats_map);
                return 1;
            }
            
            // Reuse existing maps
            err = bpf_map__reuse_fd(skel->maps.container_map, existing_container_map);
            if (err) {
                fprintf(stderr, "Failed to reuse container_map: %s\n", strerror(-err));
                goto cleanup_attach;
            }
            
            err = bpf_map__reuse_fd(skel->maps.stats_map, existing_stats_map);
            if (err) {
                fprintf(stderr, "Failed to reuse stats_map: %s\n", strerror(-err));
                goto cleanup_attach;
            }
            
            // Now load with reused maps
            err = tc_redirect_bpf__load(skel);
            if (err) {
                fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-err));
                goto cleanup_attach;
            }
            
            close(existing_container_map);
            close(existing_stats_map);
        } else {
            // First time, create new maps
            if (existing_container_map >= 0) close(existing_container_map);
            if (existing_stats_map >= 0) close(existing_stats_map);
            
            skel = tc_redirect_bpf__open_and_load();
            if (!skel) {
                fprintf(stderr, "Failed to open and load BPF skeleton\n");
                return 1;
            }

            // Create pin directory
            mkdir(PIN_PATH, 0755);

            // Pin maps
            err = bpf_map__pin(skel->maps.container_map, CONTAINER_MAP_PIN);
            if (err && err != -EEXIST) {
                fprintf(stderr, "Failed to pin container_map: %s\n", strerror(-err));
                goto cleanup_attach;
            }
            
            err = bpf_map__pin(skel->maps.stats_map, STATS_MAP_PIN);
            if (err && err != -EEXIST) {
                fprintf(stderr, "Failed to pin stats_map: %s\n", strerror(-err));
                goto cleanup_attach;
            }
            
            printf("Maps pinned at %s\n", PIN_PATH);
        }

        int prog_fd = bpf_program__fd(skel->progs.tc_redirect);
        err = attach_tc_prog(prog_fd, argv[2]);
        
cleanup_attach:
        tc_redirect_bpf__destroy(skel);
        return err ? 1 : 0;
    }
    
    // For other commands: use pinned maps
    container_map_fd = bpf_obj_get(CONTAINER_MAP_PIN);
    stats_map_fd = bpf_obj_get(STATS_MAP_PIN);

    if (strcmp(argv[1], "detach") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s detach <iface>\n", argv[0]);
            err = 1;
            goto cleanup;
        }
        err = detach_tc_prog(argv[2]);
    }
    else if (strcmp(argv[1], "add") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s add <ip> <iface>\n", argv[0]);
            err = 1;
            goto cleanup;
        }
        if (container_map_fd < 0) {
            fprintf(stderr, "BPF maps not found. Run 'attach' first.\n");
            err = 1;
            goto cleanup;
        }
        err = add_container(container_map_fd, argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "del") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s del <ip>\n", argv[0]);
            err = 1;
            goto cleanup;
        }
        if (container_map_fd < 0) {
            fprintf(stderr, "BPF maps not found. Run 'attach' first.\n");
            err = 1;
            goto cleanup;
        }
        err = del_container(container_map_fd, argv[2]);
    }
    else if (strcmp(argv[1], "list") == 0) {
        if (container_map_fd < 0) {
            fprintf(stderr, "BPF maps not found. Run 'attach' first.\n");
            err = 1;
            goto cleanup;
        }
        list_containers(container_map_fd);
    }
    else if (strcmp(argv[1], "stats") == 0) {
        if (stats_map_fd < 0) {
            fprintf(stderr, "BPF maps not found. Run 'attach' first.\n");
            err = 1;
            goto cleanup;
        }
        print_stats(stats_map_fd);
    }
    else if (strcmp(argv[1], "cleanup") == 0) {
        unlink(CONTAINER_MAP_PIN);
        unlink(STATS_MAP_PIN);
        rmdir(PIN_PATH);
        printf("Cleaned up pinned maps\n");
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        usage(argv[0]);
        err = 1;
    }

cleanup:
    if (container_map_fd >= 0) close(container_map_fd);
    if (stats_map_fd >= 0) close(stats_map_fd);
    return err ? 1 : 0;
}