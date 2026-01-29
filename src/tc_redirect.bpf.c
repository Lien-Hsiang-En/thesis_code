#include "common.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);            // ingress ifindex
    __type(value, struct stats);   // per-cpu stats
} stats_map SEC(".maps");

static void update_stats(__u32 ifindex, __u32 bytes, bool redirected)
{
    struct stats *s = bpf_map_lookup_elem(&stats_map, &ifindex);
    if (!s) {
        struct stats init = {};
        init.packets = 1;
        init.bytes = bytes;
        init.redirected = redirected ? 1 : 0;
        init.passed = redirected ? 0 : 1;
        bpf_map_update_elem(&stats_map, &ifindex, &init, BPF_ANY);
        return;
    }

    s->packets += 1;
    s->bytes += bytes;
    if (redirected) s->redirected += 1;
    else s->passed += 1;
}

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
    (void)skb;
    update_stats(skb->ifindex, skb->len, false);
    return TC_ACT_OK;
}
