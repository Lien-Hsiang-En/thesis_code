#include "common.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
    (void)skb;
    return TC_ACT_OK;
}
