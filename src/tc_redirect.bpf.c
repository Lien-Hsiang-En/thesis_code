// This BPF program intercepts packets at the TC layer and redirects
// inter-container traffic directly using bpf_redirect_peer(), bypassing
// the docker0 bridge and iptables processing.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------
// Constants not available in vmlinux.h (BTF doesn't include #defines)
// We must define them manually for CO-RE compatibility
// ---------------------------------------------------------------------

// From <linux/if_ether.h>
// Ethernet header size
#define ETH_HLEN 14
#define ETH_P_IP 0x0800

// From <linux/pkt_cls.h>
// TC action codes
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_REDIRECT 7

// Statistics structure for monitoring
struct stats {
    __u64 packets;
    __u64 bytes;
    __u64 redirected;
    __u64 passed;
};

// ---------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------

// Container IP -> veth ifindex mapping
// Key: Container IP address (network byte order)
// Value: Target veth interface index (host side)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, __u32);
} container_map SEC(".maps");

// Per-interface statistics (using PERCPU for lock-free updates)
// Key: Interface index
// Value: Statistics counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

// TC BPF program entry point (skeleton for now)
SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Validate IP header length (minimum 5 * 4 = 20 bytes)
    if (ip->ihl < 5)
        return TC_ACT_OK;
    
    // Calculate actual IP header length (for packets with options)
    __u32 ip_hlen = ip->ihl * 4;
    if ((void *)ip + ip_hlen > data_end)
        return TC_ACT_OK;
    
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
