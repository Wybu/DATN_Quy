// src/monitor.c
#ifndef BPF_WQ_FIX
#define BPF_WQ_FIX
struct bpf_wq {
    unsigned long raw;
};
#endif

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* * DEFINITION: Cau truc du lieu gui len User Space (Feature Vector)
 * Cau truc nay phai khop (aligned) voi cau truc ben Python
 */
struct packet_data_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 len;            // Feature: Kich thuoc goi
    u8  proto;          // Feature: Giao thuc (6=TCP, 17=UDP)
    u8  tcp_flags;      // Feature: Cac co TCP (SYN, ACK, FIN...) - Quan trong nhat cho ML
    u64 timestamp;      // Feature: Thoi gian (nanoseconds)
};

// Kenh truyen du lieu toc do cao (Perf Ring Buffer)
BPF_PERF_OUTPUT(events);

/*
 * MAIN PROGRAM: XDP Hook
 */
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Khoi tao struct du lieu
    struct packet_data_t pkt = {};
    pkt.timestamp = bpf_ktime_get_ns(); // Lay thoi gian chuan kernel

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) return XDP_PASS;

    // Chi xu ly goi tin IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) return XDP_PASS;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto  = ip->protocol;
    pkt.len    = bpf_ntohs(ip->tot_len); // Do dai goi tin IP

    // 3. Parse Layer 4 (Transport)
    if (pkt.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
            pkt.src_port = bpf_ntohs(tcp->source);
            pkt.dst_port = bpf_ntohs(tcp->dest);
            
            // KY THUAT QUAN TRONG: Lay TCP Flags
            // TCP Flags nam o offset 13 (byte thu 13) cua TCP Header
            // Ep kieu ve u8* de lay chinh xac 8 bit co
            u8 *flags_ptr = ((u8 *)tcp) + 13; 
            pkt.tcp_flags = *flags_ptr;
        }
    } 
    else if (pkt.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            pkt.src_port = bpf_ntohs(udp->source);
            pkt.dst_port = bpf_ntohs(udp->dest);
            pkt.tcp_flags = 0; // UDP khong co co
        }
    }
    // (Optional) Co the mo rong ICMP tai day

    // 4. Submit du lieu len User Space
    events.perf_submit(ctx, &pkt, sizeof(pkt));

    // XDP_PASS: Cho phep goi tin di qua (Monitoring Mode)
    // XDP_DROP: Neu muon chan
    return XDP_PASS;
}