#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#define ETH_P_IP      0x0800
#define IPPROTO_UDP   17
#define GTPU_UDP_PORT 2152

struct pkt_event {
    __u64 timestamp_ns;
    __u64 iat_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __u16 ip_id;
    __u16 gtp_seq;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} last_seen_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("classifier")
int tc_upf_monitor(struct __sk_buff *skb) {
    __u32 offset = 0;

    /* --- ETHERNET --- */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, offset, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    offset += sizeof(eth);

    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- IP EXTERNO --- */
    struct iphdr ip_outer;
    if (bpf_skb_load_bytes(skb, offset, &ip_outer, sizeof(ip_outer)) < 0)
        return TC_ACT_OK;
    if (ip_outer.protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_outer_hlen = ip_outer.ihl * 4;
    if (ip_outer_hlen < 20)
        return TC_ACT_OK;
    offset += ip_outer_hlen;

    /* --- UDP EXTERNO --- */
    struct udphdr udp_outer;
    if (bpf_skb_load_bytes(skb, offset, &udp_outer, sizeof(udp_outer)) < 0)
        return TC_ACT_OK;
    if (udp_outer.dest != bpf_htons(GTPU_UDP_PORT))
        return TC_ACT_OK;
    offset += sizeof(udp_outer);

    /* --- HEADER GTP-U --- */
    __u32 gtp_start = offset;

    /* Carrega os 8 bytes fixos do header GTP */
    __u8 gtp_hdr[8];
    if (bpf_skb_load_bytes(skb, gtp_start, gtp_hdr, sizeof(gtp_hdr)) < 0)
        return TC_ACT_OK;

    __u8  gtp_flags   = gtp_hdr[0];
    __u32 gtp_hdr_len = 8;
    __u16 gtp_seq     = 0;

    if (gtp_flags & 0x07) {
        gtp_hdr_len = 12;

        /* Extrai o sequence number GTP se S=1 */
        if (gtp_flags & 0x02) {
            __u16 seq_be;
            if (bpf_skb_load_bytes(skb, gtp_start + 8, &seq_be, sizeof(seq_be)) < 0)
                return TC_ACT_OK;
            gtp_seq = bpf_ntohs(seq_be);
        }

        /* Percorre extension headers se E=1 */
        if (gtp_flags & 0x04) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                __u8 next_ext_type;
                if (bpf_skb_load_bytes(skb,
                                       gtp_start + gtp_hdr_len - 1,
                                       &next_ext_type,
                                       sizeof(next_ext_type)) < 0)
                    return TC_ACT_OK;

                if (next_ext_type == 0x00)
                    break;

                __u8 ext_len;
                if (bpf_skb_load_bytes(skb,
                                       gtp_start + gtp_hdr_len,
                                       &ext_len,
                                       sizeof(ext_len)) < 0)
                    return TC_ACT_OK;

                if (ext_len == 0)
                    return TC_ACT_OK;

                gtp_hdr_len += (__u32)ext_len * 4;
            }
        }
    }

    if (gtp_hdr_len > 64)
        return TC_ACT_OK;

    /* --- IP INTERNO (UE) --- */
    __u32 inner_ip_offset = gtp_start + gtp_hdr_len;

    struct iphdr ip_inner;
    if (bpf_skb_load_bytes(skb, inner_ip_offset, &ip_inner, sizeof(ip_inner)) < 0)
        return TC_ACT_OK;
    if (ip_inner.version != 4)
        return TC_ACT_OK;

    /* --- COLETA --- */
    __u32 src_ip  = ip_inner.saddr;
    __u32 dst_ip  = ip_inner.daddr;
    __u32 pkt_len = bpf_ntohs(ip_inner.tot_len);
    __u16 ip_id   = bpf_ntohs(ip_inner.id);
    __u64 now     = bpf_ktime_get_ns();

    __u64 iat_ns = 0;
    __u64 *last_ts = bpf_map_lookup_elem(&last_seen_map, &src_ip);
    if (last_ts)
        iat_ns = now - *last_ts;
    bpf_map_update_elem(&last_seen_map, &src_ip, &now, BPF_ANY);

    struct pkt_event evt;
    __builtin_memset(&evt, 0, sizeof(evt));
    evt.timestamp_ns = now;
    evt.iat_ns       = iat_ns;
    evt.src_ip       = src_ip;
    evt.dst_ip       = dst_ip;
    evt.pkt_len      = pkt_len;
    evt.ip_id        = ip_id;
    evt.gtp_seq      = gtp_seq;

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";