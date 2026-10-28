#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define ETH_P_IP      0x0800
#define IPPROTO_UDP   17
#define GTPU_UDP_PORT 2152

/* Evento enviado ao user space por pacote */
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

SEC("xdp")
int xdp_upf_monitor(struct xdp_md *ctx) {
    void *data_end   = (void *)(long)ctx->data_end;
    void *data_start = (void *)(long)ctx->data;

    /* --- ETHERNET --- */
    struct ethhdr *eth = data_start;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    /* --- IP EXTERNO --- */
    struct iphdr *ip_outer = (void *)(eth + 1);
    if ((void *)(ip_outer + 1) > data_end) return XDP_PASS;
    if (ip_outer->protocol != IPPROTO_UDP) return XDP_PASS;

    /* --- UDP EXTERNO --- */
    struct udphdr *udp_outer = (void *)ip_outer + (ip_outer->ihl * 4);
    if ((void *)(udp_outer + 1) > data_end) return XDP_PASS;
    if (udp_outer->dest != bpf_htons(GTPU_UDP_PORT)) return XDP_PASS;

    /* --- HEADER GTP-U --- */
    void *gtp_start = (void *)(udp_outer + 1);
    if (gtp_start + 8 > data_end) return XDP_PASS;

    __u8  gtp_flags   = *(__u8 *)gtp_start;
    __u32 gtp_hdr_len = 8;
    __u16 gtp_seq     = 0;

    if (gtp_flags & 0x07) {
        gtp_hdr_len = 12;

        /* Extrai o sequence number GTP se S=1 */
        if (gtp_flags & 0x02) {
            void *seq_ptr = gtp_start + 8;
            if (seq_ptr + 2 > data_end) return XDP_PASS;
            gtp_seq = bpf_ntohs(*(__u16 *)seq_ptr);
        }

        /* Percorre extension headers se E=1 */
        if (gtp_flags & 0x04) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                void *next_ext_ptr = gtp_start + gtp_hdr_len - 1;
                if (next_ext_ptr + 1 > data_end) return XDP_PASS;

                __u8 next_ext_type = *(__u8 *)next_ext_ptr;
                if (next_ext_type == 0x00) break;

                void *ext_hdr = gtp_start + gtp_hdr_len;
                if (ext_hdr + 1 > data_end) return XDP_PASS;

                __u8 ext_len = *(__u8 *)ext_hdr;
                if (ext_len == 0) return XDP_PASS;

                gtp_hdr_len += (__u32)ext_len * 4;
            }
        }
    }

    if (gtp_hdr_len > 64) return XDP_PASS;
    if (gtp_start + gtp_hdr_len > data_end) return XDP_PASS;

    /* --- IP INTERNO (UE) --- */
    struct iphdr *ip_inner = gtp_start + gtp_hdr_len;
    if ((void *)(ip_inner + 1) > data_end) return XDP_PASS;
    if (ip_inner->version != 4) return XDP_PASS;

    /* --- COLETA --- */
    __u32 src_ip  = ip_inner->saddr;
    __u32 dst_ip  = ip_inner->daddr;
    __u32 pkt_len = bpf_ntohs(ip_inner->tot_len);
    __u16 ip_id   = bpf_ntohs(ip_inner->id);
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

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";