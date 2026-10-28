#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "upf_monitor_tc_kernel.skel.h"

#define IFACE        "eth0"
#define PIN_PATH     "/sys/fs/bpf/tc/upf_tc_prog"

struct pkt_event {
    __u64 timestamp_ns;
    __u64 iat_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __u16 ip_id;
    __u16 gtp_seq;
};

#define MAX_FLOWS 1024

struct flow_stats {
    __u32  src_ip;
    __u32  dst_ip;
    __u64  bytes;
    __u64  packets;
    __u64  jitter_sum_ns;
    __u64  jitter_count;
    __u64  lost_interval;
    __u16  last_ip_id;
    __u16  last_gtp_seq;
    int    has_prev;
    __u64  lost_total;
    int    use_gtp_seq;
};

static struct flow_stats flows[MAX_FLOWS];
static int flow_count = 0;

static struct flow_stats *get_flow(__u32 src_ip, __u32 dst_ip) {
    for (int i = 0; i < flow_count; i++)
        if (flows[i].src_ip == src_ip && flows[i].dst_ip == dst_ip)
            return &flows[i];
    if (flow_count >= MAX_FLOWS) return NULL;
    struct flow_stats *f = &flows[flow_count++];
    memset(f, 0, sizeof(*f));
    f->src_ip = src_ip;
    f->dst_ip = dst_ip;
    return f;
}

static __u64 now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static __u64 last_print_ms = 0;
#define PRINT_INTERVAL_MS 1000

static void print_and_reset(void) {
    int printed = 0;

    for (int i = 0; i < flow_count; i++) {
        struct flow_stats *f = &flows[i];
        if (f->packets == 0 && f->lost_interval == 0) continue;

        if (!printed) {
            printf("\n%-15s %-15s %10s %8s %12s %6s %6s %8s\n",
                   "SRC_IP","DST_IP","Mbps","Pkts","Jitter(ms)","Lost","LostÎ£","Loss%");
            printf("%-15s %-15s %10s %8s %12s %6s %6s %8s\n",
                   "---------------","---------------","----------",
                   "--------","------------","------","------","--------");
            printed = 1;
        }

        struct in_addr sa = { .s_addr = f->src_ip };
        struct in_addr da = { .s_addr = f->dst_ip };
        char src_str[16], dst_str[16];
        strncpy(src_str, inet_ntoa(sa), 15); src_str[15] = '\0';
        sa.s_addr = f->dst_ip;
        strncpy(dst_str, inet_ntoa(da), 15); dst_str[15] = '\0';

        double mbps      = (f->bytes * 8.0) / 1000000.0;
        double jitter_ms = 0.0;
        if (f->jitter_count > 0)
            jitter_ms = (f->jitter_sum_ns / (double)f->jitter_count) / 1e6;

        __u64 total_expected = f->packets + f->lost_interval;
        double loss_pct = total_expected > 0
            ? (f->lost_interval * 100.0) / total_expected : 0.0;

        printf("%-15s %-15s %9.2fM %8llu %11.3f %6llu %6llu %7.2f%%\n",
               src_str, dst_str, mbps,
               (unsigned long long)f->packets, jitter_ms,
               (unsigned long long)f->lost_interval,
               (unsigned long long)f->lost_total, loss_pct);

        f->bytes = f->packets = f->jitter_sum_ns = f->jitter_count = f->lost_interval = 0;
    }

    if (!printed)
        printf("(nenhum fluxo GTP-U detectado no Ãºltimo intervalo)\n");
}

static __u64 seq_gap(__u16 prev, __u16 cur) {
    __u16 diff = (__u16)(cur - prev);
    if (diff == 0) return 0;
    return (__u64)(diff - 1);
}

static void update_loss(struct flow_stats *f, __u16 ip_id, __u16 gtp_seq) {
    if (!f->has_prev) {
        f->last_ip_id = ip_id; f->last_gtp_seq = gtp_seq;
        f->use_gtp_seq = (gtp_seq != 0); f->has_prev = 1;
        return;
    }
    __u64 gap;
    if (f->use_gtp_seq && gtp_seq != 0) {
        gap = seq_gap(f->last_gtp_seq, gtp_seq);
        f->last_gtp_seq = gtp_seq;
    } else {
        gap = seq_gap(f->last_ip_id, ip_id);
        f->last_ip_id = ip_id;
    }
    f->lost_interval += gap;
    f->lost_total    += gap;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    if (data_sz < sizeof(struct pkt_event)) return;
    struct pkt_event *evt = (struct pkt_event *)data;
    struct flow_stats *f  = get_flow(evt->src_ip, evt->dst_ip);
    if (!f) return;

    f->bytes   += evt->pkt_len;
    f->packets += 1;
    if (evt->iat_ns > 0) { f->jitter_sum_ns += evt->iat_ns; f->jitter_count++; }
    update_loss(f, evt->ip_id, evt->gtp_seq);

    __u64 now = now_ms();
    if (last_print_ms == 0) last_print_ms = now;
    if ((now - last_print_ms) >= PRINT_INTERVAL_MS) {
        print_and_reset();
        last_print_ms = now;
    }
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "[AVISO] %llu eventos perdidos na CPU %d\n",
            (unsigned long long)lost_cnt, cpu);
}

static int tc_attach(int prog_fd, const char *iface) {
    char cmd[512];
    int ret;

    unlink(PIN_PATH);
    if (bpf_obj_pin(prog_fd, PIN_PATH) < 0) {
        fprintf(stderr, "Falha ao pinar programa BPF em %s: %s\n",
                PIN_PATH, strerror(errno));
        fprintf(stderr, "Verifique se /sys/fs/bpf estÃ¡ montado e o path existe.\n");
        return -1;
    }
    fprintf(stderr, "Programa pinado em %s\n", PIN_PATH);

    snprintf(cmd, sizeof(cmd),
             "tc qdisc add dev %s clsact 2>/dev/null; true", iface);
    system(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc filter add dev %s ingress "
             "bpf direct-action pinned %s",
             iface, PIN_PATH);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Falha ao adicionar filtro TC (cÃ³digo %d)\n", ret);
        unlink(PIN_PATH);
        return -1;
    }
    return 0;
}

static void tc_detach(const char *iface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "tc qdisc del dev %s clsact 2>/dev/null; true", iface);
    system(cmd);
    unlink(PIN_PATH);
    fprintf(stderr, "TC hook removido de %s.\n", iface);
}

static volatile int running = 1;
static void sig_handler(int sig) { running = 0; }

int main(int argc, char **argv) {
    struct upf_monitor_tc_kernel *skel = NULL;
    struct perf_buffer *pb             = NULL;
    int err = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    skel = upf_monitor_tc_kernel__open_and_load();
    if (!skel) {
        fprintf(stderr, "Falha ao carregar skeleton BPF\n");
        return 1;
    }

    if (!if_nametoindex(IFACE)) {
        fprintf(stderr, "Interface %s nÃ£o encontrada: %s\n", IFACE, strerror(errno));
        err = 1; goto cleanup;
    }

    if (tc_attach(bpf_program__fd(skel->progs.tc_upf_monitor), IFACE) < 0) {
        err = 1; goto cleanup;
    }

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost,
        .ctx       = NULL,
    };
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, &pb_opts);
    if (!pb) {
        fprintf(stderr, "Falha ao criar perf buffer\n");
        err = 1; goto cleanup_tc;
    }

    printf("Monitoramento eBPF iniciado (perf_buffer | TC ingress | %s)\n", IFACE);
    printf("Intervalo: %dms | Ctrl+C para encerrar\n\n", PRINT_INTERVAL_MS);

    last_print_ms = now_ms();
    while (running) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Erro no poll: %d\n", err);
            break;
        }
        __u64 now = now_ms();
        if ((now - last_print_ms) >= PRINT_INTERVAL_MS) {
            print_and_reset();
            last_print_ms = now;
        }
    }

    print_and_reset();

cleanup_tc:
    tc_detach(IFACE);
cleanup:
    perf_buffer__free(pb);
    upf_monitor_tc_kernel__destroy(skel);
    return err < 0 ? -err : err;
}