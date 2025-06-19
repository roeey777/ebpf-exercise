#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>  /* for struct sock */

#ifndef TRUE
#define TRUE 1
#endif

#define HTTP_PORT 80
#define MAX_PAYLOAD_LEN 256

struct tcp_key_t {
        u32 pid;
};

struct tcp_value_t {
        u16 family;
        u8 is_ipv4;
        __be32 ipv4_src_addr;
        __be32 ipv4_dst_addr;
        u16 src_port;
        u16 dst_port;
        u32 packet_size;
        char proc_name[TASK_COMM_LEN];
};

// accessible via BPF instance b like this: b.get_map("tcp_outboud_map")
BPF_HASH(tcp_outboud_map, struct tcp_key_t, struct tcp_value_t);

struct event_t {
        u32 pid;
        u32 packet_size;
        u8 payload[MAX_PAYLOAD_LEN + 1];
};
BPF_PERF_OUTPUT(deep_packets_inspect_events);


// SEC("kprobe/tcp_sendmsg")
// int BPF_KPROBE(kretprobe__tcp_sendmsg, struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
        struct tcp_value_t empty = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u16 dport;

        struct tcp_key_t key = {
                .pid = pid
        };

        struct tcp_value_t *value = tcp_outboud_map.lookup_or_init(&key, &empty);

        bpf_probe_read_kernel(&value->family, sizeof(value->family),  &sk->__sk_common.skc_family);
        if (value->family == AF_INET) {
                value->is_ipv4 = TRUE;
                bpf_probe_read_kernel(&value->ipv4_src_addr, sizeof(value->ipv4_src_addr),
                                        &sk->__sk_common.skc_rcv_saddr);
                bpf_probe_read_kernel(&value->ipv4_dst_addr, sizeof(value->ipv4_src_addr),
                                        &sk->__sk_common.skc_daddr);
        }

        bpf_probe_read_kernel(&value->src_port, sizeof(value->ipv4_src_addr),
                                &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport),
                                &sk->__sk_common.skc_dport);
        value->dst_port = ntohs(dport);

        value->packet_size = len;
        if (bpf_get_current_comm(&value->proc_name, TASK_COMM_LEN)) {
                bpf_trace_printk("Failed to get comm\n");
                return 0;
        }

        tcp_outboud_map.update(&key, value);

        /* suspected as HTTP, export to user-space for inspection */
        if (value->dst_port == HTTP_PORT || value->src_port == HTTP_PORT) {
                struct event_t event;
                struct iovec *iovp = NULL;
                struct iovec iov;

                bpf_probe_read_kernel(&iovp, sizeof(iovp), &msg->msg_iter.iov);
                if (!iovp) {
                        /* can't access iov data */
                        return 0;
                }

                /* read first iov data block from userspace */
                bpf_probe_read_kernel(&iov, sizeof(iov), iovp);
                size_t to_copy = iov.iov_len;
                if (to_copy > MAX_PAYLOAD_LEN) {
                        to_copy = MAX_PAYLOAD_LEN;
                }

                bpf_probe_read_user(&event.payload, to_copy, iov.iov_base);
                event.payload[MAX_PAYLOAD_LEN] = '\0';
                event.pid = pid;
                event.packet_size = to_copy;

                deep_packets_inspect_events.perf_submit(ctx, &event, sizeof(event));
        }

        return 0;
}
