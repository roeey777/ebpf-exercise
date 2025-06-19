#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
// #include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

struct tcp_key_t {
	u32 pid;
};

struct tcp_value_t {
	u32 packet_size;
};

// accessible via BPF instance b like this: b.get_map("tcp_outboud_map")
BPF_HASH(tcp_outboud_map, struct tcp_key_t, struct tcp_value_t);

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe__tcp_sendmsg, struct pt_regs *ctx)
{
	struct tcp_value_t empty = {};
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	int packet_size = PT_REGS_RC(ctx);

	struct tcp_key_t key = {
		.pid = pid
	};

	struct tcp_value_t *value = tcp_outboud_map.lookup_or_init(&key, &empty);

	value->packet_size = packet_size;

	tcp_outboud_map.update(&key, &value);

	return 0;
}
