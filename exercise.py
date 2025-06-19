#!/usr/bin/env python

import time

from datetime import datetime
from functools import partial

from bcc import BPF


SLEEP_INTERVAL = 1
BPF_FILENAME = "exercise.bpf.c"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def print_http_pkt(cpu, data, size, b):
    event = b["deep_packets_inspect_events"].event(data)

    now = datetime.now()
    formatted_time = now.strftime(TIME_FORMAT)

    print(f"At {formatted_time} - pid: {event.pid} has sent the following data:")
    print(f"\t Raw Data: {bytearray(event.payload)}")


def main():
    with open(BPF_FILENAME, "rt") as f:
        bpf_code = f.read()

    b = BPF(text=bpf_code)

    b.attach_kprobe(event="tcp_sendmsg", fn_name="kprobe__tcp_sendmsg")
    b["deep_packets_inspect_events"].open_perf_buffer(
        partial(print_http_pkt, b=b)
    )

    while True:
        try:
            # time.sleep(SLEEP_INTERVAL)

            # timeout is in miliseconds
            b.perf_buffer_poll(timeout=SLEEP_INTERVAL * 1000)

            """
            now = datetime.now()
            formatted_time = now.strftime(TIME_FORMAT)

            # for key, value in b.get_table("tcp_outboud_map").items():  # get_table seems depracted
            for key, value in b["tcp_outboud_map"].items():
                print(f"At time: {formatted_time} - process: {str(value.proc_name)} (pid: {key.pid}):")
                print(f"\tSent {value.packet_size} bytes (Using IPv4: {bool(value.is_ipv4)})")
                if value.is_ipv4:
                    print(f"\tFrom: src ip: {value.ipv4_src_addr} and src port: {value.src_port}")
                    print(f"\tTo: dst ip: {value.ipv4_dst_addr} and dst port: {value.dst_port}")
                else:
                    print(f"\tFrom: src port: {value.src_port}")
                    print(f"\tTo: dst port: {value.dst_port}")
                print("-" * 50)  # seperator
            """

        except KeyboardInterrupt:
            print("Exiting")
            break

if __name__ == "__main__":
    main()
