#!/usr/bin/env python

import time

from datetime import datetime

from bcc import BPF


SLEEP_INTERVAL = 1
BPF_FILENAME = "exercise.bpf.c"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def main():
    with open("BPF_FILENAME", "rt") as f:
        bpf_code = f.read()

    b = BPF(text=bpf_code)

    b.attach_kretprobe(event="tcp_sendmsg", fn_name="kretprobe__tcp_sendmsg")

    while True:
        try:
            time.sleep(SLEEP_INTERVAL)

            now = datetime.now()
            formatted_time = now.strftime(TIME_FORMAT)

            # for key, value in b.get_table("tcp_outboud_map"):  # get_table seems depracted
            for key, value in b["tcp_outboud_map"]:
                print(f"At time: {formatted_time} - pid: {pid} sent {value.packet_size} bytes")

        except KeyboardInterrupt:
            print("Exiting")
            break
