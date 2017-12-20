#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import re
import struct
import socket

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.kprobe
import py2bpf.util


class CommTiming(ctypes.Structure):
    _fields_ = [
        ('comm', ctypes.c_char * 32),
        ('time', ctypes.c_uint64),
        ('pid', ctypes.c_uint64),
        ('raw_addr', ctypes.c_uint8 * 128),
    ]


class ConnectStart(ctypes.Structure):
    _fields_ = [
        ('start_time', ctypes.c_uint64),
        ('sa_family', ctypes.c_uint16),
        ('raw_addr', ctypes.c_uint8 * 128),
        ('_pad', ctypes.c_uint8 * 6),
    ]

def get_pretty_addr(raw_addr):
    bs = bytearray(raw_addr)

    af = struct.unpack('H', bs[:2])[0]
    if af == socket.AF_UNIX:
        path = ''
        for c in raw_addr[2:110]:
            if c == 0:
                break
            path += chr(c)
        return 'unix:{}'.format(path)
    elif af == socket.AF_INET:
        port = socket.ntohs(struct.unpack('H', bs[2:4])[0])
        ip = socket.inet_ntop(socket.AF_INET, bs[4:8])
        return '{}:{}'.format(ip, port)
    elif af == socket.AF_INET6:
        port = socket.htons(struct.unpack('H', bs[2:4])[0])
        ip = socket.inet_ntop(socket.AF_INET6, bs[8:24])
        return '[{}]:{}'.format(ip, port)
    elif af == socket.AF_UNSPEC:
        return 'AF_UNSPEC'
    else:
        return '{{addr_family={}}}'.format(af)

def run():
    py2bpf.util.ensure_resources()

    output_queue = py2bpf.datastructures.BpfQueue(CommTiming)
    connect_starts = py2bpf.datastructures.create_map(
        ctypes.c_uint, ConnectStart, 256)

    @py2bpf.kprobe.probe('sys_connect')
    def on_sys_connect_start(pt_regs):
        pid = py2bpf.funcs.get_current_pid_tgid() & 0xfffffff

        start = ConnectStart()
        start.start_time = py2bpf.funcs.ktime_get_ns()
        py2bpf.funcs.probe_read(start.raw_addr, pt_regs.rsi)

        connect_starts[pid] = start

        return 0


    @py2bpf.kprobe.probe('sys_connect', exit_probe=True)
    def on_sys_connect_finish(pt_regs):
        pid = py2bpf.funcs.get_current_pid_tgid() & 0xfffffff

        start = connect_starts[pid]
        if not start:
            return 0

        timing = CommTiming()
        timing.pid = pid
        py2bpf.funcs.get_current_comm(timing.comm)
        py2bpf.funcs.memcpy(start.raw_addr, timing.raw_addr, 128)
        timing.time = py2bpf.funcs.ktime_get_ns() - start.start_time

        cpuid = py2bpf.funcs.get_smp_processor_id()
        py2bpf.funcs.perf_event_output(pt_regs, output_queue, cpuid, timing)

        del connect_starts[pid]

        return 0


    with on_sys_connect_start(), on_sys_connect_finish():
        for timing in output_queue:
            addr = get_pretty_addr(timing.raw_addr)
            print('comm={} addr={} pid={} time={}ns'.format(
                timing.comm.decode(), addr, timing.pid, timing.time))


def main():
    try:
        run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
