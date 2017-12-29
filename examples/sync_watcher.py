#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.kprobe
import py2bpf.util


class SyncCall(ctypes.Structure):
    _fields_ = [
        ('comm', ctypes.c_char * 32),
        ('time', ctypes.c_uint64),
        ('pid', ctypes.c_uint64),
    ]


def run():
    py2bpf.util.ensure_resources()

    output_queue = py2bpf.datastructures.BpfQueue(SyncCall)
    sync_starts = py2bpf.datastructures.create_map(
        ctypes.c_uint, ctypes.c_uint64, 2048)

    @py2bpf.kprobe.probe('sys_sync')
    def on_sys_sync_start(pt_regs):
        pid = py2bpf.funcs.get_current_pid_tgid() & 0xfffffff
        sync_starts[pid] = py2bpf.funcs.ktime_get_ns()
        return 0


    @py2bpf.kprobe.probe('sys_sync', exit_probe=True)
    def on_sys_sync_finish(pt_regs):
        pid = py2bpf.funcs.get_current_pid_tgid() & 0xfffffff

        start = sync_starts[pid]
        if not start:
            return 0

        c = SyncCall()
        c.pid = pid
        c.time = py2bpf.funcs.ktime_get_ns() - start
        py2bpf.funcs.get_current_comm(c.comm)

        cpuid = py2bpf.funcs.get_smp_processor_id()
        py2bpf.funcs.perf_event_output(pt_regs, output_queue, cpuid, c)

        del sync_starts[pid]

        return 0


    with on_sys_sync_start(), on_sys_sync_finish():
        for timing in output_queue:
            print('comm={} pid={} time={}ns'.format(
                timing.comm.decode(), timing.pid, timing.time))


def main():
    try:
        run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
