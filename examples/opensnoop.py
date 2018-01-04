#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import sys
import ctypes

import py2bpf.util
import py2bpf.funcs as funcs
import py2bpf.kprobe

class Call(ctypes.Structure):
    _fields_ = [
        ('pid', ctypes.c_int),
        ('comm', ctypes.c_char * 32),
        ('path', ctypes.c_char * 256),
    ]


def main(argv):
    py2bpf.util.ensure_resources()

    call_queue = py2bpf.datastructures.BpfQueue(Call)

    @py2bpf.kprobe.probe('sys_open')
    def open_probe(pt_regs):
        call = Call()
        call.pid = funcs.get_current_pid_tgid() & 0xffffffff
        funcs.get_current_comm(call.comm)
        funcs.probe_read_str(call.path, pt_regs.rdi)

        cpuid = funcs.get_smp_processor_id()
        funcs.perf_event_output(pt_regs, call_queue, cpuid, call)

        return 0


    with open_probe():
        for call in call_queue:
            print('pid={} comm={} path={}'.format(
                call.pid,
                call.comm.decode(),
                call.path.decode()))


if __name__ == '__main__':
    main(sys.argv)
