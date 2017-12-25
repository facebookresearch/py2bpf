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
import py2bpf.info

class Call(ctypes.Structure):
    _fields_ = [
        ('pid', ctypes.c_int),
        ('comm', ctypes.c_char * 32),
        ('arg0', ctypes.c_char * 16),
        ('arg1', ctypes.c_char * 16),
        ('arg2', ctypes.c_char * 16),
        ('arg3', ctypes.c_char * 16),
    ]


def main(argv):
    py2bpf.util.ensure_resources()

    call_queue = py2bpf.datastructures.BpfQueue(Call)

    @py2bpf.kprobe.probe('sys_execve')
    def execve_probe(pt_regs):
        call = Call()
        call.pid = funcs.get_current_pid_tgid() & 0xffffffff
        funcs.get_current_comm(call.comm)

        arg = ctypes.c_int64()
        addrof_arg = funcs.addrof(arg)

        funcs.probe_read(addrof_arg, pt_regs.rsi)
        if arg != 0: # Read argv[0]
            funcs.probe_read(call.arg0, arg)
            funcs.probe_read(addrof_arg, pt_regs.rsi + 8)

        if arg != 0: # Read argv[1]
            funcs.probe_read(call.arg1, arg)
            funcs.probe_read(addrof_arg, pt_regs.rsi + 16)

        if arg != 0: # Read argv[2]
            funcs.probe_read(call.arg2, arg)
            funcs.probe_read(addrof_arg, pt_regs.rsi + 24)

        if arg != 0: # Read argv[3]
            funcs.probe_read(call.arg3, arg)

        cpuid = funcs.get_smp_processor_id()
        funcs.perf_event_output(pt_regs, call_queue, cpuid, call)

        return 0


    with execve_probe():
        for call in call_queue:
            print('{} ({}) $ {} {} {} {}'.format(
                call.pid,
                call.comm.decode(),
                call.arg0.decode(),
                call.arg1.decode(),
                call.arg2.decode(),
                call.arg3.decode()))


if __name__ == '__main__':
    main(sys.argv)
