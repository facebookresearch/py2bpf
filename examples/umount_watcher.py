#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import multiprocessing
import sys
import resource
import threading

import py2bpf.datastructures
import py2bpf.funcs as funcs
import py2bpf.kprobe as kprobe


class UmountCall(ctypes.Structure):
    _fields_ = [
        ('comm', ctypes.c_char * 16),
        ('path', ctypes.c_char * 256),
    ]


def main(argv):
    resource.setrlimit(
        resource.RLIMIT_MEMLOCK,
        (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

    def get_probe(cpu):
        q = py2bpf.datastructures.BpfQueue(UmountCall, cpu=cpu)

        def fn(pt_regs):
            call = UmountCall()
            funcs.probe_read(call.path, pt_regs.rdi)
            funcs.get_current_comm(call.comm)
            funcs.perf_event_output(pt_regs, q, 0, call)
            return 0

        probe = kprobe.BpfKProbe('sys_umount', fn, cpu=cpu)

        try:
            for i in q:
                print(i.comm.decode(), i.path.decode())
        except KeyboardInterrupt:
            pass

        probe.close()

    threads = [
        threading.Thread(target=get_probe, args=(cpu,))
        for cpu in range(multiprocessing.cpu_count())
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == '__main__':
    main(sys.argv)
