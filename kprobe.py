#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import fcntl
import multiprocessing
import os
import random

import py2bpf.datastructures
import py2bpf.prog as prog
import py2bpf._bpf._perf_event as pe


class PtRegsContext(ctypes.Structure):
    _fields_ = [
        ('r15', ctypes.c_ulong),
        ('r14', ctypes.c_ulong),
        ('r13', ctypes.c_ulong),
        ('r12', ctypes.c_ulong),
        ('rbp', ctypes.c_ulong),
        ('rbx', ctypes.c_ulong),
        # arguments: non interrupts/non tracing syscalls only save up to here
        ('r11', ctypes.c_ulong),
        ('r10', ctypes.c_ulong),
        ('r9', ctypes.c_ulong),
        ('r8', ctypes.c_ulong),
        ('rax', ctypes.c_ulong),
        ('rcx', ctypes.c_ulong),
        ('rdx', ctypes.c_ulong),
        ('rsi', ctypes.c_ulong),
        ('rdi', ctypes.c_ulong),
        ('orig_rax', ctypes.c_ulong),
        # end of arguments
        # cpu exception frame or undefined
        ('rip', ctypes.c_ulong),
        ('cs', ctypes.c_ulong),
        ('eflags', ctypes.c_ulong),
        ('rsp', ctypes.c_ulong),
        ('ss', ctypes.c_ulong),
    ]


class BpfKProbe:
    def __init__(self, symbol, fn, cpu, exit_probe=False):
        self.symbol = symbol
        self.fn = fn
        self.cpu = cpu
        self.exit_probe = exit_probe
        self.tracepoint_name = '{}_{}'.format(
            self.symbol, random.randint(1, 2 ** 16))

    def start(self):
        attr = pe.PerfEventAttr()
        attr.type = pe.PERF_TYPE_TRACEPOINT

        fd = os.open('/sys/kernel/debug/tracing/kprobe_events',
                     os.O_WRONLY | os.O_APPEND)
        if not self.exit_probe:
            s = 'p:{} {}\n'.format(self.tracepoint_name, self.symbol)
        else:
            s = 'r:{} {}\n'.format(self.tracepoint_name, self.symbol)
        os.write(fd, s.encode('ascii'))
        os.close(fd)

        id_path = '/sys/kernel/debug/tracing/events/kprobes/{}/id'.format(
            self.tracepoint_name)
        with open(id_path) as f:
            attr.config = int(f.read().strip())

        attr.sample_type = pe.PERF_SAMPLE_RAW
        attr.sample_period = 1
        attr.wakeup_events = 1
        self.perf_event_fd = pe.perf_event_open(attr, cpu=self.cpu)
        self.prog = prog.create_prog(
            prog.ProgType.KPROBE, PtRegsContext, self.fn)

        fcntl.ioctl(self.perf_event_fd, pe.PERF_EVENT_IOC_SET_BPF, self.prog.fd)
        fcntl.ioctl(self.perf_event_fd, pe.PERF_EVENT_IOC_ENABLE, 0)

    def close(self):
        self.prog.close()
        if self.perf_event_fd >= 0:
            os.close(self.perf_event_fd)

        fd = os.open(
            '/sys/kernel/debug/tracing/kprobe_events',
            os.O_WRONLY | os.O_APPEND)

        try:
            os.write(fd, '-:{}\n'.format(self.tracepoint_name).encode())
        except FileNotFoundError:
            pass

        os.close(fd)

    def __enter__(self):
        self.start()

    def __exit__(self, *args):
        self.close()


def probe(symbol, exit_probe=False):
    def decorator(fn):
        def f():
            return BpfKProbe(symbol, fn, exit_probe=exit_probe, cpu=0)

        return f

    return decorator
