#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import os

import py2bpf._bpf._syscall as _syscall

PERF_TYPE_SOFTWARE = 1
PERF_TYPE_TRACEPOINT = 2

PERF_COUNT_SW_BPF_OUTPUT = 10

PERF_SAMPLE_IP = 1 << 0
PERF_SAMPLE_TID = 1 << 1
PERF_SAMPLE_TIME = 1 << 2
PERF_SAMPLE_ADDR = 1 << 3
PERF_SAMPLE_READ = 1 << 4
PERF_SAMPLE_CALLCHAIN = 1 << 5
PERF_SAMPLE_ID = 1 << 6
PERF_SAMPLE_CPU = 1 << 7
PERF_SAMPLE_PERIOD = 1 << 8
PERF_SAMPLE_STREAM_ID = 1 << 9
PERF_SAMPLE_RAW = 1 << 10
PERF_SAMPLE_BRANCH_STACK = 1 << 11
PERF_SAMPLE_REGS_USER = 1 << 12
PERF_SAMPLE_STACK_USER = 1 << 13
PERF_SAMPLE_WEIGHT = 1 << 14
PERF_SAMPLE_DATA_SRC = 1 << 15
PERF_SAMPLE_IDENTIFIER = 1 << 16
PERF_SAMPLE_TRANSACTION = 1 << 17
PERF_SAMPLE_REGS_INTR = 1 << 18

PERF_RECORD_MMAP = 1
PERF_RECORD_LOST = 2
PERF_RECORD_COMM = 3
PERF_RECORD_EXIT = 4
PERF_RECORD_THROTTLE = 5
PERF_RECORD_UNTHROTTLE = 6
PERF_RECORD_FORK = 7
PERF_RECORD_READ = 8
PERF_RECORD_SAMPLE = 9

PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_SET_BPF = 0x40042408


class SamplePeriodUnion(ctypes.Union):
    _fields_ = [
        ('sample_period', ctypes.c_uint64),
        ('sample_freq', ctypes.c_uint64),
    ]


class WakeupEventsUnion(ctypes.Union):
    _fields_ = [
        ('wakeup_events', ctypes.c_uint32),
        ('wakeup_watermark', ctypes.c_uint32),
    ]


class PerfEventAttr(ctypes.Structure):
    _anonymous = ('au1', 'au2',)
    _fields_ = [
        ('type', ctypes.c_uint32),
        ('size', ctypes.c_uint32),
        ('config', ctypes.c_uint64),
        ('au1', SamplePeriodUnion),
        ('sample_type', ctypes.c_uint64),
        ('read_format', ctypes.c_uint64),
        ('flags', ctypes.c_uint64),
        ('au2', WakeupEventsUnion),
        ('bp_type', ctypes.c_uint32),
        ('bp_addr_and_config1', ctypes.c_uint64),
        ('bp_len_and_config2', ctypes.c_uint64),
        ('branch_sample_time', ctypes.c_uint64),
        ('sample_regs_user', ctypes.c_uint64),
        ('sample_stack_user', ctypes.c_uint32),
        ('__reserved_2', ctypes.c_uint32),
    ]


class PerfEventHeader(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_uint32),
        ('misc', ctypes.c_uint16),
        ('size', ctypes.c_uint16),
    ]


class PerfEventMmapPage(ctypes.Structure):
    _fields_ = [
        ('version', ctypes.c_uint32),
        ('compat_version', ctypes.c_uint32),

        ('lock', ctypes.c_uint32),
        ('index', ctypes.c_uint32),
        ('offset', ctypes.c_int64),
        ('time_enabled', ctypes.c_uint64),
        ('time_running', ctypes.c_uint64),

        ('capabilities', ctypes.c_uint64),
        ('pmc_width', ctypes.c_uint16),

        ('time_shift', ctypes.c_uint16),
        ('time_mult', ctypes.c_uint32),
        ('time_offset', ctypes.c_uint64),

        ('time_zero', ctypes.c_uint64),
        ('size', ctypes.c_uint32),

        ('__reserved', ctypes.c_uint8 * (118 * 8 + 4)),

        ('data_head', ctypes.c_uint64),
        ('data_tail', ctypes.c_uint64),
        ('data_offset', ctypes.c_uint64),
        ('data_size', ctypes.c_uint64),

        ('aux_head', ctypes.c_uint64),
        ('aux_tail', ctypes.c_uint64),
        ('aux_offset', ctypes.c_uint64),
        ('aux_size', ctypes.c_uint64),
    ]


def perf_event_open(attr, pid=-1, cpu=-1, group_fd=-1, flags=0):
    _NR_perf_event_open = 298
    ret = _syscall.syscall(
        _NR_perf_event_open, ctypes.byref(attr), pid, cpu, group_fd, flags)
    if ret < 0:
        eno = _syscall._get_errno()
        raise OSError(eno, 'Failed to open perf event: {}'.format(
            os.strerror(eno)))
    return ret
