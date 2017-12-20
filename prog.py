#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import enum
import os
import re
import sys

from py2bpf._translation._translate import convert_to_register_ops
from py2bpf._bpf import _instructions, _syscall, _template_jit


class BpfCmd(enum.IntEnum):
    MAP_CREATE = 0
    PROG_LOAD = 5


class BpfAttrLoadProg(ctypes.Structure):
    _fields_ = [
        ('prog_type', ctypes.c_uint),
        ('insn_cnt', ctypes.c_uint),
        ('insns', ctypes.c_char_p),
        ('license', ctypes.c_char_p),
        ('log_level', ctypes.c_uint),
        ('log_size', ctypes.c_uint),
        ('log_buf', ctypes.c_char_p),
        ('kern_version', ctypes.c_uint),
    ]


def _get_kern_version():
    m = re.match(r'(\d+)\.(\d+)\.(\d+).*', os.uname()[2])
    return (int(m.group(1)) << 16) + (int(m.group(2)) << 8) + int(m.group(3))


def _load_prog(prog_type, insns_arr):
    log = ctypes.create_string_buffer(2 ** 20)

    attr = BpfAttrLoadProg(
        prog_type=prog_type,
        insn_cnt=len(insns_arr),
        insns=ctypes.cast(ctypes.byref(insns_arr), ctypes.c_char_p),
        license=ctypes.c_char_p('GPL'.encode()),
        log_level=100,
        log_size=ctypes.sizeof(log),
        log_buf=ctypes.addressof(log),
        kern_version=_get_kern_version(),
    )

    fd = _syscall.bpf(
        BpfCmd.PROG_LOAD, ctypes.pointer(attr), ctypes.sizeof(attr))
    if fd < 0:
        eno = _syscall._get_errno()
        print(log.value.decode(), file=sys.stderr)
        raise OSError(eno, 'Failed to load bpf prog: {}'.format(
            os.strerror(eno)))

    return fd, log.value.decode()


class ProgType(enum.IntEnum):
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5


class Prog:
    def __init__(self, prog_type, bpf_insns):
        self.prog_type = prog_type
        self.bpf_insns = bpf_insns
        raw_insns = _instructions.convert_to_raw_instructions(bpf_insns)
        self.fd, self.pretty = _load_prog(self.prog_type, raw_insns)

    def close(self):
        os.close(self.fd)
        self.fd = -1


def create_prog(prog_type, ctx_type, fn):
    reg_insns, stack = convert_to_register_ops(fn, ctx_type)

    verbose = 'PY2BPF_VERBOSE' in os.environ

    bpf_insns = _template_jit.translate(
        reg_insns, stack=stack, verbose=verbose)
    return Prog(prog_type, bpf_insns)
