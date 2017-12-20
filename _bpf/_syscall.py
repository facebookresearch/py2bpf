#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes

assert ctypes.sizeof(ctypes.c_char_p) == 8, 'x86_64 only'

__libc = None


def __get_libc():
    global __libc
    if __libc is None:
        # libc.so.6 ??
        __libc = ctypes.cdll.LoadLibrary('libc.so.6')
    return __libc


def syscall(num, *args):
    __get_libc().syscall.restype = int
    return __get_libc().syscall(num, *args)


def bpf(cmd, attr_p, attr_len):
    _NR_bpf = 321
    return syscall(_NR_bpf, cmd, attr_p, attr_len)


def _get_errno():
    get_errno_loc = __get_libc().__errno_location
    get_errno_loc.restype = ctypes.POINTER(ctypes.c_int)
    return get_errno_loc()[0]
