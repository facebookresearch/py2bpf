#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''bpf socket filter that can be attached to sockets'''

import ctypes
import socket

from py2bpf import prog


class SkBuffContext(ctypes.Structure):
    _fields_ = [
        ('len', ctypes.c_uint32),
        ('pkt_type', ctypes.c_uint32),
        ('mark', ctypes.c_uint32),
        ('queue_mapping', ctypes.c_uint32),
        ('protocol', ctypes.c_uint32),
        ('vlan_present', ctypes.c_uint32),
        ('vlan_tci', ctypes.c_uint32),
        ('vlan_proto', ctypes.c_uint32),
        ('priority', ctypes.c_uint32),
        ('ingress_ifindex', ctypes.c_uint32),
        ('ifindex', ctypes.c_uint32),
        ('tc_index', ctypes.c_uint32),
        ('cb', ctypes.c_uint32 * 5),
        ('hash', ctypes.c_uint32),
        ('tc_classid', ctypes.c_uint32),
        ('data', ctypes.c_uint32),
        ('data_end', ctypes.c_uint32),
    ]

    # This force-casts the thing under the covers. We must do this, because
    # bpf forces us to :(
    _dest_type_overrides_ = {
        'data': ctypes.c_uint64,
        'data_end': ctypes.c_uint64,
    }


class SocketFilter:
    def __init__(self, fn):
        self.prog = prog.create_prog(
            prog.ProgType.SOCKET_FILTER, SkBuffContext, fn)

    def attach(self, sock):
        SO_ATTACH_BPF = 50
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_BPF, self.prog.fd)

    def close(self):
        self.prog.close()
