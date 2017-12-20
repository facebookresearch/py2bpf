#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import resource
import socket
import struct

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.socket_filter

ETH_P_IPV6 = 0x86DD
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800

IpAddr = ctypes.c_uint8 * 4


class Flow(ctypes.Structure):
    _fields_ = [
        ('src', ctypes.c_uint32),
        ('dst', ctypes.c_uint32),
        ('src_port', ctypes.c_uint16),
        ('dst_port', ctypes.c_uint16),
        ('l4_protocol', ctypes.c_uint8),
        ('_pad', ctypes.c_uint8 * 3),
    ]


resource.setrlimit(
    resource.RLIMIT_MEMLOCK,
    (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

flow_counts = py2bpf.datastructures.create_map(Flow, ctypes.c_ulong, 256)


def add_flow_to_map(skb):
    if skb.protocol == socket.htons(ETH_P_IP):
        flow = Flow()
        flow.src = py2bpf.funcs.load_skb_word(skb, 26)
        flow.dst = py2bpf.funcs.load_skb_word(skb, 30)
        flow.l4_protocol = py2bpf.funcs.load_skb_byte(skb, 23)
        if (flow.l4_protocol == socket.IPPROTO_TCP or
                flow.l4_protocol == socket.IPPROTO_UDP):
            l4_offset = 14 + (py2bpf.funcs.load_skb_byte(skb, 14) & 0xf) * 4
            flow.src_port = py2bpf.funcs.load_skb_short(skb, l4_offset)
            flow.dst_port = py2bpf.funcs.load_skb_short(skb, l4_offset + 2)
        flow_counts[flow] += 1
    return 0


sf = py2bpf.socket_filter.SocketFilter(add_flow_to_map)
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sf.attach(s)

try:
    print('running.  ^C to stop')
    while True:
        s.recv(1)
except KeyboardInterrupt:
    print('finished')

s.close()
sf.close()


def ips(x):
    return socket.inet_ntop(socket.AF_INET, struct.pack('!I', x))


for k, v in flow_counts.items():
    if k.l4_protocol == socket.IPPROTO_TCP:
        print('TCP: {}:{} => {}:{} :: {}'.format(
            ips(k.src), k.src_port, ips(k.dst), k.dst_port, v.value))
    elif k.l4_protocol == socket.IPPROTO_UDP:
        print('UDP: {}:{} => {}:{} :: {}'.format(
            ips(k.src), k.src_port, ips(k.dst), k.dst_port, v.value))
    elif k.l4_protocol == socket.IPPROTO_ICMP:
        print('ICMP: {} => {} :: {}'.format(ips(k.src), ips(k.dst), v.value))
    else:
        print('proto({}): {} => {} :: {}'.format(
            k.l4_protocol, ips(k.src), ips(k.dst), v.value))

flow_counts.close()
