#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import argparse
import ctypes
import resource
import socket
import sys

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.tc


ETH_P_IPV6 = 0x86DD
ETH_P_IP = 0x0800

V6Addr = ctypes.c_uint8 * 16
V4Addr = ctypes.c_uint8 * 4

resource.setrlimit(
    resource.RLIMIT_MEMLOCK,
    (resource.RLIM_INFINITY, resource.RLIM_INFINITY))


def build_blacklist_maps(f):
    # TODO figure out how big the map needs to be from the input file first
    v4_blacklist = py2bpf.datastructures.create_map(
        V4Addr, ctypes.c_uint8, 2 ** 10)
    v6_blacklist = py2bpf.datastructures.create_map(
        V6Addr, ctypes.c_uint8, 2 ** 10)

    for l in f:
        ip = l.strip()
        if ':' in ip:
            v6_blacklist[V6Addr(*socket.inet_pton(socket.AF_INET6, ip))] = 1
        else:
            v4_blacklist[V4Addr(*socket.inet_pton(socket.AF_INET, ip))] = 1

    return v4_blacklist, v6_blacklist


def compile_filter(f):
    v4_blacklist, v6_blacklist = build_blacklist_maps(f)

    def drop_fn(skb):
        nonlocal v4_blacklist, v6_blacklist
        if skb.protocol == socket.htons(ETH_P_IPV6):
            v6_src_addr = V6Addr()
            py2bpf.funcs.skb_load_bytes(skb, 14 + 8, v6_src_addr, 16)
            return v6_blacklist[v6_src_addr]
        elif skb.protocol == socket.htons(ETH_P_IP):
            v4_src_addr = V4Addr()
            py2bpf.funcs.skb_load_bytes(skb, 14 + 12, v4_src_addr, 4)
            return v4_blacklist[v4_src_addr]

        return 0

    return drop_fn


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--blacklist-file', required=True,
                        help='File of ips to blacklist.  "-" means stdin')
    parser.add_argument('--dev', required=True,
                        help='Device for which to insert ingress filter')
    parser.add_argument('--clear', action='store_true', default=False)
    args = parser.parse_args(argv[1:])

    try:
        py2bpf.tc.clear_ingress_filter(args.dev)
    except Exception:
        pass

    if args.clear:
        return

    if args.blacklist_file == '-':
        fn = compile_filter(sys.stdin)
    else:
        with open(args.blacklist_file) as f:
            fn = compile_filter(f)

    fil = py2bpf.tc.IngressFilter(fn)
    fil.install(args.dev)
    fil.close()


if __name__ == '__main__':
    main(sys.argv)
