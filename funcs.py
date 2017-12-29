#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''Functions that can be invoked from within bpf programs'''


import ctypes


class PseudoFunc:
    def __init__(self, name, num_args, return_type=ctypes.c_uint64):
        self.name = name
        self.num_args = num_args
        self.return_type = return_type

    def __repr__(self):
        return 'PsuedoFunc({}, {})'.format(self.name, self.num_args)


class Func:
    def __init__(self, name, num, num_args,
                 return_type=ctypes.c_uint64,
                 fill_array_size_args=None):
        self.name = name
        self.num = num
        self.num_args = num_args
        self.return_type = return_type

        # Some functions take an array pointer followed by its size and
        # that's annoying to specify in python, so we allow ourselves to
        # automatically fill it in here.
        self.fill_array_size_args = []
        if fill_array_size_args is not None:
            self.fill_array_size_args = fill_array_size_args

    def __repr__(self):
        return 'Func({}, {}, {}, fill_array_size_args={})'.format(
            self.name, self.num, self.num_args, self.fill_array_size_args)


map_lookup_elem = Func('map_lookup_elem', 1, 2)
map_update_elem = Func('map_update_elem', 2, 4)
map_delete_elem = Func('map_delete_elem', 3, 2)
probe_read = Func('probe_read', 4, 2, fill_array_size_args=[0])
ktime_get_ns = Func('ktime_get_ns', 5, 0)
trace_printk = Func('trace_printk', 6, -1, fill_array_size_args=[0])

get_smp_processor_id = Func('get_smp_processor_id', 8, 0)

get_current_pid_tgid = Func('get_current_pid_tgid', 14, 0)
get_current_uid_gid = Func('get_current_uid_gid', 15, 0)
get_current_comm = Func('get_current_comm', 16, 1, fill_array_size_args=[0])

perf_event_output = Func('perf_event_output', 25, 4, fill_array_size_args=[3])
skb_load_bytes = Func('skb_load_bytes', 26, 4)
get_stackid = Func('get_stackid', 27, 3)

addrof = PseudoFunc('addrof', 1)
memcpy = PseudoFunc('memcpy', 3)
ptr = PseudoFunc('ptr', 1)
packet_copy = PseudoFunc('packet_copy', 4)

load_skb_byte = PseudoFunc('load_skb_byte', 2)
load_skb_short = PseudoFunc('load_skb_short', 2)
load_skb_word = PseudoFunc('load_skb_word', 2)

mem_eq = PseudoFunc('mem_eq', 2)
