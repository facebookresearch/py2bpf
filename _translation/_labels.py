#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''Explicit labels to simplify translation later'''

import heapq
import py2bpf._translation._dis_plus as dis


class Label:
    def __init__(self, offset):
        self.offset = offset

    def __str__(self):
        return 'Label({})'.format(self.offset)


def insert_labels(vis):
    ret = []
    labels_heap = []
    for i in vis:
        last = None
        while len(labels_heap) > 0 and labels_heap[0] <= i.offset:
            # Check last to prevent dup labels
            if last != labels_heap[0]:
                ret.append(Label(labels_heap[0]))
                last = labels_heap[0]
            heapq.heappop(labels_heap)

        if i.opcode in dis.hasjmp:
            heapq.heappush(labels_heap, i.argval)
        ret.append(i)
    return ret
