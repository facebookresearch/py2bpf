#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import pyroute2

import py2bpf.prog as prog
from py2bpf.socket_filter import SkBuffContext


def clear_ingress_filter(dev):
    with pyroute2.IPRoute() as ipr:
        idx = ipr.link_lookup(ifname=dev)[0]
        ipr.tc('del', 'ingress', idx, 'ffff:')


class IngressFilter:
    def __init__(self, fn):
        self.prog = prog.create_prog(
            prog.ProgType.SCHED_CLS, SkBuffContext, fn)

    def close(self):
        self.prog.close()

    def install(self, dev):
        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=dev)[0]
            ipr.tc('add', 'ingress', idx, 'ffff:')
            ipr.tc('add-filter', 'bpf', idx, ':1', fd=self.prog.fd,
                   name='drop_face', parent='ffff:', action='drop', classid=1)

    def remove(self):
        clear_ingress_filter()
