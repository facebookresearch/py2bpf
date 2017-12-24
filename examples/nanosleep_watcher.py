#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes

import py2bpf.datastructures
import py2bpf.funcs
import py2bpf.kprobe
import py2bpf.util


def run_probe():
    # Ensure that we don't run into any pesky ulimits
    py2bpf.util.ensure_resources()

    # This is a totally vanilla ctypes struct. It'll be auto-translated in
    # the context of the bpf-converted python function, so it'll look
    # pretty normal in use.
    class TimeSpec(ctypes.Structure):
        _fields_ = [
            ('tv_sec', ctypes.c_int64),
            ('tv_nsec', ctypes.c_int64),
        ]

    # This is our output type
    class NanoSleepEvent(ctypes.Structure):
        _fields_ = [
            ('comm', ctypes.c_char * 16),
            ('ts', TimeSpec),
        ]

    # Create a queue to exfiltrate the comms to us
    q = py2bpf.datastructures.BpfQueue(NanoSleepEvent)

    # Write our probing function. The probe decorator turns it into a
    # function that returns a BpfProbe.
    @py2bpf.kprobe.probe('sys_nanosleep')
    def watch_nanosleep(pt_regs):
        nse = NanoSleepEvent()

        # Read the "comm" or short description of the running process
        py2bpf.funcs.get_current_comm(nse.comm)

        # Read the time spec argument. It's a pointer to arbitrary memory,
        # so we'll have to use probe_read to read it safely. This could
        # fail and return a non-zero code, but I'm being lazy and assuming
        # success here.
        py2bpf.funcs.probe_read(nse.ts, pt_regs.rdi)

        # Send the NanoSleepEvent back to userspace through the BpfQueue
        py2bpf.funcs.perf_event_output(
            pt_regs, q, py2bpf.funcs.get_smp_processor_id(), nse)

        return 0

    # We use the `with` syntax to insert it
    with watch_nanosleep():
        # We iterate over all items returned from the queue. When there
        # are no more objects in the queue, we simply block.
        for nse in q:
            print('comm={} tv_sec={} tv_nsec={}'.format(
                nse.comm.decode(),
                nse.ts.tv_sec,
                nse.ts.tv_nsec))


def main():
    try:
        run_probe()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
