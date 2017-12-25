#!/usr/bin/env python3

import ctypes

import py2bpf.datastructures
import py2bpf.util
import py2bpf.funcs as funcs
import py2bpf.kprobe


def main():
    class UnlinkEvent(ctypes.Structure):
        _fields_ = [
            ('comm', ctypes.c_char * 32),
            ('path', ctypes.c_char * 256),
        ]

    py2bpf.util.ensure_resources()

    unlink_queue = py2bpf.datastructures.BpfQueue(UnlinkEvent)

    @py2bpf.kprobe.probe('do_unlinkat')
    def do_unlinkat(pt_regs):
        ev = UnlinkEvent()
        funcs.probe_read(ev.path, pt_regs.rsi)
        funcs.get_current_comm(ev.comm)

        cpuid = funcs.get_smp_processor_id()
        funcs.perf_event_output(pt_regs, unlink_queue, cpuid, ev)
        return 0

    with do_unlinkat():
        for ev in unlink_queue:
            print(ev.comm.decode(), ev.path.decode())


if __name__ == '__main__':
    main()
