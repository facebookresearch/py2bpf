#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''
Functions for tracing through streams of instructions
'''

import py2bpf._translation._dis_plus as dis


def get_all_execution_paths(insns):
    '''Trace all execution paths through the stream of instructions by
    following jumps and returns.
    '''
    def walk(offset, path):
        path = path[:]  # Make a copy
        for i in range(offset, len(insns)):
            path.append(insns[i])
            op = insns[i].opcode
            if op == dis.OpCode.RETURN_VALUE:
                yield path
                return

            if op in dis.hasjmp:
                # NB: argval is the absolute offset even for relative jumps
                jmp_offset = insns[i].argval
                assert jmp_offset > insns[i].offset, 'only allow forward jumps'

                found = False
                for j in range(offset, len(insns)):
                    if insns[j].offset == jmp_offset:
                        for p in walk(j, path):
                            yield p
                        found = True
                        break
                assert found, 'Failed to find jump offset'

                if op not in dis.hascondjmp:
                    return

        assert False, 'Unreachable ending'

    for p in walk(0, []):
        yield p
