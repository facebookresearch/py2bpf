#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''Really just dis with functionality that I (correctly or incorrectly) felt
was missing like an OpCode enum and other sets of opcodes
'''

# We do the gross * import because we use _dis_plus as an extension to dis.
from dis import *  # noqa: F403,F401

from dis import opmap, hasjrel, hasjabs, opname

class OpCode:
    pass


for name, v in opmap.items():
    setattr(OpCode, name, v)

hasjmp = hasjrel + hasjabs
hascondjmp = set([
    OpCode.POP_JUMP_IF_TRUE,
    OpCode.POP_JUMP_IF_FALSE,
    OpCode.JUMP_IF_TRUE_OR_POP,
    OpCode.JUMP_IF_FALSE_OR_POP,
])


def opcode_key_wrapper(f):
    def g(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except KeyError as e:
            k = e.args[0]
            if not isinstance(k, int) or k <= 0 or k >= len(opname):
                raise ValueError('Invalid opcode: {}'.format(k)) from e
            else:
                msg = 'No entry in {} for opcode: {}.'.format(
                    f.__name__, opname[k])
                raise ValueError(msg) from e

    return g
