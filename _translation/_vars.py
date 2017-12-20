#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''This file maps instructions to VarInstructions, which explicitly map
sources and dests from implicit stack locations to explicit variables. This
simplifies future type inferencing and stack allocations
'''

import collections
from py2bpf._translation import _trace, _dis_plus as dis


class Var:
    def __init__(self, num, var_type=None):
        self.num = num
        self.var_type = var_type

    def __hash__(self):
        # We deliberately only hash on num because we want to be able to
        # look up variable types with an unset Var type later.
        return hash(self.num)

    def __eq__(self, rhs):
        return type(self) == type(rhs) and self.num == rhs.num

    def __repr__(self):
        return 'Var({}, {})'.format(repr(self.num), repr(self.var_type))

    def __str__(self):
        if self.var_type is not None:
            return 'Var<{}>{}'.format(self.var_type.__name__, self.num)
        else:
            return 'Var{}'.format(self.num)


class VarInstruction:
    def __init__(self, instruction, src_vars=None, dst_vars=None):
        self.src_instruction = instruction
        self.opname = instruction.opname
        self.opcode = instruction.opcode
        self.arg = instruction.arg
        self.argval = instruction.argval
        self.argrepr = instruction.argrepr
        self.offset = instruction.offset
        self.starts_line = instruction.starts_line
        self.is_jump_target = instruction.is_jump_target

        self.src_vars = src_vars
        if src_vars is None:
            self.src_vars = []

        self.dst_vars = dst_vars
        if dst_vars is None:
            self.dst_vars = []

    def __str__(self):
        args = [self.argrepr] if self.arg is not None else []
        args.extend([str(n) for n in self.src_vars])
        args = ', '.join(args)

        dsts = ', '.join([str(n) for n in self.dst_vars])
        lhs = '{} = '.format(dsts) if len(dsts) > 0 else ''
        return '{}{}({}) # line {}'.format(
            lhs, self.opname, args, self.starts_line)


@dis.opcode_key_wrapper
def _num_pushes(i):
    return {
        dis.OpCode.LOAD_GLOBAL: 1,
        dis.OpCode.LOAD_DEREF: 1,
        dis.OpCode.LOAD_CONST: 1,
        dis.OpCode.LOAD_FAST: 1,
        dis.OpCode.STORE_FAST: 0,
        dis.OpCode.BINARY_TRUE_DIVIDE: 1,
        dis.OpCode.BINARY_FLOOR_DIVIDE: 1,
        dis.OpCode.BINARY_MULTIPLY: 1,
        dis.OpCode.POP_JUMP_IF_FALSE: 0,
        dis.OpCode.POP_JUMP_IF_TRUE: 0,
        dis.OpCode.RETURN_VALUE: 0,
        dis.OpCode.COMPARE_OP: 1,
        dis.OpCode.INPLACE_ADD: 1,
        dis.OpCode.LOAD_ATTR: 1,
        dis.OpCode.STORE_ATTR: 0,
        dis.OpCode.BINARY_SUBSCR: 1,
        dis.OpCode.BINARY_ADD: 1,
        dis.OpCode.BINARY_AND: 1,
        dis.OpCode.BINARY_OR: 1,
        dis.OpCode.BINARY_LSHIFT: 1,
        dis.OpCode.BINARY_RSHIFT: 1,
        dis.OpCode.BINARY_SUBTRACT: 1,
        dis.OpCode.CALL_FUNCTION: 1,
        dis.OpCode.JUMP_FORWARD: 0,
        dis.OpCode.STORE_SUBSCR: 0,
        dis.OpCode.DELETE_SUBSCR: 0,
    }[i.opcode]


@dis.opcode_key_wrapper
def _num_pops(i):
    if i.opcode == dis.OpCode.CALL_FUNCTION:
        nkwargs = (i.arg >> 8) * 2
        nargs = i.arg & 0xff
        # +1 for function that we're calling
        return 1 + nkwargs + nargs

    return {
        dis.OpCode.LOAD_GLOBAL: 0,
        dis.OpCode.LOAD_DEREF: 0,
        dis.OpCode.LOAD_CONST: 0,
        dis.OpCode.LOAD_FAST: 0,
        dis.OpCode.STORE_FAST: 1,
        dis.OpCode.BINARY_TRUE_DIVIDE: 2,
        dis.OpCode.BINARY_FLOOR_DIVIDE: 2,
        dis.OpCode.BINARY_MULTIPLY: 2,
        dis.OpCode.POP_JUMP_IF_FALSE: 1,
        dis.OpCode.POP_JUMP_IF_TRUE: 1,
        dis.OpCode.RETURN_VALUE: 1,
        dis.OpCode.COMPARE_OP: 2,
        dis.OpCode.INPLACE_ADD: 2,
        dis.OpCode.LOAD_ATTR: 1,
        dis.OpCode.STORE_ATTR: 2,
        dis.OpCode.BINARY_SUBSCR: 2,
        dis.OpCode.BINARY_ADD: 2,
        dis.OpCode.BINARY_AND: 2,
        dis.OpCode.BINARY_OR: 2,
        dis.OpCode.BINARY_LSHIFT: 2,
        dis.OpCode.BINARY_RSHIFT: 2,
        dis.OpCode.BINARY_SUBTRACT: 2,
        dis.OpCode.JUMP_FORWARD: 0,
        dis.OpCode.STORE_SUBSCR: 3,
        dis.OpCode.DELETE_SUBSCR: 2,
    }[i.opcode]


def assign_vars(instructions):
    '''Given a list of instructions, set src_vars and dst_vars by tracing
    through all execution paths
    '''

    # Go through all execution paths and note sources and destinations by
    # simulating the state of the stack for any given execution trace.
    srcs = collections.defaultdict(list)
    for path in _trace.get_all_execution_paths(instructions):
        stack = []
        for i in path:
            # Handle special snowflake ops that manipulate stack first
            if i.opcode == dis.OpCode.ROT_TWO:
                tos = stack.pop()
                tos1 = stack.pop()
                stack.extend([tos, tos1])
            elif i.opcode == dis.OpCode.ROT_THREE:
                tos = stack.pop()
                tos1 = stack.pop()
                tos2 = stack.pop()
                stack.extend([tos, tos2, tos1])
            elif i.opcode == dis.OpCode.DUP_TOP:
                stack.append(stack[-1])
            elif i.opcode == dis.OpCode.POP_TOP:
                stack.pop()
            elif i.opcode == dis.OpCode.DUP_TOP_TWO:
                stack.extend(stack[-2:])
            else:
                # Grab sources for this instruction
                pops = _num_pops(i)
                if pops > 0:
                    srcs[i.offset].append(stack[-pops:])
                    stack = stack[:-pops]
                # Provide pushes for this instruction
                pushes = _num_pushes(i)
                if pushes > 0:
                    stack.extend([i.offset] * pushes)

    # srcs now contains the potential source instructions for every op. Now
    # we coalesce the destinations for every op into single variables. If
    # an instruction has two possible inputs, it means that we'll insure
    # that both inputs output to the same variable.

    # Sort by op offset to make numbering less arbitrary
    src_lists = [t[1] for t in sorted(srcs.items(), key=lambda t: t[0])]

    next_var_num = 1
    op_to_dest = {}
    for src_list in src_lists:
        for op_off in src_list[0]:
            if op_off not in op_to_dest:
                op_to_dest[op_off] = Var(next_var_num)
                next_var_num += 1
        for alt_src in src_list[1:]:
            for op_off1, op_off2 in zip(src_list[0], alt_src):
                if op_off2 in op_to_dest:
                    assert op_to_dest[op_off1] == op_to_dest[op_off2]
                else:
                    op_to_dest[op_off2] = op_to_dest[op_off1]

    # Now that we've canonicalized the destination variables of each op
    # with the op_to_dest map, assign the src and dst vars.
    var_instructions = []
    for i in instructions:
        # Drop these now that we have vars
        if i.opcode in [dis.OpCode.ROT_TWO, dis.OpCode.DUP_TOP,
                        dis.OpCode.DUP_TOP_TWO, dis.OpCode.ROT_THREE,
                        dis.OpCode.POP_TOP]:
            continue

        if i.offset in srcs:
            src_vars = [
                op_to_dest[src_off] for src_off in srcs[i.offset][0]]
        else:
            src_vars = []

        if i.offset in op_to_dest:
            dst_vars = [op_to_dest[i.offset]]
        else:
            dst_vars = []
        vi = VarInstruction(i, src_vars=src_vars, dst_vars=dst_vars)
        var_instructions.append(vi)

    return var_instructions


def fill_line_starts(vis):
    ret = []
    last_line = None
    for vi in vis:
        if vi.starts_line is not None:
            last_line = vi.starts_line
        else:
            vi.starts_line = last_line
        ret.append(vi)
    return ret
