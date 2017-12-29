#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

'''Module for doing template translations from VarInstructions to
BpfInstructions. We deliberately do as little as possible -- any possible
complexity should exist in other modules and invoked by the _translate
file.
'''

import ctypes
import _ctypes

from py2bpf._translation import _labels, _mem, _stack, _types, _dis_plus as dis
from py2bpf._bpf import _instructions as bi
from py2bpf import funcs
from py2bpf._translation._datastructures import FileDescriptorDatastructure
from py2bpf.exception import TranslationError

_opcode_translators = {}


def _opcode_translate(opcode):
    '''This decorator just puts the function into the _opcode_translators map
    for bpf_template_jit to use
    '''
    def dec(f):
        _opcode_translators[opcode] = f
        return f

    return dec


_next_tmp_label_num = 0


def _make_tmp_label():
    global _next_tmp_label_num
    name = 'tmp_label_{}'.format(_next_tmp_label_num)
    _next_tmp_label_num += 1
    return name


def _get_var_reg(var):
    if isinstance(var, _stack.StackVar):
        return bi.Reg.RSP
    elif var.arg_num == 0:
        return bi.Reg.R6
    assert False, 'Only support a single arg right now'


def _get_cdata_size(var_type):
    assert issubclass(var_type, _ctypes._SimpleCData)
    return {
        8: bi.Size.Quad,
        4: bi.Size.Word,
        2: bi.Size.Short,
        1: bi.Size.Byte
    }[ctypes.sizeof(var_type)]


def _convert_var(var):
    if isinstance(var, _mem.ConstVar):
        assert issubclass(var.var_type, _ctypes._SimpleCData)
        # TODO: handle non-int types...
        return bi.Imm(var.val.value)
    elif isinstance(var, _stack.StackVar) or isinstance(var, _mem.ArgVar):
        sz = _get_cdata_size(var.var_type)
        return bi.Mem(_get_var_reg(var), var.offset, sz)
    elif all([not isinstance(var, t) for t in [
            bi.Reg, bi.Mem, bi.Imm, bi.Imm64, bi.MapFdImm]]):
        raise NotImplemented('StackVar, ArgVar, ConstVar, what am I missing?')

    return var


def _mov_const(val_type, val, reg, offset):
    if issubclass(val_type, FileDescriptorDatastructure):
        return (_mov(bi.MapFdImm(val.fd), bi.Reg.R0) +
                _mov(bi.Reg.R0, bi.Mem(reg, offset, bi.Size.Quad)))

    if issubclass(val_type, _ctypes._SimpleCData):
        # They may have passed us a vanilla int here
        if hasattr(val, 'value'):
            val = val.value
        dst_mem = bi.Mem(reg, offset, _get_cdata_size(val_type))
        return [bi.Mov(bi.Imm(val), dst_mem)]
    ret = []
    if issubclass(val_type, ctypes.Array):
        for i in range(val_type._length_):
            el_off = offset + ctypes.sizeof(val_type._type_) * i
            el = val[i] if i < len(val) else val_type._type_()
            ret.extend(_mov_const(val_type._type_, el, reg, el_off))
    else:
        for f, t in val_type._fields_:
            f_val = getattr(val, f)
            f_off = getattr(val_type, f).offset
            ret.extend(_mov_const(t, f_val, reg, offset + f_off))
    return ret


def _mov(src, dst):
    if isinstance(src, _mem.ConstVar) and isinstance(dst, _stack.StackVar):
        return _mov_const(src.var_type, src.val, _get_var_reg(dst), dst.offset)

    src, dst = _convert_var(src), _convert_var(dst)
    if isinstance(src, bi.Mem) and isinstance(dst, bi.Mem):
        return [
            bi.Mov(src, bi.Reg.R0),
            bi.Mov(bi.Reg.R0, dst)
        ]
    else:
        return [bi.Mov(src, dst)]


def _lea(i, src, dst, stack, **kwargs):
    if issubclass(src.var_type, FileDescriptorDatastructure):
        if not isinstance(src, _mem.ConstVar):
            raise TranslationError(
                i.starts_line,
                'Cannot handle non-const file descriptor datastructures')
        return _mov(bi.MapFdImm(src.val.fd), dst)

    setup = []
    if isinstance(src, _mem.ConstVar):
        # We have to lay it down in memory ourselves, sadly
        tmp_src = stack.alloc(src.var_type)
        tmp_reg = _get_var_reg(tmp_src)
        setup = _mov_const(src.var_type, src.val, tmp_reg, tmp_src.offset)
        src = tmp_src

    # TODO: fix types. Right now, dt may by a ulong for addrof, because we
    # can't plug in real return types yet.
    # if not isinstance(dst, bi.Reg):
    #     st, dt = src.var_type, dst.var_type
    #     assert issubclass(dt,_types.Ptr) and dt.var_type == st

    reg = _get_var_reg(src)
    if src.offset == 0:
        return setup + _mov(reg, dst)
    else:
        return (
            setup +
            [bi.Mov(reg, bi.Reg.R0), bi.Add(bi.Imm(src.offset), bi.Reg.R0)] +
            _mov(bi.Reg.R0, dst)
        )


def _memcpy(i, dst_reg, src_reg, num_bytes):
    ret = []
    # Unpack ctype
    if hasattr(num_bytes, 'value'):
        num_bytes = num_bytes.value

    for i in range(num_bytes):
        sm = bi.Mem(src_reg, i, bi.Size.Byte)
        dm = bi.Mem(dst_reg, i, bi.Size.Byte)
        ret.extend(_mov(sm, dm))

    return ret


@_opcode_translate(dis.OpCode.JUMP_FORWARD)
def _jump_forward(i, **kwargs):
    return [
        bi.Jump('label_{}'.format(i.argval))
    ]


def _call_load_skb(i, sz):
    fn, skb, off = i.src_vars
    dst = i.dst_vars[0]

    if not isinstance(skb, _mem.ArgVar):
        raise TranslationError(
            i.starts_line, 'First argument to {} must be skb context'.format(
                fn.val.name))

    if isinstance(off, _mem.ConstVar):
        # Unbox ctypes
        off_val = off.val
        if hasattr(off_val, 'value'):
            off_val = off_val.value
        return [bi.LoadSkb(bi.Imm(off_val), sz)] + _mov(bi.Reg.R0, dst)
    else:
        return (
            _mov(off, bi.Reg.R0) +
            [bi.LoadSkb(bi.Reg.R0, sz)] +
            _mov(bi.Reg.R0, dst)
        )


def _call_load_skb_byte(i, **kwargs):
    return _call_load_skb(i, bi.Size.Byte)


def _call_load_skb_short(i, **kwargs):
    return _call_load_skb(i, bi.Size.Short)


def _call_load_skb_word(i, **kwargs):
    return _call_load_skb(i, bi.Size.Word)


def _call_packet_copy(i, **kwargs):
    # If you're thinking 'wow, this function looks complicated,' just go
    # take a look at kernel/bpf/verifier.c:find_good_pkt_pointers to see
    # the hoops that we're jumping through here.
    ret = []
    fn, skb, offset, dst_ptr, num_bytes = i.src_vars

    # TODO: also support ptr to context?
    if not isinstance(skb, _mem.ArgVar):
        raise TranslationError(
            i.starts_line,
            'First argument to packet_copy must be SkBuffContext argument')
    elif not isinstance(num_bytes, _mem.ConstVar):
        raise TranslationError(
            i.starts_line,
            'Num bytes must not be dynamically defined for packet_copy')

    skb_data_mem = bi.Mem(
        _get_var_reg(skb), skb.var_type.data.offset, bi.Size.Word)
    skb_data_end_mem = bi.Mem(
        _get_var_reg(skb), skb.var_type.data_end.offset, bi.Size.Word)

    out_of_bounds = _make_tmp_label()

    ret = _mov(dst_ptr, bi.Reg.R1)

    # %r2 = skb->data
    ret.append(bi.Mov(skb_data_mem, bi.Reg.R2))

    # %r2 += offset
    if isinstance(offset, _mem.ConstVar):
        off_val = offset.val
        if hasattr(off_val, 'value'):
            off_val = off_val.value
        if off_val != 0:
            ret.append(bi.Add(bi.Imm(off_val), bi.Reg.R2))
    else:
        ret.extend(_mov(offset, bi.Reg.R3))
        ret.append(bi.Add(bi.Reg.R3, bi.Reg.R2))

    # %r3 = %r2
    ret.append(bi.Mov(bi.Reg.R2, bi.Reg.R3))

    # %r2 += num_bytes
    ret.append(bi.Add(bi.Imm(num_bytes.val), bi.Reg.R2))

    # %r4 = skb->data_end
    ret.append(bi.Mov(skb_data_end_mem, bi.Reg.R4))

    # if skb->data + offset + num_bytes > skb->data_end: goto out_of_bounds
    ret.append(bi.JumpIfGreaterThan(bi.Reg.R4, bi.Reg.R2, out_of_bounds))

    ret.extend(_memcpy(i, bi.Reg.R1, bi.Reg.R3, num_bytes.val))

    ret.append(bi.Label(out_of_bounds))

    return ret


def _call_memcpy(i, **kwargs):
    fn, dst_addr, src_addr, num_bytes = i.src_vars
    if not isinstance(num_bytes, _mem.ConstVar):
        raise TranslationError(i.starts_line, 'memcpy amount must be constant')

    return (
        _mov(src_addr, bi.Reg.R1) +
        _mov(dst_addr, bi.Reg.R2) +
        _memcpy(i, bi.Reg.R1, bi.Reg.R2, num_bytes.val)
    )


def _call_addrof(i, **kwargs):
    return _lea(i, i.src_vars[1], i.dst_vars[0], **kwargs)


def _call_ptr(i, **kwargs):
    return _mov(i.src_vars[1], i.dst_vars[0])


def _call_deref(i, **kwargs):
    sz = _get_cdata_size(i.dst_vars[0].var_type)
    return (_mov(i.src_vars[1], bi.Reg.R0) +
            _mov(bi.Mem(bi.Reg.R0, 0, sz), i.dst_vars[0]))


def _call_mem_eq(i, **kwargs):
    if (not isinstance(i.src_vars[1], _mem.ConstVar) or
            not issubclass(i.src_vars[1].var_type, ctypes.Array)):
        raise TranslationError(
            i.starts_line, 'first arg to mem_eq must be const ctypes.Array')
    ret = []

    # stack=None because we shouldn't need to allocate anything
    ret.extend(_lea(i, i.src_vars[2], bi.Reg.R2, stack=None))

    false, done = _make_tmp_label(), _make_tmp_label()
    for off, v in enumerate(i.src_vars[1].val.value):
        ret.extend([
            bi.Mov(bi.Mem(bi.Reg.R2, off, bi.Size.Byte), bi.Reg.R1),
            bi.JumpIfNotEqual(bi.Imm(v), bi.Reg.R1, false)
        ])

    # If we made it here, it's a match
    ret.extend(_mov(bi.Imm(1), i.dst_vars[0]))
    ret.append(bi.Jump(done))

    # if we jumped here, it's not a match
    ret.append(bi.Label(false))
    ret.extend(_mov(bi.Imm(0), i.dst_vars[0]))
    ret.append(bi.Label(done))

    return ret


def _call_pseudo_function(i, **kwargs):
    fn = i.src_vars[0].val
    if fn.name == 'memcpy':
        return _call_memcpy(i, **kwargs)
    elif fn.name == 'addrof':
        return _call_addrof(i, **kwargs)
    elif fn.name == 'ptr':
        return _call_ptr(i, **kwargs)
    elif fn.name == 'deref':
        return _call_deref(i, **kwargs)
    elif fn.name == 'packet_copy':
        return _call_packet_copy(i, **kwargs)
    elif fn.name == 'load_skb_byte':
        return _call_load_skb_byte(i, **kwargs)
    elif fn.name == 'load_skb_short':
        return _call_load_skb_short(i, **kwargs)
    elif fn.name == 'load_skb_word':
        return _call_load_skb_word(i, **kwargs)
    elif fn.name == 'mem_eq':
        return _call_mem_eq(i, **kwargs)
    else:
        raise TranslationError(
            i.starts_line, 'Reference to invalid pseudo-function: {}'.format(
                fn.name))


@_opcode_translate(dis.OpCode.CALL_FUNCTION)
def _call_function(i, **kwargs):
    fn_var = i.src_vars[0]
    if not isinstance(fn_var, _mem.ConstVar):
        raise TranslationError(
            i.starts_line, 'Function may not be determined dynamically')
    fn = fn_var.val

    if isinstance(fn, funcs.PseudoFunc):
        return _call_pseudo_function(i, **kwargs)

    if not isinstance(fn, funcs.Func):
        raise TranslationError(
            i.starts_line, 'Function must be bpf function from py2bpf.funcs')
    if fn.num_args != -1 and len(i.src_vars) != fn.num_args + 1:
        raise TranslationError(
            i.starts_line, 'Function "{}" expected {} arguments, got {}'.format(
                fn.name, fn.num_args, len(i.src_vars) - 1))
    arg_regs = [bi.Reg.R1, bi.Reg.R2, bi.Reg.R3, bi.Reg.R4, bi.Reg.R5]

    ret = []

    # See explanation for this nonsense in funcs.py
    arg_vars = []
    for idx, var in enumerate(i.src_vars[1:]):
        arg_vars.append(var)
        if idx in fn.fill_array_size_args:
            if issubclass(var.var_type, _types.Ptr):
                length = ctypes.sizeof(var.var_type.var_type)
            else:
                length = ctypes.sizeof(var.var_type)
            arg_vars.append(_mem.ConstVar(ctypes.c_uint64(length)))

    # Put the arguments into appropriate registers
    for arg, reg in zip(arg_vars, arg_regs):
        if issubclass(arg.var_type, _ctypes._SimpleCData):
            ret.extend(_mov(arg, reg))
        else:
            ret.extend(_lea(i, arg, reg, **kwargs))

    # Call the function
    ret.append(bi.Call(bi.Imm(fn.num)))

    # Move the result, if we haven't ignored it
    if len(i.dst_vars) > 0:
        ret.extend(_mov(bi.Reg.R0, i.dst_vars[0]))

    return ret


@_opcode_translate(dis.OpCode.COMPARE_OP)
def _compare_op(i, **kwargs):
    lhs, rhs = i.src_vars

    op = i.argval
    if op == '<':
        lhs, rhs = rhs, lhs
        op = '>'
    elif op == '<=':
        lhs, rhs = rhs, lhs
        op = '>='

    jmp_type = {
        '>': bi.JumpIfGreaterThan,
        '>=': bi.JumpIfGreaterOrEqual,
        '==': bi.JumpIfEqual,
        '!=': bi.JumpIfNotEqual,
    }[op]

    true, done = _make_tmp_label(), _make_tmp_label()
    return (
        _mov(lhs, bi.Reg.R1) +
        _mov(rhs, bi.Reg.R2) +
        [jmp_type(bi.Reg.R1, bi.Reg.R2, true)] +
        _mov(bi.Imm(0), i.dst_vars[0]) +
        [bi.Jump(done)] +
        [bi.Label(true)] +
        _mov(bi.Imm(1), i.dst_vars[0]) +
        [bi.Label(done)]
    )


@_opcode_translate(dis.OpCode.POP_JUMP_IF_FALSE)
def _pop_jump_if_false(i, **kwargs):
    return (
        _mov(i.src_vars[0], bi.Reg.R1) +
        [bi.JumpIfEqual(bi.Imm(0), bi.Reg.R1, 'label_{}'.format(i.argval))]
    )


@_opcode_translate(dis.OpCode.POP_JUMP_IF_TRUE)
def _pop_jump_if_true(i, **kwargs):
    return (
        _mov(i.src_vars[0], bi.Reg.R1) +
        [bi.JumpIfNotEqual(bi.Imm(0), bi.Reg.R1, 'label_{}'.format(i.argval))]
    )


def _is_ptr(var_type):
    return issubclass(var_type, _types.Ptr)


@_opcode_translate(dis.OpCode.STORE_FAST)
def _store_fast(i, **kwargs):
    sv, dv = i.src_vars[0], i.dst_vars[0]
    if _is_ptr(dv.var_type) and not _is_ptr(sv.var_type):
        return _lea(i, sv, dv, **kwargs)
    return _mov(sv, dv)


@_opcode_translate(dis.OpCode.LOAD_FAST)
def _load_fast(i, **kwargs):
    return _mov(i.src_vars[0], i.dst_vars[0])


def _binary_op(i, Op):
    return (
        _mov(i.src_vars[0], bi.Reg.R0) +
        _mov(i.src_vars[1], bi.Reg.R1) +
        [Op(bi.Reg.R1, bi.Reg.R0)] +
        _mov(bi.Reg.R0, i.dst_vars[0])
    )


@_opcode_translate(dis.OpCode.BINARY_TRUE_DIVIDE)
def _binary_true_divide(i, **kwargs):
    return _binary_op(i, bi.Divide)


@_opcode_translate(dis.OpCode.BINARY_FLOOR_DIVIDE)
def _binary_floor_divide(i, **kwargs):
    return _binary_op(i, bi.Divide)


@_opcode_translate(dis.OpCode.BINARY_MULTIPLY)
def _binary_multiply(i, **kwargs):
    return _binary_op(i, bi.Multiply)


@_opcode_translate(dis.OpCode.BINARY_ADD)
def _binary_add(i, **kwargs):
    return _binary_op(i, bi.Add)


@_opcode_translate(dis.OpCode.BINARY_SUBTRACT)
def _binary_subtract(i, **kwargs):
    return _binary_op(i, bi.Sub)


@_opcode_translate(dis.OpCode.BINARY_AND)
def _binary_and(i, **kwargs):
    return _binary_op(i, bi.BitAnd)


@_opcode_translate(dis.OpCode.BINARY_OR)
def _binary_or(i, **kwargs):
    return _binary_op(i, bi.BitOr)


@_opcode_translate(dis.OpCode.BINARY_RSHIFT)
def _binary_rshift(i, **kwargs):
    return _binary_op(i, bi.RightShift)


@_opcode_translate(dis.OpCode.BINARY_LSHIFT)
def _binary_lshift(i, **kwargs):
    return _binary_op(i, bi.LeftShift)


@_opcode_translate(dis.OpCode.RETURN_VALUE)
def _return_value(i, **kwargs):
    if not issubclass(i.src_vars[0].var_type, _ctypes._SimpleCData):
        raise TranslationError(
            i.starts_line, 'Must return int from function. Type is {}'.format(
                repr(i.src_vars[0].var_type)))

    return _mov(i.src_vars[0], bi.Reg.R0) + [bi.Ret()]


def _get_attr_type(svt, name):
    for f, t in svt._fields_:
        if f == name:
            return t
    assert False, 'Programmer error: missing attr should have been found before'


def _load_attr_val(i, **kwargs):
    sv, dv = i.src_vars[0], i.dst_vars[0]
    name = i.argval
    if issubclass(sv.var_type, _types.Ptr):
        sz = _get_cdata_size(_get_attr_type(sv.var_type.var_type, name))
        off = getattr(sv.var_type.var_type, i.argval).offset
        return _mov(sv, bi.Reg.R0) + _mov(bi.Mem(bi.Reg.R0, off, sz), dv)
    else:
        assert isinstance(sv, _stack.StackVar) or isinstance(sv, _mem.ArgVar)
        sz = _get_cdata_size(_get_attr_type(sv.var_type, name))
        off = getattr(sv.var_type, i.argval).offset
        reg = _get_var_reg(sv)
        if isinstance(sv, _stack.StackVar):
            off += sv.offset

        return _mov(bi.Mem(reg, off, sz), dv)


def _load_attr_addr(i, **kwargs):
    sv, dv = i.src_vars[0], i.dst_vars[0]
    if _is_ptr(sv.var_type):
        off = getattr(sv.var_type.var_type, i.argval).offset
        return (
            _mov(sv, bi.Reg.R0) +
            ([bi.Add(bi.Imm(off), bi.Reg.R0)] if off != 0 else []) +
            _mov(bi.Reg.R0, dv)
        )
    else:
        off = getattr(sv.var_type, i.argval).offset
        assert isinstance(sv, _stack.StackVar) or isinstance(sv, _mem.ArgVar)
        if isinstance(sv, _stack.StackVar):
            off += sv.offset
        return (
            _mov(_get_var_reg(sv), bi.Reg.R0) +
            ([bi.Add(bi.Imm(off), bi.Reg.R0)] if off != 0 else []) +
            _mov(bi.Reg.R0, dv)
        )


@_opcode_translate(dis.OpCode.LOAD_ATTR)
def _load_attr(i, **kwargs):
    if issubclass(i.dst_vars[0].var_type, _types.Ptr):
        return _load_attr_addr(i, **kwargs)
    else:
        return _load_attr_val(i, **kwargs)


@_opcode_translate(dis.OpCode.STORE_ATTR)
def _store_attr(i, **kwargs):
    val, obj = i.src_vars
    reg = _get_var_reg(obj)
    off = getattr(obj.var_type, i.argval).offset
    if isinstance(obj, _stack.StackVar):
        off += obj.offset
    for f, t in obj.var_type._fields_:
        if f == i.argval:
            sz = _get_cdata_size(t)
            return _mov(val, bi.Mem(reg, off, sz))
    assert False, 'Unreachable. Programmer error?'


def _load_arr_element_addr(i, arr, index, dst_reg):
    if not isinstance(index, _mem.ConstVar):
        raise TranslationError(
            i.starts_line, 'Illegal to use dynamic index to array')

    if _is_ptr(arr.var_type):
        el_off = index.val.value * ctypes.sizeof(arr.var_type.var_type._type_)
        ret = _mov(arr, dst_reg)
    else:
        el_off = index.val.value * ctypes.sizeof(arr.var_type._type_) + arr.offset
        ret = [bi.Mov(_get_var_reg(arr), dst_reg)]

    if el_off != 0:
        ret.append(bi.Add(bi.Imm(el_off), dst_reg))

    return ret

def _binary_subscr_arr(i):
    arr, index, dv = i.src_vars[0], i.src_vars[1], i.dst_vars[0]

    vt = arr.var_type
    if _is_ptr(arr.var_type):
        vt = vt.var_type

    op_sz = _get_cdata_size(vt._type_)

    return (
        _load_arr_element_addr(i, arr, index, bi.Reg.R0) +
        _mov(bi.Mem(bi.Reg.R0, 0, op_sz), bi.Reg.R0) +
        _mov(bi.Reg.R0, dv)
    )


def _binary_subscr_map(i, **kwargs):
    m, k, dv = i.src_vars[0], i.src_vars[1], i.dst_vars[0]
    if not isinstance(m, _mem.ConstVar):
        raise TranslationError(
            i.starts_line, 'Cannot subscript dynamically select map')

    found, done = _make_tmp_label(), _make_tmp_label()
    ret = []
    ret.extend(_mov(bi.MapFdImm(m.val.fd), bi.Reg.R1))
    ret.extend(_lea(i, k, bi.Reg.R2, **kwargs))
    ret.extend([
        bi.Call(bi.Imm(funcs.map_lookup_elem.num)),
    ])


    if _is_ptr(dv.var_type):
        sz = _get_cdata_size(dv.var_type)
        ret.extend(_mov(bi.Reg.R0, dv))
    else:
        ret.extend([
            bi.JumpIfNotEqual(bi.Imm(0), bi.Reg.R0, found),
        ])

        # Move default value
        dr = _get_var_reg(dv)
        ret.extend(_mov_const(dv.var_type, m.val.DEFAULT_VALUE, dr, dv.offset))

        ret.extend([
            bi.Jump(done),
            bi.Label(found),
        ])

        # Primitives by value, others by reference
        if issubclass(dv.var_type, _ctypes._SimpleCData):
            sz = _get_cdata_size(dv.var_type)
            ret.extend(_mov(bi.Mem(bi.Reg.R0, 0, sz), dv))
        else:
            ret.extend(_mov(bi.Reg.R0, dv))

        ret.append(bi.Label(done))

    return ret


@_opcode_translate(dis.OpCode.BINARY_SUBSCR)
def _binary_subscr(i, **kwargs):
    vt = i.src_vars[0].var_type
    if _is_ptr(vt):
        vt = vt.var_type
    if issubclass(vt, ctypes.Array):
        return _binary_subscr_arr(i)
    else:
        return _binary_subscr_map(i, **kwargs)


def _store_subscr_arr(i):
    val, arr, index = i.src_vars
    op_sz = _get_cdata_size(arr.var_type._type_)

    return (
        _load_arr_element_addr(i, arr, index, bi.Reg.R0) +
        _mov(val, bi.Reg.R1) +
        _mov(bi.Reg.R1, bi.Mem(bi.Reg.R0, 0, op_sz))
    )


def _store_subscr_map(i, **kwargs):
    v, m, k = i.src_vars
    if not isinstance(m, _mem.ConstVar):
        raise TranslationError(
            i.starts_line, 'Cannot subscript dynamically selected map')
    return (
        [bi.Mov(bi.MapFdImm(m.val.fd), bi.Reg.R1)] +
        _lea(i, k, bi.Reg.R2, **kwargs) +
        _lea(i, v, bi.Reg.R3, **kwargs) + [
            bi.Mov(bi.Imm(0), bi.Reg.R4),
            bi.Call(bi.Imm(funcs.map_update_elem.num))
        ]
    )


@_opcode_translate(dis.OpCode.STORE_SUBSCR)
def _store_subscr(i, **kwargs):
    if issubclass(i.src_vars[1].var_type, ctypes.Array):
        return _store_subscr_arr(i)
    else:
        return _store_subscr_map(i, **kwargs)


@_opcode_translate(dis.OpCode.DELETE_SUBSCR)
def _delete_subscr(i, **kwargs):
    if issubclass(i.src_vars[1].var_type, ctypes.Array):
        raise TranslationError(i.starts_line, 'Cannot delete from array')

    m, k = i.src_vars
    if not isinstance(m, _mem.ConstVar):
        raise TranslationError(
            i.starts_line, 'Cannot delete from dynamically selected map')

    return (
        [bi.Mov(bi.MapFdImm(m.val.fd), bi.Reg.R1)] +
        _lea(i, k, bi.Reg.R2, **kwargs) +
        [bi.Call(bi.Imm(funcs.map_delete_elem.num))]
    )


@_opcode_translate(dis.OpCode.INPLACE_ADD)
def _inplace_add(i, **kwargs):
    return (
        _mov(i.src_vars[0], bi.Reg.R0) +
        _mov(i.src_vars[1], bi.Reg.R1) +
        [bi.Add(bi.Reg.R1, bi.Reg.R0)] +
        _mov(bi.Reg.R0, i.dst_vars[0])
    )


def _label(i):
    return [bi.Label('label_{}'.format(i.offset))]


@dis.opcode_key_wrapper
def translate(vis, verbose=False, **kwargs):
    def verbose_fn(*args, **kwargs):
        if verbose:
            print(*args, **kwargs)

    insns_to_info = {}

    ret = _mov(bi.Reg.R1, bi.Reg.R6)
    for i in vis:
        insns_to_info[len(ret)] = str(i)
        if isinstance(i, _labels.Label):
            new = _label(i)
        else:
            new = _opcode_translators[i.opcode](i, **kwargs)
        ret.extend(new)
        verbose_fn('Op:', i)
        for ni in new:
            verbose_fn('>', ni)
        verbose_fn()

    return ret, insns_to_info
