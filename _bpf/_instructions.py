#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import enum
import struct


class _Op(enum.IntEnum):
    BPF_LD = 0x00
    BPF_LDX = 0x01
    BPF_ST = 0x02
    BPF_STX = 0x03
    BPF_ALU = 0x04
    BPF_JMP = 0x05
    BPF_RET = 0x06
    BPF_ALU64 = 0x07

    BPF_W = 0x00
    BPF_H = 0x08
    BPF_B = 0x10
    BPF_IMM = 0x00
    BPF_ABS = 0x20
    BPF_IND = 0x40
    BPF_MEM = 0x60
    BPF_LEN = 0x80
    BPF_MSH = 0xa0

    BPF_ADD = 0x00
    BPF_SUB = 0x10
    BPF_MUL = 0x20
    BPF_DIV = 0x30
    BPF_OR = 0x40
    BPF_AND = 0x50
    BPF_LSH = 0x60
    BPF_RSH = 0x70
    BPF_NEG = 0x80
    BPF_MOD = 0x90
    BPF_XOR = 0xa0

    BPF_JA = 0x00
    BPF_JEQ = 0x10
    BPF_JGT = 0x20
    BPF_JGE = 0x30
    BPF_JSET = 0x40
    BPF_K = 0x00
    BPF_X = 0x08

    BPF_DW = 0x18
    BPF_XADD = 0xc0

    BPF_MOV = 0xb0
    BPF_ARSH = 0xc0

    BPF_END = 0xd0
    BPF_TO_LE = 0x00
    BPF_TO_BE = 0x08

    BPF_JNE = 0x50
    BPF_JSGT = 0x60
    BPF_JSGE = 0x70
    BPF_CALL = 0x80
    BPF_EXIT = 0x90


class _Insn(ctypes.Structure):
    _fields_ = [
        ('code', ctypes.c_uint8),
        ('dst', ctypes.c_uint8, 4),
        ('src', ctypes.c_uint8, 4),
        ('off', ctypes.c_int16),
        ('imm', ctypes.c_int32),
    ]

    def __repr__(self):
        return '_Insn({}, {}, {}, {}, {})'.format(
            self.code, self.dst, self.src, self.off, self.imm)


def _size_to_op(sz):
    return {
        8: _Op.BPF_DW,
        4: _Op.BPF_W,
        2: _Op.BPF_H,
        1: _Op.BPF_B,
    }[sz]


class Reg(enum.IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    RSP = 10


class Size(enum.IntEnum):
    Quad = _Op.BPF_DW
    Word = _Op.BPF_W
    Short = _Op.BPF_H
    Byte = _Op.BPF_B


class Instruction:
    def to_insn(self):
        raise NotImplementedError()


class Label:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'Label({})'.format(self.name)


class Mem:
    def __init__(self, reg, off, size):
        self.reg, self.off, self.size = reg, off, size

    def __repr__(self):
        return 'Mem({}, {}, {})'.format(self.reg, self.off, self.size)


class Imm:
    def __init__(self, value):
        if hasattr(value, 'value'):  # Handle ctype primitives
            value = value.value
        if isinstance(value, bytes):
            value = struct.unpack('b', value)[0]
        self.value = value

    def __repr__(self):
        return 'Imm({})'.format(self.value)


class Imm64:
    def __init__(self, value):
        if hasattr(value, 'value'):  # Handle ctype primitives
            value = value.value
        if isinstance(value, bytes):
            value = struct.unpack('b', value)[0]
        self.value = value

    def __repr__(self):
        return 'Imm64({})'.format(self.value)


class MapFdImm(Imm64):
    def __init__(self, fd):
        self.fd = fd

    def __repr__(self):
        return 'MapFdImm({})'.format(self.fd)


class Mov(Instruction):
    def __init__(self, src, dst):
        self.src, self.dst = src, dst
        self._raw()  # type-check

    def __repr__(self):
        return 'Mov({}, {})'.format(self.src, self.dst)

    def _raw(self):
        if isinstance(self.dst, Mem):
            if isinstance(self.src, Reg):
                return _Insn(
                    code=_Op.BPF_STX | _Op.BPF_MEM | int(self.dst.size),
                    src=int(self.src),
                    dst=int(self.dst.reg),
                    off=int(self.dst.off),
                )
            elif isinstance(self.src, Imm):
                return _Insn(
                    code=_Op.BPF_ST | _Op.BPF_MEM | int(self.dst.size),
                    imm=int(self.src.value),
                    dst=int(self.dst.reg),
                    off=int(self.dst.off),
                )
            else:
                raise TypeError('Mov to Mem must have Imm or Reg src')
        elif isinstance(self.dst, Reg):
            if isinstance(self.src, Mem):
                return _Insn(
                    code=_Op.BPF_LDX | _Op.BPF_MEM | int(self.src.size),
                    src=int(self.src.reg),
                    off=int(self.src.off),
                    dst=int(self.dst),
                )
            elif isinstance(self.src, Reg):
                return _Insn(
                    code=_Op.BPF_ALU64 | _Op.BPF_MOV | _Op.BPF_X,
                    src=int(self.src),
                    dst=int(self.dst),
                )
            elif isinstance(self.src, Imm):
                return _Insn(
                    code=_Op.BPF_ALU64 | _Op.BPF_MOV | _Op.BPF_K,
                    dst=int(self.dst),
                    imm=int(self.src.value),
                )
            elif isinstance(self.src, MapFdImm):
                return [
                    _Insn(
                        code=_Op.BPF_LD | _Op.BPF_IMM | _Op.BPF_DW,
                        src=1,  # BPF_PSEUDO_MAP_FD
                        dst=int(self.dst),
                        imm=self.src.fd & 0xFFFFFFFF,
                    ),
                    _Insn(
                        imm=self.src.fd >> 32,
                    ),
                ]
            elif isinstance(self.src, Imm64):
                return [
                    _Insn(
                        code=_Op.BPF_LD | _Op.BPF_IMM | _Op.BPF_DW,
                        dst=int(self.dst),
                        imm=self.src.value & 0xFFFFFFFF,
                    ),
                    _Insn(
                        imm=self.src.value >> 32,
                    ),
                ]
            else:
                raise TypeError('Mov to Reg must have Mem, Reg, or Imm source')
        else:
            raise TypeError('Mov must be to Mem or Reg')


class _Alu64(Instruction):
    def __init__(self, src, dst):
        self.src, self.dst = src, dst
        self._raw()  # type-check

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__, self.src, self.dst)

    def _raw(self):
        if not isinstance(self.dst, Reg):
            raise TypeError('Alu dst must be reg')
        if isinstance(self.src, Imm):
            return _Insn(
                code=_Op.BPF_ALU64 | self.ALU_OP_CODE | _Op.BPF_K,
                imm=self.src.value,
                dst=int(self.dst),
            )
        elif isinstance(self.src, Reg):
            return _Insn(
                code=_Op.BPF_ALU64 | self.ALU_OP_CODE | _Op.BPF_X,
                src=int(self.src),
                dst=int(self.dst),
            )
        else:
            raise TypeError('Alu src must be Reg or Imm')


class Add(_Alu64):
    ALU_OP_CODE = _Op.BPF_ADD


class Sub(_Alu64):
    ALU_OP_CODE = _Op.BPF_SUB


class Modulo(_Alu64):
    ALU_OP_CODE = _Op.BPF_MOD


class Multiply(_Alu64):
    ALU_OP_CODE = _Op.BPF_MUL


class Divide(_Alu64):
    ALU_OP_CODE = _Op.BPF_DIV


class LeftShift(_Alu64):
    ALU_OP_CODE = _Op.BPF_LSH


class RightShift(_Alu64):
    ALU_OP_CODE = _Op.BPF_RSH


class BitAnd(_Alu64):
    ALU_OP_CODE = _Op.BPF_AND


class BitOr(_Alu64):
    ALU_OP_CODE = _Op.BPF_OR


class BitXor(_Alu64):
    ALU_OP_CODE = _Op.BPF_XOR


class _Jump(Instruction):
    pass


class _CondJump(_Jump):
    def __init__(self, src, dst, target):
        self.src, self.dst, self.target = src, dst, target
        self._raw(0)  # type-check

    def __repr__(self):
        return '{}({}, {}, {})'.format(
            self.__class__.__name__, self.src, self.dst,
            repr(self.target))

    def _raw(self, jump_off):
        if not isinstance(self.dst, Reg):
            raise TypeError('CondJump dst must be Reg')

        if isinstance(self.src, Reg):
            return _Insn(
                code=_Op.BPF_JMP | _Op.BPF_X | self.CMP_OP_CODE,
                src=int(self.src),
                dst=int(self.dst),
                off=jump_off,
            )
        elif isinstance(self.src, Imm):
            return _Insn(
                code=_Op.BPF_JMP | _Op.BPF_K | self.CMP_OP_CODE,
                imm=self.src.value,
                dst=int(self.dst),
                off=jump_off,
            )
        else:
            raise TypeError('CondJump src must be Reg or Imm')


class JumpIfEqual(_CondJump):
    CMP_OP_CODE = _Op.BPF_JEQ


class JumpIfNotEqual(_CondJump):
    CMP_OP_CODE = _Op.BPF_JNE


class JumpIfAbove(_CondJump):
    CMP_OP_CODE = _Op.BPF_JA


class JumpIfGreaterThan(_CondJump):
    CMP_OP_CODE = _Op.BPF_JGT


class JumpIfGreaterOrEqual(_CondJump):
    CMP_OP_CODE = _Op.BPF_JGE

# TODO: am I right? What does S stand for?
#
# class JumpIfSignedGreaterThan(_CondJump):
#     CMP_OP_CODE = _Op.BPF_JSGT

# class JumpIfSignedGreaterOrEqual(_CondJump):
#     CMP_OP_CODE = _Op.BPF_JSGE


class Jump(_Jump):
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return 'Jump({})'.format(self.target)

    def _raw(self, jump_off):
        return _Insn(
            code=_Op.BPF_JMP,
            off=jump_off
        )


class Call(Instruction):
    def __init__(self, fn):
        self.fn = fn
        self._raw()  # type-check

    def __repr__(self):
        return 'Call({})'.format(self.fn)

    def _raw(self):
        if isinstance(self.fn, Imm):
            fn_num = self.fn.value
        else:
            raise TypeError('Call fn must be Imm')

        return _Insn(
            code=_Op.BPF_JMP | _Op.BPF_CALL,
            imm=fn_num,
        )


class Ret(Instruction):
    def __init__(self):
        self._raw()  # type-check

    def __repr__(self):
        return 'Ret()'

    def _raw(self):
        return _Insn(code=_Op.BPF_JMP | _Op.BPF_EXIT)


class ChangeByteOrder(Instruction):
    def __init__(self, dst, size):
        self.dst, self.size = dst, size
        self._raw()  # type-check

    def __repr__(self):
        return 'ChangeByteOrder({}, {})'.format(repr(self.dst), repr(self.size))

    def _raw(self):
        if not isinstance(self.dst, Reg):
            raise TypeError('ChangeByteOrder dst must be a Reg')
        elif self.size not in [Size.Quad, Size.Word, Size.Short]:
            raise ValueError('size must be either Quad, Word, or Short')

        return _Insn(
            code=_Op.BPF_ALU | _Op.BPF_END | _Op.BPF_TO_BE,
            imm={Size.Quad: 64, Size.Word: 32, Size.Short: 16}[self.size],
            dst=self.dst
        )


class LoadSkb(Instruction):
    def __init__(self, src, size):
        self.src, self.size = src, size
        self._raw()  # type-check

    def __repr__(self):
        return 'LoadSkb({}, {})'.format(self.src, self.size)

    def _raw(self):
        if not isinstance(self.size, Size):
            raise TypeError('LoadSkb size must be instance of Size')

        if self.size == Size.Quad:
            raise ValueError('LoadSkb cannot load Size.Quad')

        if isinstance(self.src, Reg):
            return _Insn(
                code=_Op.BPF_LD | _Op.BPF_IND | int(self.size),
                src=int(self.src),
            )
        elif isinstance(self.src, Imm):
            return _Insn(
                code=_Op.BPF_LD | _Op.BPF_ABS | int(self.size),
                imm=self.src.value,
            )
        else:
            raise TypeError('LoadSkb src must be Reg or Imm')


def convert_to_raw_instructions(prog):
    labels = {}

    raw_ops = []
    for n in prog:
        if isinstance(n, Label):
            if n.name in labels:
                raise ValueError('Redefinition of label: {}'.format(n.name))
            labels[n.name] = len(raw_ops)
        elif isinstance(n, _Jump):
            raw_ops.append(n)  # Update later
        else:
            r = n._raw()
            if isinstance(r, list):
                raw_ops.extend(r)
            else:
                raw_ops.append(r)

    for idx, n in enumerate(raw_ops):
        if isinstance(n, _Jump):
            if n.target not in labels:
                raise ValueError('Jump to undefined label: {}'.format(n.target))
            elif labels[n.target] < idx:
                raise ValueError('Illegal jump back: {}'.format(n.target))
            raw_ops[idx] = n._raw(labels[n.target] - idx - 1)

    return (_Insn * len(raw_ops))(*raw_ops)
