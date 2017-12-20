#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

import ctypes
import enum
import errno
import fcntl
import mmap
import multiprocessing
import os
import resource
import select

import py2bpf._bpf._syscall as _syscall
import py2bpf._bpf._perf_event as pe
from py2bpf._translation._datastructures import (
    FileDescriptorDatastructure, RuntimeDatastructure
)


class BpfMapType(enum.IntEnum):
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7


class _BpfAttrMapCreate(ctypes.Structure):
    _fields_ = [
        ('map_type', ctypes.c_uint),
        ('key_size', ctypes.c_uint),
        ('value_size', ctypes.c_uint),
        ('max_entries', ctypes.c_uint),
        ('map_flags', ctypes.c_uint),
    ]


class _BpfAttrMapElem(ctypes.Structure):
    _fields_ = [
        ('map_fd', ctypes.c_uint),
        ('key', ctypes.c_char_p),
        ('value_or_next_key', ctypes.c_char_p),
        ('flags', ctypes.c_char_p),
    ]


class _MapCmd(enum.IntEnum):
    CREATE = 0
    LOOKUP_ELEM = 1
    UPDATE_ELEM = 2
    DELETE_ELEM = 3
    GET_NEXT_KEY = 4


def _map_create(map_type, key_size, value_size, max_entries):
    attr = _BpfAttrMapCreate(
        map_type=map_type,
        key_size=key_size,
        value_size=value_size,
        max_entries=max_entries,
        map_flags=0
    )
    fd = _syscall.bpf(_MapCmd.CREATE, ctypes.pointer(attr), ctypes.sizeof(attr))
    if fd < 0:
        eno = _syscall._get_errno()
        raise OSError(eno, 'Failed to create bpf map: {}'.format(
            os.strerror(eno)))
    return fd


def _update_elem(fd, key, value):
    key_p = ctypes.cast(ctypes.pointer(key), ctypes.c_char_p)
    value_p = ctypes.cast(ctypes.pointer(value), ctypes.c_char_p)
    attr = _BpfAttrMapElem(
        map_fd=fd,
        key=key_p,
        value_or_next_key=value_p,
        flags=0,
    )
    attr_p = ctypes.pointer(attr)
    if _syscall.bpf(_MapCmd.UPDATE_ELEM, attr_p, ctypes.sizeof(attr)) != 0:
        eno = _syscall._get_errno()
        raise OSError(eno, 'Failed to update bpf map: {}'.format(
            os.strerror(eno)))


class BpfMap(FileDescriptorDatastructure):
    def __init__(self, max_entries):
        self.fd = -1
        key_size = ctypes.sizeof(self.KEY_TYPE)
        value_size = ctypes.sizeof(self.VALUE_TYPE)
        self.fd = _map_create(BpfMapType.HASH, key_size, value_size, max_entries)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)

    def __getitem__(self, key):
        if not isinstance(key, self.KEY_TYPE):
            key = self.KEY_TYPE(key)
        return self.lookup(key)

    def __setitem__(self, key, value):
        if not isinstance(key, self.KEY_TYPE):
            key = self.KEY_TYPE(key)
        if not isinstance(value, self.VALUE_TYPE):
            value = self.VALUE_TYPE(value)
        self.update(key, value)

    def __delitem__(self, key):
        if not isinstance(key, self.KEY_TYPE):
            key = self.KEY_TYPE(key)
        self.delete(key)

    def update(self, key, value):
        if not isinstance(key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(key), repr(self.KEY_TYPE)))

        if not isinstance(value, self.VALUE_TYPE):
            raise TypeError('value {} is not instance of value_type {}'.format(
                repr(value), repr(self.VALUE_TYPE)))

        _update_elem(self.fd, key, value)

    def lookup(self, key):
        if not isinstance(key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(key), repr(self.KEY_TYPE)))

        key_p = ctypes.cast(ctypes.pointer(key), ctypes.c_char_p)

        value = self.VALUE_TYPE()
        value_p = ctypes.cast(ctypes.pointer(value), ctypes.c_char_p)
        attr = _BpfAttrMapElem(
            map_fd=self.fd,
            key=key_p,
            value_or_next_key=value_p,
            flags=0,
        )
        attr_p = ctypes.pointer(attr)
        ret = _syscall.bpf(_MapCmd.LOOKUP_ELEM, attr_p, ctypes.sizeof(attr))
        if ret == 0:
            return value

        eno = _syscall._get_errno()
        if eno == errno.ENOENT:
            raise KeyError(key)

        raise OSError(eno, 'Failed to lookup bpf map: {}'.format(
            os.strerror(eno)))

    def delete(self, key):
        if not isinstance(key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(key), repr(self.KEY_TYPE)))

        key_p = ctypes.cast(ctypes.pointer(key), ctypes.c_char_p)
        attr = _BpfAttrMapElem(map_fd=self.fd, key=key_p, flags=0)
        attr_p = ctypes.pointer(attr)

        ret = _syscall.bpf(_MapCmd.DELETE_ELEM, attr_p, ctypes.sizeof(attr))
        if ret == 0:
            return

        eno = _syscall._get_errno()
        if eno == errno.ENOENT:
            raise KeyError(key)

        raise OSError(eno, 'Failed to lookup bpf map: {}'.format(
            os.strerror(eno)))

    def get_next_key(self, last_key):
        if not isinstance(last_key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(last_key), repr(self.KEY_TYPE)))
        key_p = ctypes.cast(ctypes.pointer(last_key), ctypes.c_char_p)

        next_key = self.KEY_TYPE()
        next_key_p = ctypes.cast(ctypes.pointer(next_key), ctypes.c_char_p)

        attr = _BpfAttrMapElem(
            map_fd=self.fd,
            key=key_p,
            value_or_next_key=next_key_p,
            flags=0,
        )
        attr_p = ctypes.pointer(attr)
        ret = _syscall.bpf(_MapCmd.GET_NEXT_KEY, attr_p, ctypes.sizeof(attr))
        if ret == 0:
            return next_key

        eno = _syscall._get_errno()
        if eno == errno.ENOENT:
            return None

        raise OSError(eno, 'Failed to get next key: {}'.format(
            os.strerror(eno)))

    def keys(self):
        keys = []
        last_key = self.KEY_TYPE()
        while True:
            next_key = self.get_next_key(last_key)
            if next_key is None:
                return keys
            keys.append(next_key)
            last_key = next_key

    def items(self):
        return [(k, self.lookup(k)) for k in self.keys()]


def create_map(key_type, value_type, max_entries, default=None):
    class MapClass(BpfMap):
        KEY_TYPE = key_type
        VALUE_TYPE = value_type
        DEFAULT_VALUE = default if default is not None else value_type()

    return MapClass(max_entries)


PERF_MAX_STACK_DEPTH = 127


class BpfStackTraceMap(BpfMap):
    KEY_TYPE = ctypes.c_uint32
    VALUE_TYPE = ctypes.c_uint64 * PERF_MAX_STACK_DEPTH

    def __init__(self, max_entries):
        self.fd = -1
        key_size = ctypes.sizeof(self.KEY_TYPE)
        value_size = ctypes.sizeof(self.VALUE_TYPE)
        self.fd = _map_create(
            BpfMapType.STACK_TRACE, key_size, value_size, max_entries)

    def __del__(self):
        if self.fd >= 0:
            os.close(self.fd)

    def __getitem__(self, key):
        if not isinstance(key, self.KEY_TYPE):
            key = self.KEY_TYPE(key)
        return self.lookup(key)

    def __delitem__(self, key):
        if not isinstance(key, self.KEY_TYPE):
            key = self.KEY_TYPE(key)
        self.delete(key)

    def lookup(self, key):
        if not isinstance(key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(key), repr(self.KEY_TYPE)))

        key_p = ctypes.cast(ctypes.pointer(key), ctypes.c_char_p)

        value = self.VALUE_TYPE()
        value_p = ctypes.cast(ctypes.pointer(value), ctypes.c_char_p)
        attr = _BpfAttrMapElem(
            map_fd=self.fd,
            key=key_p,
            value_or_next_key=value_p,
            flags=0,
        )
        attr_p = ctypes.pointer(attr)
        ret = _syscall.bpf(_MapCmd.LOOKUP_ELEM, attr_p, ctypes.sizeof(attr))
        if ret == 0:
            return value

        eno = _syscall._get_errno()
        if eno == errno.ENOENT:
            raise KeyError(key)

        raise OSError(eno, 'Failed to lookup bpf map: {}'.format(
            os.strerror(eno)))

    def delete(self, key):
        if not isinstance(key, self.KEY_TYPE):
            raise TypeError('key {} is not instance of key_type {}'.format(
                repr(key), repr(self.KEY_TYPE)))

        key_p = ctypes.cast(ctypes.pointer(key), ctypes.c_char_p)
        attr = _BpfAttrMapElem(map_fd=self.fd, key=key_p, flags=0)
        attr_p = ctypes.pointer(attr)

        ret = _syscall.bpf(_MapCmd.DELETE_ELEM, attr_p, ctypes.sizeof(attr))
        if ret == 0:
            return

        eno = _syscall._get_errno()
        if eno == errno.ENOENT:
            raise KeyError(key)

        raise OSError(eno, 'Failed to lookup bpf map: {}'.format(
            os.strerror(eno)))


class PerfQueue:
    def __init__(self, data_type, cpu, num_pages=9):
        self.mm_fd = -1
        self.data_type = data_type

        try:
            attr = pe.PerfEventAttr()
            attr.type = pe.PERF_TYPE_SOFTWARE
            attr.config = pe.PERF_COUNT_SW_BPF_OUTPUT
            attr.sample_type = pe.PERF_SAMPLE_RAW
            self.mm_fd = pe.perf_event_open(attr, cpu=cpu)
            if self.mm_fd < 0:
                eno = _syscall._get_errno()
                raise OSError(eno, 'Failed to create perf event: {}'.format(
                    os.strerror(eno)))

            fcntl.ioctl(self.mm_fd, pe.PERF_EVENT_IOC_ENABLE, 0)
            self.pagesz = resource.getpagesize()
            self.mm = mmap.mmap(self.mm_fd, num_pages * self.pagesz)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.mm_fd > 0:
            os.close(self.mm_fd)
            self.mm_fd = -1

    def __iter__(self):
        self.items = []
        return self

    def __next__(self):
        while len(self.items) == 0:
            self.items.extend(self.get_items())
        return self.items.pop()

    def get_items(self, timeout_ms=1000):
        if timeout_ms != 0:
            p = select.poll()
            p.register(self.mm_fd, select.POLLIN)
            p.poll(timeout_ms)
            p.unregister(self.mm_fd)

        class Sample(ctypes.Structure):
            _pack_ = 1
            _fields_ = [
                ('header', pe.PerfEventHeader),
                ('size', ctypes.c_uint32),
                ('data', self.data_type)
            ]

        items = []
        page = pe.PerfEventMmapPage.from_buffer(self.mm)
        begin, end = page.data_tail + self.pagesz, page.data_head + self.pagesz
        while begin != end:
            header = pe.PerfEventHeader.from_buffer(self.mm, begin)
            if header.type == pe.PERF_RECORD_SAMPLE:
                s = Sample.from_buffer(self.mm, begin)
                items.append(s.data)
            elif header.type == pe.PERF_RECORD_LOST:
                print('lost')
            begin += header.size

        page.data_tail = page.data_head

        return items


class BpfQueue(FileDescriptorDatastructure):
    def __init__(self, data_type, num_pages=9):
        self.queues = {}

        self.fd = _map_create(
            BpfMapType.PERF_EVENT_ARRAY, 4, 4, multiprocessing.cpu_count())

        for cpu in range(multiprocessing.cpu_count()):
            q = PerfQueue(data_type, cpu, num_pages)
            _update_elem(self.fd, ctypes.c_int(cpu), ctypes.c_int(q.mm_fd))
            self.queues[cpu] = q


    def close(self):
        for cpu, q in self.queues.items():
            q.close()
        self.queues = {}

        if self.fd > 0:
            os.close(self.fd)
            self.fd = -1

    def __iter__(self):
        self.items = []
        return self

    def __next__(self):
        while len(self.items) == 0:
            self.items.extend(self.get_items())
        return self.items.pop()

    def get_items(self, timeout_ms=1000):
        p = select.poll()
        for cpu, q in self.queues.items():
            p.register(q.mm_fd, select.POLLIN)
        p.poll(timeout_ms)
        for cpu, q in self.queues.items():
            p.unregister(q.mm_fd)

        items = []
        for cpu, q in self.queues.items():
            items.extend(q.get_items(timeout_ms=0))

        return items

    def get_cpu_queue(self, cpu):
        return self.queues[cpu]
