#!/usr/bin/env python3

# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from setuptools import setup


setup(
    name='py2bpf',
    version='0.1',
    description='A python to bpf (Berkeley Packet Filter bytecode) converter',
    author='Alex Gartrell',
    author_email='agartrell@fb.com',
    url='http://github.com/facebookresearch/py2bpf',
    license='BSD',
    packages=[
        'py2bpf',
        'py2bpf._bpf',
        'py2bpf._translation'
    ],
    package_dir={
        'py2bpf': '.',
        'py2bpf._bpf': '_bpf',
        'py2bpf._translation': '_translation',
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
    ],
    keywords='bpf',
)
