# `py2bpf`

`py2bpf` translates functions from python to bpf, which is a linux kernel
bytecode.

## Caveat Emptor

This project is the working material behind a [pycon
talk](https://www.youtube.com/watch?v=CpqMroMBGP4), and not really a full
formed or fleshed out projects. It's essentially unsupported, so use at
your own risk.

## What is `bpf`?

bpf is a virtual machine bytecode that can be executed in the linux kernel
in a variety of different places as hooks. You can hook things like packet
arrival (at the socket with socket filter, within tc, or even within the
NIC with xdp), software events (with kprobe and uprobe), and more.

In order to ensure safety, many operations are illegal in bpf, including
arbitrary memory access, loops, recursion, and backward jumps. Instructions
first pass through a verifier. On some architectures like x86_64, this
bytecode is then compiled to raw machine code, so it's very low-overhead to
execute.

## Partial Evaluation

Obviously most python functionality is not available within bpf, so we need
to evaluate as much of the program as we can before handing it off to be
switched. To do, we convert all global loads and dereferences into
constants and then evaluate things as far down the line as we can. As a
result, the following would be permitted:

```
    packet_short = py2bpf.funcs.load_skb_short(24)
    if packet_short == socket.htons(12345):
         return 0
```

Because `socket.htons(12345)` can be eagerly evaluated to `0x3930`. The
following *will not* work, because we'd need to evaluate it in the bpf
context where `socket.htons` is not available.

```
    packet_short = py2bpf.funcs.load_skb_short(24)
    # DOES NOT WORK!!!
    if socket.ntohs(packet_short) == 12345:
         return 0
```

## Datastructures

py2bpf supports native bpf datastructures like map. These datastructures
can be transparently shared between functions compiled to bpf and the
userspace processes associated with them. For example, you could implement
a socket filter that simply counts packets by protocol using the following.

```
m = py2bpf.datastructures.create_map(ctypes.c_uint32, ctypes.c_uint64, 16)
def filter_fn(skb):
    m[skb.protocol] += 1
    return 0
```

In the above example, you could reference the result from other python
functions with something like.

```
for proto, count in m.items():
    print('{} => {}'.format(proto, count))
```

You can also use bpf perf queues.

```
q = py2bpf.datastructures.BpfQueue(ctypes.c_int)

@py2bpf.kprobe.probe('sys_close')
def on_sys_close(pt_regs):
    pid = py2bpf.funcs.get_current_pid_tgid() & 0xfffffff
    ptr = py2bpf.funcs.addrof(pid)
    cpuid = py2bpf.funcs.get_smp_processor_id()
    py2bpf.funcs.perf_event_output(pt_regs, q, cpuid, ptr)
    return 0


with on_sys_close():
    for pid in q:
        print('pid={}'.format(pid))
```

## Helpers

Limitations in the bpf bytecode mean that a lot of functionality is
provided via helper functions which can be called from bpf programs. These
helpers appear to you as simple python functions which can be invoked in
compiled functions. For example, the following will issue a printk to
`/sys/kernel/debug/tracing/trace_pipe`.

```
def fn(ctx):
    ...
    py2bpf.funcs.trace_printk("Hello World!")
    ...
```

These functions are generally described in `/usr/include/linux/bpf.h`. The
major difference in signature is that it's annoying in python to have to
specify the array or string and then the length, so we provide the length
transparently instead (see `fill_array_size_args` in
`py2bpf/funcs.py:Func`).

## Examples

See more examples in `py2bpf/examples/`, but here is the abbreviated version.

### Socket Filters

Socket filtering was the original usecase of bpf (which actually stands for
"Berkeley Packet Filter"). Here, we write a function that matches only
IPv6/TCP connections.

```
def match(skb):
    if skb.protocol != socket.htons(ETH_P_IP):
        return 0
    elif py2bpf.funcs.load_skb_byte(skb, 23) != socket.IPPROTO_TCP:
        return 0
    else:
        return skb.len

sf = py2bpf.socket_filter.SocketFilter(match)
sf.attach(raw_sock)
raw_sock.recv(...)  # And then do recv stuff
```

### Kprobes

Kernel probes allow you to trace individual execution points within the
linux kernel. The following example will simply print out the name of the
calling program every time a connect is started.

```
@py2bpf.kprobe.probe('sys_nanosleep')
def watch_nanosleep(pt_regs):
    return 0

with watch_nanosleep():
    # do things
```


### Traffic Control

`tc` is a utility that allows you to do everything from traffic shaping to
filtering. It has classifiers, which identify traffic; and actions, which
act upon traffic. You can implement either in bpf. Here's an example of a
classifier paired with the drop action which allows us to filter incoming
IPv4 traffic.

```
def drop_fn(skb):
    if skb.protocol == socket.htons(ETH_P_IP):
        return 1
    return 0
fil = py2bpf.tc.IngressFilter(drop_fn)
fil.install()
fil.close()
```

Note that the filter in this case outlives the process. You must called
`clear_ingress_filter` to get rid of it.

See also: man tc(8)
