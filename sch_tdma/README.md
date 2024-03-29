# TDMA Documentation

## Usage
The module may be interacted with via `rtnetlink` messages. This may be done indirectly, via (an extension of) the `tc` command line tool, or directly (programatically), via `rtnetlink` messages, as in the userspace driver program `tc_tdma.c`.

### Warning
Be sure that the copy of `tc_tdma.h` used to compile `tc_tdma.so` is identical to that used to compile `sch_tdma.ko`; in particular, be sure the same `tc_tdma_qopt` is available to both.

## Build

### Module
```
make
insmod sch_tdma.ko
```

### Module Driver
```
gcc -I . -I ./include/ -c tc_tdma.c -o tc_tdma.o
gcc tc_tdma.o ./lib/libutil.a ./lib/libnetlink.a -o tc_tdma
```
The following are dependencies of `tc_tdma.c`:
- `tc_tdma.h`: definition of `struct tc_tdma_qopt`
- `libnetlink.h`: definitions of netlink types, macros, functions
- `libnetlink.a`: archive corresponding to `libnetlink.h` (can be copied from `/iproute/lib/` once `iproute` has been built, or may be built locally)
- `libutil.a`: dependency of `libnetlink.a`

### TC Extension
See `/iproute2/README.md` for build instructions. In order to use the `tc` CLI to configure or monitor the qdisc options, `q_tdma.so` must be located in `TC_LIB_DIR`; otherwise, `tc` will be unable to monitor qdisc options via `tc qdisc show`. A comparison of output with and without this dependency is as follows:
-   ```
    root@localhost:~/sources/modules/tc_tdma# tc -s -d -r qdisc show
    qdisc noqueue 0:[00000000] dev lo root refcnt 2 
    Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
    backlog 0b 0p requeues 0
    qdisc tdma 8017:[80170000] dev enp0s1 root refcnt 2 [Unknown qdisc, optlen=60] 
    Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
    backlog 0b 0p requeues 0

    ```
-   ```
    root@localhost:~/sources/modules/tc_tdma# export TC_LIB_DIR=/usr/lib/tc
    root@localhost:~/sources/modules/tc_tdma# tc -s -d -r qdisc show
    qdisc noqueue 0:[00000000] dev lo root refcnt 2 
    Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
    backlog 0b 0p requeues 0
    qdisc tdma 8017:[80170000] dev enp0s1 root refcnt 2 rate 220Kbit burst 1540b/1 mpu 0b [000d59f8] lat 50ms limit 2915b linklayer ethernet frame 1000000000 slot 100000000 
    Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
    backlog 0b 0p requeues 0
    ```
Despite this, `tc` will still be able to report on statistics such as packet drops and backlogs (as long as these are recorded correctly by the underlying qdisc).


## Implementation
The module tracks three values: `t_frame`, `t_slot`, and `t_c`, all in nanoseconds. Whenever `dequeue` is called, the value of `t_c` is adjusted such that `t_c <= now < t_c + t_frame` (`now = ktime_get_ns()`). The frame offset is thus `now - t_c`, and if this value is less than `t_slot`, the module is allowed to `dequeue`; otherwise, the module will sleep, setting a watchdog timer to wake it up at the start of the next slot, in `t_frame - (now - t_c)` nanoseconds. Essentially `t_c` functions as an offset pointer, so shifting this value will cause the module to shift its transmission window by the corresponding amount (modulo `t_frame`).

## TODOs
- As noted above, work is in progress to make use of `rtnetlink` to set TDMA parameters (frame size, slot size, and frame offset) programatically. This is particularly important for the purpose of setting the offset of the TDMA frame, as nodes in communication may often become out-of-sync, and the algorithm must be able to recover without wasting slots or communicating during another node's slot.\
One simple approach is to reset the value of `t_c` to the current time whenever a `change` call occurs. In this way, even with no parameter changes made, the module will be made to shift its slot to begin at the moment the `change` call occurred. Otherwise, a more robust approach is to provide a `t_offset` value by which `t_c` is adjusted.
- Clean out the implementation details relevant to TBF
- Combine the build of the module, userspace driver, and `tc` CLI extension into a single `Makefile`
- Resolve the `libnetlink` and `libutil` dependencies of the userspace driver (and `tc` CLI extension) without needing a local instance of `iproute2`