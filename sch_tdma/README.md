# TDMA Documentation

## Usage
The module may be interacted with via `rtnetlink` messages. This is currently possible using the `tc` command line tool, but more generally, any application making use of `rtnetlink` can do the same programatically.

### Warning
Be sure that the copy of `tc_tdma.h` used to compile `tc_tdma.so` is identical to that used to compile `sch_tdma.ko`; in particular, be sure the same `tc_tdma_qopt` is available to both.

## Build
```
make
insmod sch_tdma.ko
```

## Implementation
The module tracks three values: `t_frame`, `t_slot`, and `t_c`, all in nanoseconds. Whenever `dequeue` is called, the value of `t_c` is adjusted such that `t_c <= now < t_c + t_frame` (`now = ktime_get_ns()`). The frame offset is thus `now - t_c`, and if this value is less than `t_slot`, the module is allowed to `dequeue`; otherwise, the module will sleep, setting a watchdog timer to wake it up at the start of the next slot, in `t_frame - (now - t_c)` nanoseconds. Essentially `t_c` functions as an offset pointer, so shifting this value will cause the module to shift its transmission window by the corresponding amount (modulo `t_frame`).

## TODOs
- As noted above, work is in progress to make use of `rtnetlink` to set TDMA parameters (frame size, slot size, and frame offset) programatically. This is particularly important for the purpose of setting the offset of the TDMA frame, as nodes in communication may often become out-of-sync, and the algorithm must be able to recover without wasting slots or communicating during another node's slot.\
One simple approach is to reset the value of `t_c` to the current time whenever a `change` call occurs. In this way, even with no parameter changes made, the module will be made to shift its slot to begin at the moment the `change` call occurred. Otherwise, a more robust approach is to provide a `t_offset` value by which `t_c` is adjusted.
- Clean out the implementation details relevant to TBF