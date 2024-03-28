# TC Documentation

## Build
```
export SRC_DIR=/path/to/iproute2
export LIB_DIR=/usr/lib
export TC_LIB_DIR=${LIB_DIR}/tc

cd ${SRC_DIR}
./configure
make TCSO=q_tdma.so

mkdir -p ${LIB_DIR}/tc
cp ./tc/q_tdma.so ${TC_LIB_DIR}
```

## Usage
Ensure the TDMA/TC module is built and loaded.
Once the library file is built and the environment variable set, the following commands illustrate a sample usage of the module via `tc`.
```
# display qdiscs in use
tc qdisc show

# attach the tdma qdisc to device enp0s1
tc qdisc add dev enp0s1 root tdma rate 220kbit latency 50ms burst 1540 frame 1000000000 slot 100000000

# check that tdma qdisc is attached
tc qdisc show

# reattach the tdma qdisc to device enp0s1 with new parameter values
tc qdisc change dev enp0s1 root tdma rate 220kbit latency 50ms burst 1540 frame 1000000000 slot 500000000
tc qdisc show

# reset the qdisc attached to device enp0s1 to the system default
tc qdisc del dev enp0s1 root
tc qdisc show
```

There are a number of observations made in the course of developing the `tc` frontend and associated kernel module `sch_tdma.ko`; namely,

1. The kernel module uses a pair of `struct`s to store and pass most parameter values.
    1. The frontend `struct` is called `tc_tdma_qopt`. This struct is populated by the command line arguments to `tc qdisc ...` and passed along unchanged by the frontend to the backend, together with a collection of additional parameters derived from the values in `tc_tdma_qopt`. These are packed via `addattr_nest` and `addattr_l` of the `libnetlink` library. This `struct` is defined in `tc_tdma.h` and is based on the `tc_tbf_qopt` `struct` defined in `kernel/net/sched/pkt_sched.h`, with a single parameter `param` added as proof of concept.
    1. The corresponding backend `struct` is called `tbf_sched_data`, and is accessible from the `Qdisc` `struct` `sch` (which stores qdisc state and is passed to each method implemented by a qdisc) via `qdisc_priv(sch)`.  
        1. It is populated with the values in `tc_tdma_qopt`, including `param`. This is done "manually" in `tbf_change` (which is called from `tbf_init` as well as anytime a parameter change is desired), where an instance of `tc_tdma_qopt` is unpacked from the `nlattr` `struct` passed to `tbf_change`, whose fields are then written to `tbf_sched_data`.
        1. Conversely, in `tbf_dump`, the fields of the `tbf_sched_data` `struct` are copied into a new instance of `tc_tdma_qopt`, which, along with the other "loose" parameters, is packed into `netlink` message and sent back to the frontend for display via the `tc qdisc show` command.
1. There is much room for simplification and optimization.
    1. It is recommended to consult simpler qdisc implementations' corresponding frontends and backends (e.g. `kernel/net/sched/sch_prio.c` and `iproute/tc/q_prio.c`). In particular, it seems unnecessary to pack individual parameters directly into a `netlink` message if its parameters can be stored in a single `struct` and passed as the sole parameter of the qdisc.
        1. It appears generally that the `tbf` implementation is among the most unwieldy, with both the frontend and backend performing duplicate checks for input validity. This should be resolved before migrating this setup to the current `tdma` implementation, as otherwise it is expected extensibility of the frontend would suffer.
    1. It should be verified that there is no performance loss from not using `*_offload` methods; in particular, it should be verified whether the virtual network devices in use during this project are capable of offloading or not. There appears to be no performance penalty given the testing performed thus far.
    1. It should be useful to simplify building the front and back ends of the implementation at once, particularly since they rely on a common header file, and since the frontend's dependency on `iproute2` is transient (only exists at build time).

