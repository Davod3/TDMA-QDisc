# TDMA QDisc Implementation/Kernel Internals

## Setup
To build the kernel module, invoke the appropriate Makefile.

In what follows, `[kmod_name]` was originally `sch_tdma`; in the current branch it is defined to be `tdma`.

```
ifneq (${KERNELRELEASE},)

obj-m := [kmod_name].o

else

KDIR := /lib/modules/`uname -r`/build
MDIR := `pwd`

default:
    $(MAKE) -C $(KDIR) M=$(MDIR)

endif
```

```
./make
insmod [kmod_name].ko
```

## Parameters
The main data structure to communicate with the kernel module is `struct tc_tdma_qopt`. Ensure this `struct` and the `enum`s `TCA_TDMA_*` are defined in the included header file (previously `tc_tdma.h`, now `netlink_sock.h`).

The options correspond to the `TCA_TDMA_PARMS` field of the QDisc options (the full structure of the netlink message is detailed in the Implementation/Netlink subsection). The parameters of a `struct tc_tdma_qopt qopt` are as follows:
- `qopt->limit` (in bytes; default is `dev->tx_queue_len`, where `dev` is the device associated with this instance of the `tdma` qdisc)
- `qopt->t_frame` (in nanoseconds; default is `1`)
- `qopt->t_slot` (in nanoseconds; default is `1`)
- `qopt->t_offset` (in nanoseconds; default is `0`)

If any of these options are set to `0`, it is assumed they are to be left unchanged. Note that if the default options are kept, then the QDisc will behave indistinguishably from the default `bfifo` QDisc.

Together with these, two optional flags may also be passed via rtnetlink, namely `TCA_TDMA_OFFSET_FUTURE`, and `TCA_TDMA_OFFSET_RELATIVE`. They have the following effects:
- `TCA_TDMA_OFFSET_FUTURE`: if set, and if `dequeue` is called when `now < q->t_offset`, then do not recompute the internal offset `q->t_offset`, and set the watchdog timer for `q->t_offset - now` time units. This is used particularly when it is desired to delay transmission for longer than `t_frame` time units; otherwise, within `t_frame` time units, `q->t_offset` would have been recomputed.
- `TCA_TDMA_OFFSET_RELATIVE`: if set, then the internal offset is set by `q->t_offset = now + qopt->t_offset` rather than being incremented by `q->t_offset += qopt->t_offset`. This is used when it is desired to delay the transmission window relative to the current instant (synchronous, e.g. setting a delay relative to an event that triggered the parameter update), rather than delaying the transmission window relative to its prior position (asynchronous).

Note that here and elsewhere `q->t_offset` refers to the internal offset parameter, as measured in absolute time since the kernel started (via `CLOCK_MONOTONIC`; this is why it can be compared against `now`). Meanwhile `qopt->t_offset` refers to the supplied offset parameter, and is interpreted as a delta (how much to shift the transmission window by).

There may be a desire in the future for an optional flag `TCA_TDMA_SPLIT_GSO`; the default behavior at present is indeed to split GSO packets (the implementation is found in `tdma_enqueue` and `tdma_segment`).

## Implementation

### Enqueue
The TDMA QDisc enqueues all packets when they arrive, assuming the `txqueue` of its device is not full. Otherwise, they are dropped.

Some of the packets received here are marked as `GSO` and have lengths larger than the `MTU` of the transmission device. They may be directly enqueued or may be segmented into their constituent packets before enqueueing.

### Dequeue
The TDMA QDisc acts as a filter over when packets are allowed to be `dequeue`d. The `q->t_offset` field is recomputed if necessary on each `dequeue` call, and depending on the result, it is determined whether there are any packets to be `dequeue`d.

The `q->t_offset` field is computed such that the following are true: `q->t_offset <= now < q->t_offset + q->t_frame` and `(q->t_offset - q->t_offset_prev) % q->t_frame == 0`. That is, the `q->t_offset` field is computed to as the base of the current transmission window, where the transmission window moves in steps of size `q->t_frame`.

Then if it also holds that `q->t_offset <= now < q->t_offset + q->t_slot`, a packet is `dequeue`d; otherwise, the watchdog timer is set for another `q->t_frame - (now - q->t_offset)` time units (i.e. the start of the next transmission window).

```
t_offset
|                      t_offset + t_frame
|         now          |
|         |            |
v         v            v
----------.-------------
| t_on | t_off         |
----------.-------------

|------| <------------------- t_slot
          |------------| <--- t_frame - (now - t_offset)
|----------------------| <--- t_frame
```

The one exception to this behavior of `t_offset` is when `TCA_TDMA_OFFSET_FUTURE` is set. In this case, if `t_offset` is found to be set in the future, then `t_offset` is not recomputed (yet), and the timer is set to wake up the module when `now == t_offset`. This allows the module to account for intentional delays of magnitude greater than `t_frame`.

### Init
The QDisc receives the contents of the `TCA_OPTIONS`. No processing is done immediately. Rather, the QDisc's internal state structure (a `struct tdma_sched_data`) is populated with the default values for each parameter as described above, including setting a null child QDisc and instantiating the watchdog timer. The contents of `TCA_OPTIONS` is then passed to the `change` method.

### Change
The QDisc receives the contents of the `TCA_OPTIONS`. The options are unpacked (un-nested), and the resulting parameters are briefly validated. If this is also the first `change` invocation, then a `bfifo` child QDisc is created.

Once the parameters have been validated, the QDisc tree lock is acquired in order to populate the entries of its internal state structure (`struct tdma_sched_data`) based on the parameters that were provided (`struct tc_tdma_qopt` along with the optional flags). The tree lock is then released, and the watchdog timer is set to zero in order to trigger an immediate `dequeue` (in order to check whether it is now time to transmit or whether the watchdog needs to be set for a later time).

### Dump
The QDisc copies the `q->{limit,t_{frame,slot,offset}}` fields of its `struct tdma_sched_data` into the `qopt->{limit,t_{frame,slot,offset}}` fields of a `struct tc_tdma_qopt`, respectively. This is packed into the `TCA_OPTIONS` message field and passed back to userspace by the kernel. The kernel will also have populated `TCA_KIND`, `TCA_STATS`, and `TCA_STATS2` (detailed further in the Netlink subsection).

### Netlink

The template below demonstrates how to construct a simple rtnetlink message in order to add, change, or delete the `"tdma"` QDisc. The `librtnetlink` header, source, and associated examples may be found in `dev-gryan`. `librtnetlink.{c,h}` consist of `libnetlink.{c,h}` minus external dependencies. See https://man7.org/linux/man-pages/man3/libnetlink.3.html for an overview.

```
#include <netlink.h>
#include <rtnetlink.h>
#include <librtnetlink.h>

struct rtnl_handle rth;

int cmd = RTM_NEWQDISC, flags = NLM_F_CREATE | NLM_F_EXCL; // add QDisc
int cmd = RTM_NEWQDISC, flags = 0; // change QDisc options
int cmd = RTM_DELQDISC, flags = 0; // delete QDisc

int qdisc_dev = 1; // Device index
char *qdisc_kind = "tdma"; // QDisc name
struct tc_tdma_qopt opt; // QDisc options

struct {
    struct nlmsghdr n;
    struct tcmsg t;
    char buf[64 * 1024];
} req = {
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg))
    .n.nlmsg_flags = NLM_F_REQUEST | flags,
    .n.nlmsg_type = cmd,
    .t.tcm_family = AF_UNSPEC,
    .t.tcm_ifindex = qdisc_dev,
    .t.tcm_parent = TC_H_ROOT,
};

struct rtattr *tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
addattr_l(&req.n, 1024, TCA_TDMA_PARMS, opt, sizeof(*opt)); // required parameter
// addattr32(&req.n, 1024, TCA_TDMA_OFFSET_FUTURE, 1); // optional parameter; ignored if not added
// addattr32(&req.n, 1024, TCA_TDMA_OFFSET_RELATIVE, 1); // optional parameter; ignored if not added
addattr_nest_end(&req.n, tail);

addattr_l(&req.n, sizeof(req), TCA_KIND, qdisc_kind, strlen(qdisc_kind) + 1);

rtnl_open(&rth, 0); // returns < 0 on error
rtnl_talk(&rth, &req.n, NULL); // returns < 0 on error
rtnl_close(&rth);
```

The following message fields should be of note (these and others are defined in `rtnetlink.h`):
- `TCA_OPTIONS`: sent and received; the only `nlattr` which is directly passed to the QDisc's `init` and `change` methods, thus typically a nested `nlattr`
- `TCA_KIND`: sent and received; self-explanatory
- `TCA_STATS`: received only; deprecated (a subset of the information provided by `TCA_STATS2`)
- `TCA_STATS2`: received only; a nested `nlattr` consisting of `TCA_STATS2_{BASIC,QUEUE}` subfields (among others) corresponding to a `struct gnet_stats_{basic,queue}` (see `gen_stats.h`)

The `struct rtnl_handle` structure holds a socket, tracks sequence numbers, along with some other housekeeping tasks. The `rtnl_{open,close}` methods bring up/tear down the state variables in the handle structure. The `rtnl_talk` method transmits a fully-formed rtnetlink message. The `addattr*` methods perform alignment and validation against the attributes being packed into the message. Importantly, the `addattr_nest{,_end}` methods allow nesting the options attributes expected by the QDisc, and the `addattr_l` method allows adding arbitrarily-sized bytestreams as attributes.

Not discussed here is the process of eliciting a data dump from the QDisc. This is somewhat more involved, requiring a `rtnl_request_dump_n` call followed by passing `rtnl_filter` a callback to filter the response for the desired entries. The callback should use `parseattr*` methods to unpack the returned attributes. It is expected a better, more targeted approach for data dumps is possible via `genetlink`. For the time being however, to view the QDisc's "basic" (total seen bytes/packets) and "queue" (total queued bytes/packets, total dropped packets) statistics, it suffices to use the `tc qdisc show` command.

See https://man7.org/linux/man-pages/man7/netlink.7.html, https://man7.org/linux/man-pages/man3/rtnetlink.3.html, or some of the archived sources in `dev-gryan` for how to bypass the `lib{,rt}netlink` helpers. See https://man7.org/linux/man-pages/man3/netlink.3.html for a list of netlink helper macros. See https://man7.org/linux/man-pages/man7/rtnetlink.7.html for a more comprehensive list of the rtnetlink-specific `nlmsg_flags`, message structures, and attribute fields.
