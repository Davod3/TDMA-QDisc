// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_tbf.c	Token Bucket Filter queue.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Dmitry Torokhov <dtor@mail.ru> - allow attaching inner qdiscs -
 *						 original idea by Martin Devera
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>

#include "tc_tdma.h"


/*	Simple Token Bucket Filter.
	=======================================

	SOURCE.
	-------

	None.

	Description.
	------------

	A data flow obeys TBF with rate R and depth B, if for any
	time interval t_i...t_f the number of transmitted bits
	does not exceed B + R*(t_f-t_i).

	Packetized version of this definition:
	The sequence of packets of sizes s_i served at moments t_i
	obeys TBF, if for any i<=k:

	s_i+....+s_k <= B + R*(t_k - t_i)

	Algorithm.
	----------

	Let N(t_i) be B/R initially and N(t) grow continuously with time as:

	N(t+delta) = min{B/R, N(t) + delta}

	If the first packet in queue has length S, it may be
	transmitted only at the time t_* when S/R <= N(t_*),
	and in this case N(t) jumps:

	N(t_* + 0) = N(t_* - 0) - S/R.



	Actually, QoS requires two TBF to be applied to a data stream.
	One of them controls steady state burst size, another
	one with rate P (peak rate) and depth M (equal to link MTU)
	limits bursts at a smaller time scale.

	It is easy to see that P>R, and B>M. If P is infinity, this double
	TBF is equivalent to a single one.

	When TBF works in reshaping mode, latency is estimated as:

	lat = max ((L-B)/R, (L-M)/P)


	NOTES.
	------

	If TBF throttles, it starts a watchdog timer, which will wake it up
	when it is ready to transmit.
	Note that the minimal timer resolution is 1/HZ.
	If no new packets arrive during this period,
	or if the device is not awaken by EOI for some previous packet,
	TBF can stop its activity for 1/HZ.


	This means, that with depth B, the maximal rate is

	R_crit = B*HZ

	F.e. for 10Mbit ethernet and HZ=100 the minimal allowed B is ~10Kbytes.

	Note that the peak rate TBF is much more tough: with MTU 1500
	P_crit = 150Kbytes/sec. So, if you need greater peak
	rates, use alpha with HZ=1000 :-)

	With classful TBF, limit is just kept for backwards compatibility.
	It is passed to the default bfifo qdisc - if the inner qdisc is
	changed the limit is not effective anymore.
*/

struct tdma_sched_data {
/* Parameters */
	u32		limit;		/* Maximal length of backlog: bytes */

	s64 t_frame;
	s64 t_slot;
	s64	t_offset;			/* Time check-point */

	struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue */
	struct qdisc_watchdog watchdog;	/* Watchdog timer */
};


/* GSO packet is too big, segment it so that tdma can transmit
 * each segment in time
 */
static int tdma_segment(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct sk_buff *segs, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	// unsigned int len = 0, prev_len = qdisc_pkt_len(skb);
	unsigned int len = 0;
	// int ret, nb;
	int ret, nb, nt;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs))
		return qdisc_drop(skb, sch, to_free);

	nb = 0;
	nt = 0;
	skb_list_walk_safe(segs, segs, nskb) {
		skb_mark_not_on_list(segs);
		qdisc_skb_cb(segs)->pkt_len = segs->len;
		// len += segs->len;
		len = segs->len;
		ret = qdisc_enqueue(segs, q->qdisc, to_free);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret))
				qdisc_qstats_drop(sch);
			printk(KERN_DEBUG "drop\t%u\t(gso %d)\n", len, nt + 1);
		} else {
			printk(KERN_DEBUG "enqueue\t%u\t(gso %d)\n", len, nt + 1);

			sch->qstats.backlog += len;
			sch->q.qlen++;
			nb++;
		}
		nt++;
	}
	// sch->q.qlen += nb;
	// if (nb > 1)
	// 	qdisc_tree_reduce_backlog(sch, 1 - nb, prev_len - len);
	consume_skb(skb);
	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int tdma_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb), max_len = psched_mtu(qdisc_dev(sch));
	int ret;

	if (qdisc_pkt_len(skb) > max_len) {
		if (skb_is_gso(skb) && skb_gso_validate_mac_len(skb, max_len))
			return tdma_segment(skb, sch, to_free);

		printk(KERN_DEBUG "drop\t%u\t(gso)\n", len);

		return qdisc_drop(skb, sch, to_free);
	}

	ret = qdisc_enqueue(skb, q->qdisc, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);

		printk(KERN_DEBUG "drop\t%u\n", len);

		return ret;
	}

	printk(KERN_DEBUG "enqueue\t%u\n", len);

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *tdma_dequeue(struct Qdisc *sch)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	s64 now;

	now = ktime_get_ns();
	while (now >= q->t_offset + q->t_frame)
		q->t_offset += q->t_frame;
	while (now < q->t_offset)
		q->t_offset -= q->t_frame;

	if (q->qdisc->ops->peek(q->qdisc)) {
		if (!(now >= q->t_offset + q->t_slot)) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;
				
			printk(KERN_DEBUG "dequeue\t%u\n", qdisc_pkt_len(skb));

			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			qdisc_bstats_update(sch, skb);
			return skb;
		}

		qdisc_watchdog_schedule_ns(&q->watchdog, q->t_frame - (now - q->t_offset));
	}

	return NULL;
}

static void tdma_reset(struct Qdisc *sch)
{
	struct tdma_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	qdisc_reset(q->qdisc);
}

static const struct nla_policy tdma_policy[TCA_TDMA_MAX + 1] = {
	[TCA_TDMA_PARMS] = { .len = sizeof(struct tc_tdma_qopt) },
};

static int tdma_change(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	int err;
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_TDMA_MAX + 1];
	struct tc_tdma_qopt *qopt;

	err = -EINVAL;
	if (!opt)
		return err;

	err = nla_parse_nested_deprecated(tb, TCA_TDMA_MAX, opt, tdma_policy, NULL);
	if (err < 0)
		return err;

	err = -EINVAL;
	if (tb[TCA_TDMA_PARMS] == NULL)
		return err;

	qopt = nla_data(tb[TCA_TDMA_PARMS]);

	if (qopt->limit > 0) {
		err = fifo_set_limit(q->qdisc, qopt->limit);
		if (err)
			return err;
	}


	sch_tree_lock(sch);

	q->limit = q->qdisc->limit;

	q->t_frame = qopt->t_frame;
	q->t_slot = qopt->t_slot;
	q->t_offset += qopt->t_offset;

	sch_tree_unlock(sch);

	if (qopt->t_offset)
		qdisc_watchdog_schedule_ns(&q->watchdog, 0);
	

	return 0;
}

static int tdma_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct tdma_sched_data *q = qdisc_priv(sch);

	// q->qdisc = &noop_qdisc;
	q->qdisc = fifo_create_dflt(sch, &bfifo_qdisc_ops, qdisc_dev(sch)->tx_queue_len * psched_mtu(qdisc_dev(sch)), extack);
	if (IS_ERR(q->qdisc))
		return PTR_ERR(q->qdisc);
	qdisc_hash_add(q->qdisc, true);

	qdisc_watchdog_init(&q->watchdog, sch);
	q->t_offset = ktime_get_ns();

	return tdma_change(sch, opt, extack);
}

static void tdma_destroy(struct Qdisc *sch)
{
	struct tdma_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	qdisc_put(q->qdisc);
}

static int tdma_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;
	struct tc_tdma_qopt opt;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;


	opt.limit = q->limit;

	opt.t_frame = q->t_frame;
	opt.t_slot = q->t_slot;
	opt.t_offset = q->t_offset;
	

	if (nla_put(skb, TCA_TDMA_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}


static struct Qdisc_ops tdma_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.id			=	"tdma",
	.priv_size	=	sizeof(struct tdma_sched_data),
	.enqueue	=	tdma_enqueue,
	.dequeue	=	tdma_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	tdma_init,
	.reset		=	tdma_reset,
	.destroy	=	tdma_destroy,
	.change		=	tdma_change,
	.dump		=	tdma_dump,
	.owner		=	THIS_MODULE,
};

static int __init tdma_module_init(void)
{
	return register_qdisc(&tdma_qdisc_ops);
}

static void __exit tdma_module_exit(void)
{
	unregister_qdisc(&tdma_qdisc_ops);
}
module_init(tdma_module_init)
module_exit(tdma_module_exit)
MODULE_LICENSE("GPL");
