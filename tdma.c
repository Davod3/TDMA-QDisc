// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * THIS QDISC IS AN ADAPTATION OF: 
 * 
 * net/sched/sch_tbf.c	Token Bucket Filter queue.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Dmitry Torokhov <dtor@mail.ru> - allow attaching inner qdiscs -
 *						 original idea by Martin Devera
 * 
 * ADAPTED TO TDMA BY:
 * 
 * *Authors* 
 * 
 * ADAPTED TO SYNCED TDMA BY:
 * 
 * *Authors*
 */
#ifndef TDMA_K
#define TDMA_K

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
#include <net/gso.h>

#include "netlink_sock.h"

char devname[] = "wlo1"; //Change to interface that will be used
u32 limit = 0;
s64 t_frame = 0;
s64 t_slot = 0;
s64 t_offset = 0;
u32 offset_future = 0;
u32 offset_relative = 0;

EXPORT_SYMBOL(devname);
EXPORT_SYMBOL(limit);
EXPORT_SYMBOL(t_frame);
EXPORT_SYMBOL(t_slot);
EXPORT_SYMBOL(t_offset);
EXPORT_SYMBOL(offset_future);
EXPORT_SYMBOL(offset_relative);

struct tdma_sched_data {
/* Parameters */
	u32		limit;		/* Maximal length of backlog: bytes */

	s64 t_frame;
	s64 t_slot;
	s64	t_offset;			/* Time check-point */

	u32 offset_future;
	u32 offset_relative;

	struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue */
	struct qdisc_watchdog watchdog;	/* Watchdog timer */
};

static s64 intdiv(s64 a, u64 b) {
	return (((a * ((a >= 0) ? 1 : -1)) / b) * ((a >= 0) ? 1 : -1)) - ((!(a >= 0)) && (!(((a * ((a >= 0) ? 1 : -1)) % b) == 0)));
}


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

	if (IS_ERR_OR_NULL(segs)) {
		// printk(KERN_DEBUG "drop\t%u\t%s\t(gso)\n", len, qdisc_dev(sch)->name);
		printk(KERN_DEBUG "\e[0;31mdrop\t%u\t%s\t(gso)\e[0m\n", len, qdisc_dev(sch)->name);
		return qdisc_drop(skb, sch, to_free);
	}

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
			// printk(KERN_DEBUG "drop\t%u\t%s\t(gso %d)\n", len, qdisc_dev(sch)->name, nt + 1);
			printk(KERN_DEBUG "\e[0;31mdrop\t%u\t%s\t(gso %d)\e[0m\n", len, qdisc_dev(sch)->name, nt + 1);
		} else {
			// printk(KERN_DEBUG "enqueue\t%u\t%s\t(gso %d)\n", len, qdisc_dev(sch)->name, nt + 1);
			printk(KERN_DEBUG "\e[0;34menqueue\t%u\t%s\t(gso %d)\e[0m\n", len, qdisc_dev(sch)->name, nt + 1);

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

	// TODO: make choice of split-gso configurable
	if (qdisc_pkt_len(skb) > max_len) {
		if (skb_is_gso(skb) && skb_gso_validate_mac_len(skb, max_len))
			return tdma_segment(skb, sch, to_free);

		// printk(KERN_DEBUG "drop\t%u\t%s\t(gso)\n", len, qdisc_dev(sch)->name);
		printk(KERN_DEBUG "\e[0;31mdrop\t%u\t%s\t(gso)\e[0m\n", len, qdisc_dev(sch)->name);

		return qdisc_drop(skb, sch, to_free);
	}

	ret = qdisc_enqueue(skb, q->qdisc, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);

		// printk(KERN_DEBUG "drop\t%u\t%s\n", len, qdisc_dev(sch)->name);
		printk(KERN_DEBUG "\e[0;31mdrop\t%u\t%s\e[0m\n", len, qdisc_dev(sch)->name);

		return ret;
	}

	// printk(KERN_DEBUG "enqueue\t%u\t%s\n", len, qdisc_dev(sch)->name);
	printk(KERN_DEBUG "\e[0;34menqueue\t%u\t%s\e[0m\n", len, qdisc_dev(sch)->name);

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *tdma_dequeue(struct Qdisc *sch)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	s64 now = ktime_get_ns();
	s64 div_result = intdiv(now - q->t_offset, q->t_frame);
	s64 offset = q->t_offset + (div_result * q->t_frame);

	printk( KERN_DEBUG "NOW: %lld\n", now);
	printk( KERN_DEBUG "OFFSET: %lld\n", offset);
	printk( KERN_DEBUG "t_offset: %lld\n", q->t_offset);
	printk( KERN_DEBUG "INTDIV: %lld\n", div_result);



	if (!((offset <= now) && (now < (offset + q->t_frame)) && (((offset - q->t_offset) % q->t_frame) == 0)))
		printk(KERN_DEBUG "TDMA: bad offsets (%lld -> %lld @ %lld)\n", q->t_offset, offset, now);

	// // TODO: make choice of offset configurable
	if (!(q->offset_future)) {
		q->t_offset = offset;
	}

	if (q->qdisc->ops->peek(q->qdisc)) {

		if ((offset <= now) && (now < (offset + q->t_slot))) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;
				
			printk(KERN_DEBUG "DEQUEUED PACKET!!!!----------%lld------------%lld-------------%lld\n", offset, now, offset + q->t_slot);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
			qdisc_bstats_update(sch, skb);
			return skb;
		}

		qdisc_watchdog_schedule_ns(&q->watchdog, q->t_frame - (now - offset));
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
	[TCA_TDMA_OFFSET_FUTURE] = { .type = NLA_U32 },
	[TCA_TDMA_OFFSET_RELATIVE] = { .type = NLA_U32 },
};

static int tdma_change(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	int err;
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_TDMA_MAX + 1];
	struct tc_tdma_qopt *qopt;
	u32 offset_future, offset_relative;
	struct Qdisc *child;

	//printk(KERN_DEBUG "change\t\t%s", qdisc_dev(sch)->name);
	printk(KERN_DEBUG "[RA-TDMA]######################CHANGE TDMA###############\n");

	if (!opt)
		return -EINVAL;

	if ((err = nla_parse_nested_deprecated(tb, TCA_TDMA_MAX, opt, tdma_policy, NULL)) < 0)
		return err;

	if (!tb[TCA_TDMA_PARMS])
		return -EINVAL;

	offset_future = 0;
	if (tb[TCA_TDMA_OFFSET_FUTURE])
		offset_future = nla_get_u32(tb[TCA_TDMA_OFFSET_FUTURE]);
	
	offset_relative = 0;
	if (tb[TCA_TDMA_OFFSET_RELATIVE])
		offset_relative = nla_get_u32(tb[TCA_TDMA_OFFSET_RELATIVE]);

	qopt = nla_data(tb[TCA_TDMA_PARMS]);

	if ((child = q->qdisc) == &noop_qdisc) {
		if (!(child = qdisc_create_dflt(sch->dev_queue, &bfifo_qdisc_ops, sch->handle, extack)))
			return -ENOMEM;
		qdisc_hash_add(child, true);
	}

	if (qopt->limit && (err = fifo_set_limit(child, qopt->limit)) < 0)
		return err;

	// printk(KERN_DEBUG "%lld, %lld\n", q->t_offset, qopt->t_offset);

	sch_tree_lock(sch);

	q->qdisc = child;

	q->limit = child->limit;

	q->offset_future = offset_future;
	q->offset_relative = offset_relative;
	if (q->offset_relative)
		q->t_offset = ktime_get_ns();

	if (qopt->t_frame > 0)
		q->t_frame = qopt->t_frame;
	if (qopt->t_slot > 0)
		q->t_slot = qopt->t_slot;
	if (qopt->t_offset)
		q->t_offset += qopt->t_offset;

	sch_tree_unlock(sch);

	// if ((qopt->t_frame > 0) || (qopt->t_slot > 0) || qopt->t_offset || offset_relative) {
	// 	// printk(KERN_DEBUG "change\t%u\t%s", offset_relative, qdisc_dev(sch)->name);
	// 	qdisc_watchdog_schedule_ns(&q->watchdog, 0);
	// 	// printk(KERN_DEBUG "change\t%u\t%s", offset_relative, qdisc_dev(sch)->name);
	// }

	qdisc_watchdog_schedule_ns(&q->watchdog, 0);

	printk(KERN_DEBUG "change\tflags=%u%u\t%s", q->offset_future, q->offset_relative, qdisc_dev(sch)->name);

	return 0;
}

static int tdma_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct tdma_sched_data *q = qdisc_priv(sch);

	// // // q->qdisc = &noop_qdisc;
	// // q->qdisc = fifo_create_dflt(sch, &bfifo_qdisc_ops, qdisc_dev(sch)->tx_queue_len * psched_mtu(qdisc_dev(sch)), extack);
	// // if (IS_ERR(q->qdisc))
	// // 	return PTR_ERR(q->qdisc);
	// // qdisc_hash_add(q->qdisc, true);

	// // if (!(q->qdisc = qdisc_create_dflt(sch->dev_queue, &bfifo_qdisc_ops, TC_H_MAKE(sch->handle, 1), extack)))
	// if (!(q->qdisc = qdisc_create_dflt(sch->dev_queue, &bfifo_qdisc_ops, sch->handle, extack)))
	// 	return -ENOMEM;
	// qdisc_hash_add(q->qdisc, true);

	q->limit = 0;

	q->t_frame = q->t_slot = 1;
	q->t_offset = 0;

	q->offset_future = q->offset_relative = 0;

	q->qdisc = &noop_qdisc;

	qdisc_watchdog_init(&q->watchdog, sch);

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

	printk(KERN_DEBUG "(dump %08x) dev: (name, tx_queue_len, psched_mtu) = (%s, %d, %d)\n", sch->handle, qdisc_dev(sch)->name, qdisc_dev(sch)->tx_queue_len, psched_mtu(qdisc_dev(sch)));
	printk(KERN_DEBUG "(dump %08x) bfifo: (limit, qlen, backlog, drops) = (%d, %d, %d, %d)\n", sch->handle, q->qdisc->limit, q->qdisc->q.qlen, q->qdisc->qstats.backlog, q->qdisc->qstats.drops);
	printk(KERN_DEBUG "(dump %08x) tdma: (limit, qlen, backlog, drops) = (%d, %d, %d, %d)\n", sch->handle, q->limit, sch->q.qlen, sch->qstats.backlog, sch->qstats.drops);
	printk(KERN_DEBUG "(dump %08x) limit: (kernel, user) = (%d, %d)\n", sch->handle, q->limit, opt.limit);
	printk(KERN_DEBUG "(dump %08x) t_frame: (kernel, user) = (%lld, %lld)\n", sch->handle, q->t_frame, opt.t_frame);
	printk(KERN_DEBUG "(dump %08x) t_slot: (kernel, user) = (%lld, %lld)\n", sch->handle, q->t_slot, opt.t_slot);
	printk(KERN_DEBUG "(dump %08x) t_offset: (kernel, user) = (%lld, %lld)\n", sch->handle, q->t_offset, opt.t_offset);

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

#endif
