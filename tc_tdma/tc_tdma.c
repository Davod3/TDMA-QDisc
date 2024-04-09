#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <malloc.h>

#include <linux/pkt_sched.h>

#include <libnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>

#include "tc_tdma.h"

struct rtnl_handle rth;

static int qdisc_modify(int cmd, unsigned int flags, struct tc_tdma_qopt *opt) {
    // cmd = RTM_NEWQDISC // add | change | replace | link
    // cmd = RTM_DELQDISC // delete
    // flags = NLM_F_EXCL | NLM_F_CREATE // add
    // flags = 0 // change | delete
    // flags = NLM_F_CREATE | NLM_F_REPLACE // replace
    // flags = NLM_F_REPLACE // link

    // char d[IFNAMSIZ] = {};
    char d[16] = {}; // device (interface) name
    // char *d = "enp0s1";
    // strncpy(d, "enp0s1", 16);
    strncpy(d, "eth0", 16);
    // char k[FILTER_NAMESZ] = {};
    char k[16] = {}; // qdisc (kind) name
    strncpy(k, "tdma", 16);
    // char *k = "tdma";

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
	char buf[64 * 1024];
        // char buf[TCA_BUF_MAX];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags,
        .n.nlmsg_type = cmd,

        .t.tcm_family = AF_UNSPEC, // unsigned char
        // .t.tcm_ifindex // int // required
        // .t.tcm_handle = handle, // __u32 // optional
        .t.tcm_parent = TC_H_ROOT, // __u32
        // .t.tcm_info = 0 // __u32 // optional
    };

    struct rtattr *tail;

    // BEGIN hardcoding    // END hardcoding

    if (k[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k) + 1);

    // Add TCA_OPTIONS
    tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    // addattr_l(&req.n, 2024, TCA_TBF_PARMS, opt, sizeof(*opt));
    addattr_l(&req.n, 2024, TCA_TDMA_PARMS, opt, sizeof(*opt));
    addattr_nest_end(&req.n, tail);

    if (d[0]) {
        int idx;

        ll_init_map(&rth);

        idx = ll_name_to_index(d);
        if (!idx)
            return 1;
        req.t.tcm_ifindex = idx;
    }

    if (rtnl_talk(&rth, &req.n, NULL) < 0)
        return 1;
        
    return 0;
}

int qdisc_list_filter(struct nlmsghdr *n, void *arg) {
    int len;
    struct tcmsg *t = NLMSG_DATA(n);

    struct rtattr *tb[TCA_MAX + 1];
    struct rtattr *tbs[TCA_STATS_MAX + 1];

    struct tc_stats *stats;
    struct gnet_stats_basic *bstats;
    struct gnet_stats_queue *qstats;
    struct gnet_stats_rate_est *rstats;
    struct gnet_stats_rate_est64 *rstats64;

    struct tc_estimator *est;
    

    printf("nlmsg_type: %s\n", n->nlmsg_type == RTM_NEWQDISC ? "new" : n->nlmsg_type == RTM_DELQDISC ? "del" : n->nlmsg_type == RTM_GETQDISC ? "get" : "other");
    printf("nlmsg_len, nlmsghdr_len: %d, %d\n", n->nlmsg_len, NLMSG_LENGTH(sizeof(*t)));
    printf("family: %s\n", t->tcm_family == AF_UNSPEC ? "unspecified" : "other");
    printf("device: %d\n", t->tcm_ifindex);
    printf("handle: %04x:%04x\n", t->tcm_handle >> 16, t->tcm_handle & 0xffff);
    printf("parent: %s\n", t->tcm_parent == TC_H_ROOT ? "root" : "other");

    len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*t));
    if (len < 0)
        return -1;

    parse_rtattr_flags(tb, TCA_MAX, TCA_RTA(t), n->nlmsg_len - NLMSG_LENGTH(sizeof(*t)), NLA_F_NESTED);

    printf("kind: %s\n", (const char *) RTA_DATA(tb[TCA_KIND]));
    printf("stats: %d, %d, %d\n", tb[TCA_STATS] ? 1 : 0, tb[TCA_STATS2] ? 1 : 0, tb[TCA_XSTATS] ? 1 : 0);
    
    if (tb[TCA_STATS]) {
        stats = RTA_DATA(tb[TCA_STATS]);
        printf("stats_1: %llu, %lu, %lu, %lu\n", stats->bytes, stats->packets, stats->drops, stats->overlimits);
        printf("stats_1: %lu, %lu, %lu, %lu\n", stats->bps, stats->pps, stats->qlen, stats->backlog);
    }
    if (tb[TCA_STATS2]) {
        parse_rtattr_nested(tbs, TCA_STATS_MAX, tb[TCA_STATS2]);
        if (tbs[TCA_STATS_BASIC]) {
            bstats = RTA_DATA(tbs[TCA_STATS_BASIC]);
            printf("stats_2 (basic): %llu, %lu\n", bstats->bytes, bstats->packets);
        }
        if (tbs[TCA_STATS_QUEUE]) {
            qstats = RTA_DATA(tbs[TCA_STATS_QUEUE]);
            printf("stats_2 (queue): %lu, %lu, %lu, %lu, %u\n", qstats->qlen, qstats->backlog, qstats->drops, qstats->requeues, qstats->overlimits);
        }
        if (tbs[TCA_STATS_RATE_EST]) {
            rstats = RTA_DATA(tbs[TCA_STATS_RATE_EST]);
            printf("stats_2 (rate_est): %lu, %lu\n", rstats->bps, rstats->pps);
        }
        if (tbs[TCA_STATS_RATE_EST64]) {
            rstats64 = RTA_DATA(tbs[TCA_STATS_RATE_EST]);
            printf("stats_2 (rate_est64): %llu, %llu\n", rstats64->bps, rstats64->pps);
        }
    }

    if (tb[TCA_RATE]) {
        est = RTA_DATA(tb[TCA_RATE]);
        printf("est: %hhd, %hhu\n", est->interval, est->ewma_log);
    }

    printf("\n");

    return 0;
}

static int qdisc_list(int invisible) {
    struct {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[256];
    } req = {
        .n.nlmsg_type = RTM_GETQDISC,
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .t.tcm_family = AF_UNSPEC,
    };
    
    // char d[IFNAMSIZ] = {};
    char d[16] = {}; // device (interface) name
    // char *d = "enp0s1";
    // strncpy(d, "enp0s1", 16);
    strncpy(d, "eth0", 16);
    // char k[FILTER_NAMESZ] = {};
    char k[16] = {}; // qdisc (kind) name
    strncpy(k, "tdma", 16);
    // char *k = "tdma";

    if (d[0]) {
        int idx;

        ll_init_map(&rth);

        idx = ll_name_to_index(d);
        if (!idx)
            return 1;
        req.t.tcm_ifindex = idx;
    }

    if (invisible)
        addattr_l(&req.n, 256, TCA_DUMP_INVISIBLE, NULL, 0);

    if (rtnl_dump_request_n(&rth, &req.n) < 0)
        return 1;
    
    if (rtnl_dump_filter(&rth, qdisc_list_filter, NULL) < 0)
        return 1;
    
    return 0;
}

// struct tc_ratespec *dummy_ratespec() {
//     struct tc_ratespec *rs;
//     rs = malloc(sizeof(struct tc_ratespec));
//     rs->cell_log = '\0';
//     rs->linklayer = 0;
//     rs->overhead = 0;
//     rs->cell_align = 0;
//     rs->mpu = 0;
//     rs->rate = 0;
//     return rs;
// }


int main(int argc, char **argv) {
    struct tc_tdma_qopt *opt;
    // struct tc_ratespec *rate;
    // struct tc_ratespec *peakrate;

    long long int frame;
    long long int slot;
    long long int offset;


    if (rtnl_open(&rth, 0) < 0) {
        printf("Cannot open rtnetlink\n");
        exit(1);
    }

    // opt = malloc(sizeof(struct tc_tdma_qopt));
    // opt->rate = *dummy_ratespec();
    // opt->rate.linklayer = 1;
    // opt->rate.rate = 27500;
    // opt->peakrate = *dummy_ratespec();

    // // opt->limit = 2915;
    // // opt->limit = 1514000;
    // opt->limit = 0;
    // opt->buffer = 874999;
    // opt->mtu = 0;
    // opt->frame = 1000000000;
    // opt->slot = 100000000;

    opt = malloc(sizeof(struct tc_tdma_qopt));
    opt->limit = 0;
    opt->t_frame = 1000000000;
    opt->t_slot = 100000000;
    opt->t_offset = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "add") == 0) {
            if (argc > 3) {
                sscanf(argv[2], "%lld", &opt->t_frame);
                sscanf(argv[3], "%lld", &opt->t_slot);
            }
            if (qdisc_modify(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, opt)) {
                printf("Failed to add qdisc\n");
                exit(1);
            }
        } else if (strcmp(argv[1], "change") == 0) {
            if (argc > 2)
                sscanf(argv[2], "%lld", &opt->t_offset);
            if (qdisc_modify(RTM_NEWQDISC, 0, opt)) {
                printf("Failed to change qdisc\n");
                exit(1);
            }
        } else if (strcmp(argv[1], "show") == 0) {
            if (qdisc_list(1)) {
                printf("Failed to list qdiscs\n");
                exit(1);
            }
        }
    }

    rtnl_close(&rth);

    printf("Success\n");
    return 0;
}
