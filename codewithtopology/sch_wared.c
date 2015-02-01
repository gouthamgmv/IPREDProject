#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#include <linux/bug.h>
#include <net/dsfield.h>
#include <linux/reciprocal_div.h>
#include <linux/ip.h>

#define RED_ONE_PERCENT ((u32)DIV_ROUND_CLOSEST(1ULL<<32, 100))

#define MAX_P_MIN (1 * RED_ONE_PERCENT)
#define MAX_P_MAX (50 * RED_ONE_PERCENT)
#define MAX_P_ALPHA(val) min(MAX_P_MIN, val / 4)

#define RED_STAB_SIZE    256
#define RED_STAB_MASK    (RED_STAB_SIZE - 1)

enum {
    TCA_NRED_UNSPEC,
    TCA_NRED_PARMS,
    TCA_NRED_STAB,
    TCA_NRED_MAX_P,
    __TCA_NRED_MAX,
};

#define TCA_NRED_MAX (__TCA_NRED_MAX - 1)

struct tc_nred_qopt {
    __u32        limit;        /* HARD maximal queue length (bytes)    */
    __u32        qth_min;    /* Min average length threshold (bytes) */
    __u32        qth_max;    /* Max average length threshold (bytes) */
    unsigned char   Wlog;        /* log(W)        */
    unsigned char   Plog;        /* log(P_max/(qth_max-qth_min))    */
    unsigned char   Scell_log;    /* cell size for idle damping */
    unsigned char    flags;
    __u32         factor;
};



struct tc_nred_xstats {
    __u32           early;          /* Early drops */
    __u32           pdrop;          /* Drops due to queue limits */
    __u32           other;          /* Drops due to drop() calls */
    __u32           marked;         /* Marked packets */
};

struct red_stats {
    u32        prob_drop;   
    u32        prob_mark;   
    u32        forced_drop;   
    u32        forced_mark;   
    u32        pdrop;         
    u32        other;   
    u32        droppednormal;  
    u32        droppedpriority;
};

struct red_parms {
   
    u32        qth_min;   
    u32        qth_max;   
    u32        Scell_max;
    u32        max_P;       
    u32        max_P_reciprocal;
    u32        qth_delta;   
    u32        target_min;   
    u32        target_max;   
    u8        Scell_log;
    u8        Wlog;       
    u8        Plog;       
    u8        Stab[RED_STAB_SIZE];
    u32        factor;
};

struct red_vars {
   
    int        qcount;       
    u32        qR;       

    unsigned long    qavg;       
    ktime_t        qidlestart;
    unsigned long adjust;   
};

static inline u32 red_maxp(u8 Plog)
{
    return Plog < 32 ? (~0U >> Plog) : ~0U;
}

static inline void red_set_vars(struct red_vars *v)
{
    v->qavg        = 0;

    v->qcount    = -1;
    v->adjust    =0;
}

static inline void red_set_parms(struct red_parms *p,
                 u32 qth_min, u32 qth_max, u8 Wlog, u8 Plog,
                 u8 Scell_log, u8 *stab, u32 max_P,u32 factor)
{
    int delta = qth_max - qth_min;
    u32 max_p_delta;

    p->qth_min    = qth_min<< Wlog;
    p->qth_max    = qth_max<< Wlog;
    p->Wlog        = Wlog;
    p->Plog        = Plog;
    p->factor    =factor;
    if (delta < 0)
        delta = 1;
    p->qth_delta    = delta;
    if (!max_P) {
        max_P = red_maxp(Plog);
        max_P *= delta;
    }
    p->max_P = max_P;
    max_p_delta = max_P / delta;
    max_p_delta = max(max_p_delta, 1U);
    p->max_P_reciprocal  = reciprocal_value(max_p_delta);

    delta /= 5;
    p->target_min = qth_min + 2*delta;
    p->target_max = qth_min + 3*delta;

    p->Scell_log    = Scell_log;
    p->Scell_max    = (255 << Scell_log);

    if (stab)
        memcpy(p->Stab, stab, sizeof(p->Stab));
}

static inline int red_is_idling(const struct red_vars *v)
{
    return v->qidlestart.tv64 != 0;
}

static inline void red_start_of_idle_period(struct red_vars *v)
{
    v->qidlestart = ktime_get();
}

static inline void red_end_of_idle_period(struct red_vars *v)
{
    v->qidlestart.tv64 = 0;
}

static inline void red_restart(struct red_vars *v)
{
    red_end_of_idle_period(v);
    v->qavg = 0;
    v->qcount = -1;
    v->adjust=0;
   
}

static inline unsigned long red_calc_qavg_from_idle_time(const struct red_parms *p,
                             const struct red_vars *v)
{
    s64 delta = ktime_us_delta(ktime_get(), v->qidlestart);
    long us_idle = min_t(s64, delta, p->Scell_max);
    int  shift;

   

    shift = p->Stab[(us_idle >> p->Scell_log) & RED_STAB_MASK];

    if (shift)
        return v->qavg >> shift;
    else {
       
        us_idle = (v->qavg * (u64)us_idle) >> p->Scell_log;

        if (us_idle < (v->qavg >> 1))
            return v->qavg - us_idle;
        else
            return v->qavg >> 1;
    }
}

static inline unsigned long red_calc_qavg_no_idle_time(const struct red_parms *p,
                               const struct red_vars *v,
                               unsigned int backlog)
{
   
    return v->qavg + (backlog - (v->qavg >> p->Wlog));
}

static inline unsigned long red_calc_qavg(const struct red_parms *p,
                      const struct red_vars *v,
                      unsigned int backlog)
{
    if (!red_is_idling(v))
        return red_calc_qavg_no_idle_time(p, v, backlog);
    else
        return red_calc_qavg_from_idle_time(p, v);
}


static inline u32 red_random(const struct red_parms *p)
{
    return reciprocal_divide(net_random(), p->max_P_reciprocal);
}

static inline int red_mark_probability(const struct red_parms *p,
                       const struct red_vars *v,
                       unsigned long qavg)
{
   
    return !(((qavg - p->qth_min) >> p->Wlog) * v->qcount < v->qR);
}

enum {
    RED_BELOW_MIN_THRESH,
    RED_BETWEEN_TRESH,
    RED_ABOVE_MAX_TRESH,
};

static inline int red_cmp_thresh(const struct red_parms *p, unsigned long qavg,int tos,int adjust)
{
    int mini;
    printk("qavg=%lu\n",qavg);
    printk("p->qth_min=%d\n",p->qth_min);
    printk("p->qth_max=%d\n",p->qth_max);


    if(tos>4)
    {
        mini=1000+adjust;
    }
    else
    {
        mini=0;
    }
   
    if (qavg < (p->qth_min)-mini)
        return RED_BELOW_MIN_THRESH;
    else if (qavg >= (p->qth_max))
        return RED_ABOVE_MAX_TRESH;
    else
        return RED_BETWEEN_TRESH;
}

enum {
    RED_DONT_MARK,
    RED_PROB_MARK,
    RED_HARD_MARK,
};

static inline int red_action(const struct red_parms *p,
                 struct red_vars *v,
                 unsigned long qavg,int tos,int adjust)
{
    switch (red_cmp_thresh(p, qavg,tos,adjust)) {
        case RED_BELOW_MIN_THRESH:
            v->qcount = -1;
            return RED_DONT_MARK;

        case RED_BETWEEN_TRESH:
            if (++v->qcount) {
                if (red_mark_probability(p, v, qavg)) {
                    v->qcount = 0;
                    v->qR = red_random(p);
                    return RED_PROB_MARK;
                }
            } else
                v->qR = red_random(p);

            return RED_DONT_MARK;

        case RED_ABOVE_MAX_TRESH:
            v->qcount = -1;
            return RED_HARD_MARK;
    }

    BUG();
    return RED_DONT_MARK;
}

static inline void red_adaptative_algo(struct red_parms *p, struct red_vars *v)
{
    unsigned long qavg;
    u32 max_p_delta;

    qavg = v->qavg;
    if (red_is_idling(v))
        qavg = red_calc_qavg_from_idle_time(p, v);

   
    qavg >>= p->Wlog;

    if (qavg > p->target_max && p->max_P <= MAX_P_MAX)
        p->max_P += MAX_P_ALPHA(p->max_P);
    else if (qavg < p->target_min && p->max_P >= MAX_P_MIN)
        p->max_P = (p->max_P/10)*9;

    max_p_delta = DIV_ROUND_CLOSEST(p->max_P, p->qth_delta);
    max_p_delta = max(max_p_delta, 1U);
    p->max_P_reciprocal = reciprocal_value(max_p_delta);
}

struct red_sched_data {
    u32            limit;       
    unsigned char        flags;
    struct timer_list    adapt_timer;
    struct red_parms    parms;
    struct red_vars        vars;
    struct red_stats    stats;
    struct Qdisc        *qdisc;
};


static int red_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
   
    int ret;
    int tos;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    //int factor;
    //factor=100;

    if(q->stats.droppedpriority == q->stats.droppednormal)
    {
        q->vars.adjust=0;
    }
    else
    {
        if(q->stats.droppedpriority > q->stats.droppednormal)
        {
            q->vars.adjust=q->vars.adjust+q->parms.factor;
		if(q->vars.adjust<0)
		{
			q->vars.adjust=0;
		}
		if((q->vars.adjust) >=(q->parms.qth_min))
		{
			q->vars.adjust=	q->parms.qth_min-500;
		}
        }
        else
        {
            q->vars.adjust=q->vars.adjust-q->parms.factor;
		if(q->vars.adjust<0)
		{
			q->vars.adjust=0;
		}
		if((q->vars.adjust) >=(q->parms.qth_min))
		{
			q->vars.adjust=	q->parms.qth_min-500;
		}
		
        }
    }   
     printk("Adjustment=%d\n",q->vars.adjust);
  
    q->vars.qavg = red_calc_qavg(&q->parms,
                     &q->vars,
                     child->qstats.backlog);
   
   
   

    if (red_is_idling(&q->vars))
        red_end_of_idle_period(&q->vars);
    tos=ip_header->tos;
    switch (red_action(&q->parms, &q->vars, q->vars.qavg,tos,q->vars.adjust)) {
    case RED_DONT_MARK:
        break;

    case RED_PROB_MARK:
        sch->qstats.overlimits++;
            q->stats.prob_drop++;
            goto congestion_drop;
        break;

    case RED_HARD_MARK:
        sch->qstats.overlimits++;
            q->stats.forced_drop++;
            goto congestion_drop;
        break;
    }

    ret = qdisc_enqueue(skb, child);
    if (likely(ret == NET_XMIT_SUCCESS)) {
        sch->q.qlen++;
        printk("Dropped priority packets=%d\n",q->stats.droppedpriority);
        printk("Dropped normal packets=%d\n",q->stats.droppednormal);
       
       
    } else if (net_xmit_drop_count(ret)) {
        q->stats.pdrop++;
        sch->qstats.drops++;
    }
    return ret;

congestion_drop:
    qdisc_drop(skb, sch);
    if(tos>4)
    {
    q->stats.droppednormal++;
    printk("Dropped priority packets=%d\n",q->stats.droppedpriority);
    printk("Dropped normal packets=%d\n",q->stats.droppednormal);
    }
    else
    {
    q->stats.droppedpriority++;
    printk("Dropped priority packets=%d\n",q->stats.droppedpriority);
    printk("Dropped normal packets=%d\n",q->stats.droppednormal);
    }
   
   
   
    return NET_XMIT_CN;
}

static struct sk_buff *red_dequeue(struct Qdisc *sch)
{
    struct sk_buff *skb;
    struct red_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;

    skb = child->dequeue(child);
    if (skb) {
        qdisc_bstats_update(sch, skb);
        sch->q.qlen--;
    } else {
        if (!red_is_idling(&q->vars))
            red_start_of_idle_period(&q->vars);
    }
    return skb;
}

static struct sk_buff *red_peek(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;

    return child->ops->peek(child);
}

static unsigned int red_drop(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
    unsigned int len;

    if (child->ops->drop && (len = child->ops->drop(child)) > 0) {
        q->stats.other++;
        sch->qstats.drops++;
        sch->q.qlen--;
        return len;
    }

    if (!red_is_idling(&q->vars))
        red_start_of_idle_period(&q->vars);

    return 0;
}

static void red_reset(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);

    qdisc_reset(q->qdisc);
    sch->q.qlen = 0;
    q->stats.droppedpriority=0;
    q->stats.droppednormal=0;
   
    red_restart(&q->vars);
}

static void red_destroy(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);

    del_timer_sync(&q->adapt_timer);
    qdisc_destroy(q->qdisc);
}

static const struct nla_policy red_policy[TCA_NRED_MAX + 1] = {
    [TCA_NRED_PARMS]    = { .len = sizeof(struct tc_nred_qopt) },
    [TCA_NRED_STAB]    = { .len = RED_STAB_SIZE },
    [TCA_NRED_MAX_P] = { .type = NLA_U32 },
};

static int red_change(struct Qdisc *sch, struct nlattr *opt)
{
    struct red_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_NRED_MAX + 1];
    struct tc_nred_qopt *ctl;
    struct Qdisc *child = NULL;
    int err;
    u32 max_P;
    q->stats.droppedpriority=0;
    q->stats.droppednormal=0;
    if (opt == NULL)
        return -EINVAL;

    err = nla_parse_nested(tb, TCA_NRED_MAX, opt, red_policy);
    if (err < 0)
        return err;

    if (tb[TCA_NRED_PARMS] == NULL ||
        tb[TCA_NRED_STAB] == NULL)
        return -EINVAL;

    max_P = tb[TCA_NRED_MAX_P] ? nla_get_u32(tb[TCA_NRED_MAX_P]) : 0;

    ctl = nla_data(tb[TCA_NRED_PARMS]);

    if (ctl->limit > 0) {
        child = fifo_create_dflt(sch, &bfifo_qdisc_ops, ctl->limit);
        if (IS_ERR(child))
            return PTR_ERR(child);
    }

    sch_tree_lock(sch);
    q->flags = ctl->flags;
    q->limit = ctl->limit;
    if (child) {
        qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
        qdisc_destroy(q->qdisc);
        q->qdisc = child;
    }

    red_set_parms(&q->parms,
              ctl->qth_min, ctl->qth_max, ctl->Wlog,
              ctl->Plog, ctl->Scell_log,
              nla_data(tb[TCA_NRED_STAB]),
              max_P,ctl->factor);
    red_set_vars(&q->vars);

    del_timer(&q->adapt_timer);
    if (ctl->flags & TC_RED_ADAPTATIVE)
        mod_timer(&q->adapt_timer, jiffies + HZ/2);

    if (!q->qdisc->q.qlen)
        red_start_of_idle_period(&q->vars);

    sch_tree_unlock(sch);
    return 0;
}

static inline void red_adaptative_timer(unsigned long arg)
{
    struct Qdisc *sch = (struct Qdisc *)arg;
    struct red_sched_data *q = qdisc_priv(sch);
    spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

    spin_lock(root_lock);
    red_adaptative_algo(&q->parms, &q->vars);
    mod_timer(&q->adapt_timer, jiffies + HZ/2);
    spin_unlock(root_lock);
}

static int red_init(struct Qdisc *sch, struct nlattr *opt)
{
    struct red_sched_data *q = qdisc_priv(sch);

    q->qdisc = &noop_qdisc;
    setup_timer(&q->adapt_timer, red_adaptative_timer, (unsigned long)sch);
    return red_change(sch, opt);
}

static struct Qdisc_ops wared_qdisc_ops __read_mostly = {
    .id        =    "wared",
    .priv_size    =    sizeof(struct red_sched_data),
    .enqueue    =    red_enqueue,
    .dequeue    =    red_dequeue,
    .peek        =    red_peek,
    .drop        =    red_drop,
    .init        =    red_init,
    .reset        =    red_reset,
    .destroy    =    red_destroy,
    .change        =    red_change,
    .owner        =    THIS_MODULE,
};

static int __init wared_module_init(void)
{
    return register_qdisc(&wared_qdisc_ops);
}

static void __exit wared_module_exit(void)
{
    unregister_qdisc(&wared_qdisc_ops);
}

module_init(wared_module_init)
module_exit(wared_module_exit)

MODULE_LICENSE("GPL");
