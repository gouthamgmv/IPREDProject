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
	__u32		limit;		/* HARD maximal queue length (bytes)	*/
	__u32		qth_min;	/* Min average length threshold (bytes) */
	__u32		qth_max;	/* Max average length threshold (bytes) */
	unsigned char   Wlog;		/* log(W)		*/
	unsigned char   Plog;		/* log(P_max/(qth_max-qth_min))	*/
	unsigned char   Scell_log;	/* cell size for idle damping */
	unsigned char	flags;
	__u32 		decrement;
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
    u32        dropped;  
    u32        accepted;
    u32	       droppedpriority;
    u32        droppednormal; 
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
    u32	 	decrement;
};

struct red_vars {
   
    int        qcount;       
    u32        qR;       

    unsigned long    qavg[2];       
    ktime_t        qidlestart[2];
    unsigned int backlog;   
};

static inline u32 red_maxp(u8 Plog)
{
    return Plog < 32 ? (~0U >> Plog) : ~0U;
}

static inline void red_set_vars(struct red_vars *v,struct red_stats *s)
{
    v->qavg[0]        = 0;
    v->qavg[1]		=0;

    v->qcount    = -1;
	v->backlog=0;
	s->accepted=0;
	s->dropped=0;
	s->droppedpriority=0;
	s->droppednormal=0;
}

static inline void red_set_parms(struct red_parms *p,
                 u32 qth_min, u32 qth_max, u8 Wlog, u8 Plog,
                 u8 Scell_log, u8 *stab, u32 max_P,u32 decrement)
{
    int delta = qth_max - qth_min;
    u32 max_p_delta;

    p->qth_min    = qth_min<< Wlog;
    p->qth_max    = qth_max<< Wlog;
    p->Wlog        = Wlog;
    p->Plog        = Plog;
    p->decrement   =decrement;
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

static inline int red_is_idling(const struct red_vars *v,int order)
{
    return v->qidlestart[order].tv64 != 0;
}

static inline void red_start_of_idle_period(struct red_vars *v,int order)
{
    v->qidlestart[order] = ktime_get();
}

static inline void red_end_of_idle_period(struct red_vars *v,int order)
{
    v->qidlestart[order].tv64 = 0;
}

static inline void red_restart(struct red_vars *v,struct red_stats *s)
{
    red_end_of_idle_period(v,0);
    red_end_of_idle_period(v,1);
	
    v->qavg[0] = 0;
    v->qavg[1]	=0;
    v->qcount = -1;
	v->backlog=0;
	s->accepted=0;
	s->dropped=0;
	s->droppedpriority=0;
	s->droppednormal=0;
}

static inline unsigned long red_calc_qavg_from_idle_time(const struct red_parms *p,
                             const struct red_vars *v,unsigned int backlog,int order)
{
   
    s64 delta = ktime_us_delta(ktime_get(), v->qidlestart[order]);
    long us_idle = min_t(s64, delta, p->Scell_max);
    int  shift;
	unsigned long ret;
    unsigned long check,backlogdelta;
	backlogdelta=0;
	if(backlog>0)
	{
    check=p->qth_min/backlog;
    if(check<=15)
    {
        backlogdelta=0;
    }
    else
    {
        backlogdelta=check*1000;
    }
	}

    shift = p->Stab[(us_idle >> p->Scell_log) & RED_STAB_MASK];
   

    if (shift)
	{
	
        ret=((v->qavg[order] >> shift)-backlogdelta);
	if(ret>backlogdelta)
	{
		ret=ret-backlogdelta;
		return ret;
	}
	else
	{
		return ret;
	}
	}
    else {
       
        us_idle = (v->qavg[order] * (u64)us_idle) >> p->Scell_log;

        if (us_idle < (v->qavg[order] >> 1))
		{
            ret= ((v->qavg[order] - us_idle)-backlogdelta);
		if(ret>backlogdelta)
	{
		ret=ret-backlogdelta;
		return ret;
	}
	else
	{
		return ret;
	}
	}
	
        else
	{
            ret=((v->qavg[order] >> 1)-backlogdelta);
		if(ret>backlogdelta)
	{
		ret=ret-backlogdelta;
		return ret;
	}
	else
	{
		return ret;
	}
	}
    }
}

static inline unsigned long red_calc_qavg_no_idle_time(const struct red_parms *p,
                               const struct red_vars *v,
                               unsigned int backlog,int order)
{
   
    return v->qavg[order] + (backlog - (v->qavg[order] >> p->Wlog));
}

static inline unsigned long red_calc_qavg(const struct red_parms *p,
                      const struct red_vars *v,
                      unsigned int backlog,int order)
{
    if (!red_is_idling(v,order))
        return red_calc_qavg_no_idle_time(p, v, backlog,order);
    else
        return red_calc_qavg_from_idle_time(p, v,backlog,order);
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

static inline int red_cmp_thresh(const struct red_parms *p, unsigned long qavg,int order)
{
	int mini;
	if(order==1)
	{
		mini=p->decrement;
		printk("decrement=%d",mini);
	}
	else
	{
		mini=0;
	}
    printk("qavg=%lu\n",qavg);
    printk("p->qth_min=%d\n",p->qth_min);
    printk("p->qth_max=%d\n",p->qth_max);
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
                 unsigned long qavg,int order)
{
    switch (red_cmp_thresh(p, qavg,order)) {
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


struct red_sched_data {
    u32            limit;       
    unsigned char        flags;
      struct red_parms    parms;
    struct red_vars        vars;
    struct red_stats    stats;
    struct Qdisc        *qdisc;
};


static int red_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);
    struct Qdisc *child = q->qdisc;
	int tos;
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

   
    int ret;
	int order;
	tos=ip_header->tos;
	if(tos<4)
	{
		order=0;
	}
	else 
	{
		order=1;
	}
	
    q->vars.backlog=child->qstats.backlog;
    q->vars.qavg[order] = red_calc_qavg(&q->parms,&q->vars,child->qstats.backlog,order);
	
    
   
   

    if (red_is_idling(&q->vars,order))
	{
        red_end_of_idle_period(&q->vars,order);
	}
    switch (red_action(&q->parms, &q->vars, q->vars.qavg[order],order)) {
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
	q->stats.accepted++;
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
	int tos;
	int order;
	
	
	struct iphdr *ip_header;
	skb = child->dequeue(child);
 	ip_header = (struct iphdr *)skb_network_header(skb);
	tos=ip_header->tos;
	if(tos<4)
	{
		order=0;
	}
	else 
	{
		order=1;
	}
		

    
    if (skb) {
        qdisc_bstats_update(sch, skb);
        sch->q.qlen--;
    } else {
        if (!red_is_idling(&q->vars,order))
	{
            red_start_of_idle_period(&q->vars,order);
	    }

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

    if (!red_is_idling(&q->vars,0))
	{
        red_start_of_idle_period(&q->vars,0);
	 
	}
	if (!red_is_idling(&q->vars,1))
	{
	red_start_of_idle_period(&q->vars,1);
	}

    return 0;
}

static void red_reset(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);

    qdisc_reset(q->qdisc);
    sch->q.qlen = 0;
	
    red_restart(&q->vars,&q->stats);
}

static void red_destroy(struct Qdisc *sch)
{
    struct red_sched_data *q = qdisc_priv(sch);
	
    
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
              max_P,ctl->decrement);
    red_set_vars(&q->vars,&q->stats);

    

    if (!q->qdisc->q.qlen)
	{
        red_start_of_idle_period(&q->vars,0);
	red_start_of_idle_period(&q->vars,1);
	}
	
    sch_tree_unlock(sch);
    return 0;
}



static int red_init(struct Qdisc *sch, struct nlattr *opt)
{
    struct red_sched_data *q = qdisc_priv(sch);
	

    q->qdisc = &noop_qdisc;
	
   
    return red_change(sch, opt);
}

static struct Qdisc_ops wred_qdisc_ops __read_mostly = {
    .id        =    "wred",
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

static int __init wred_module_init(void)
{
    return register_qdisc(&wred_qdisc_ops);
}

static void __exit wred_module_exit(void)
{
    unregister_qdisc(&wred_qdisc_ops);
}

module_init(newred_module_init)
module_exit(newred_module_exit)

MODULE_LICENSE("GPL");
