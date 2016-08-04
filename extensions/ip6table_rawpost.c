/*
 * IPv6 rawpost table
 * Copyright (C) 2016 Vittorio Gambaletta <linuxbugs@vittgam.net>
 *
 * Based on ip6table_raw.c
 * Copyright (C) 2003 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 */
#include <linux/module.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

static int __net_init ip6table_rawpost_table_init(struct net *net);

static const struct xt_table packet_rawpost = {
	.name = "rawpost",
	.valid_hooks = 1 << NF_INET_POST_ROUTING,
	.me = THIS_MODULE,
	.af = NFPROTO_IPV6,
	.priority = NF_IP6_PRI_LAST,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	.table_init = ip6table_rawpost_table_init,
#endif
};

static int rawpost_net_id;
static inline struct xt_table **rawpost_pernet(struct net *net)
{
	return net_generic(net, rawpost_net_id);
}

/* The work comes in here from netfilter.c. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static unsigned int ip6table_rawpost_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return ip6t_do_table(skb, state, *rawpost_pernet(state->net));
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static unsigned int ip6table_rawpost_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return ip6t_do_table(skb, ops->hooknum, state, *rawpost_pernet(state->net));
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static unsigned int ip6table_rawpost_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	return ip6t_do_table(skb, ops->hooknum, in, out, *rawpost_pernet(dev_net((in != NULL) ? in : out)));
}
#else
static unsigned int ip6table_rawpost_hook(unsigned int hook, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	return ip6t_do_table(skb, hook, in, out, *rawpost_pernet(dev_net((in != NULL) ? in : out)));
}
#endif

static struct nf_hook_ops *rawposttable_ops __read_mostly;

static int __net_init ip6table_rawpost_table_init(struct net *net)
{
	struct xt_table **ip6table_rawpost = rawpost_pernet(net);
	struct ip6t_replace *repl;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	int ret;
#endif

	if (*ip6table_rawpost)
		return 0;

	repl = ip6t_alloc_initial_table(&packet_rawpost);
	if (repl == NULL)
		return -ENOMEM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	ret = ip6t_register_table(net, &packet_rawpost, repl, rawposttable_ops, ip6table_rawpost);
	kfree(repl);
	return ret;
#else
	*ip6table_rawpost = ip6t_register_table(net, &packet_rawpost, repl);
	kfree(repl);
	return PTR_ERR_OR_ZERO(*ip6table_rawpost);
#endif
}

static void __net_exit ip6table_rawpost_net_exit(struct net *net)
{
	struct xt_table **ip6table_rawpost = rawpost_pernet(net);
	if (!*ip6table_rawpost)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	ip6t_unregister_table(net, *ip6table_rawpost, rawposttable_ops);
#else
	ip6t_unregister_table(net, *ip6table_rawpost);
#endif
	*ip6table_rawpost = NULL;
}

static struct pernet_operations ip6table_rawpost_net_ops = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	.init = ip6table_rawpost_table_init,
#endif
	.exit = ip6table_rawpost_net_exit,
	.id   = &rawpost_net_id,
	.size = sizeof(struct xt_table *),
};

static int __init ip6table_rawpost_init(void)
{
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	/* Register hooks */
	rawposttable_ops = xt_hook_ops_alloc(&packet_rawpost, ip6table_rawpost_hook);
	if (IS_ERR(rawposttable_ops))
		return PTR_ERR(rawposttable_ops);

	ret = register_pernet_subsys(&ip6table_rawpost_net_ops);
	if (ret < 0) {
		kfree(rawposttable_ops);
		return ret;
	}

	ret = ip6table_rawpost_table_init(&init_net);
	if (ret) {
		unregister_pernet_subsys(&ip6table_rawpost_net_ops);
		kfree(rawposttable_ops);
	}
#else
 	ret = register_pernet_subsys(&ip6table_rawpost_net_ops);
	if (ret < 0)
 		return ret;
 
	/* Register hooks */
	rawposttable_ops = xt_hook_link(&packet_rawpost, ip6table_rawpost_hook);
	if (IS_ERR(rawposttable_ops)) {
		ret = PTR_ERR(rawposttable_ops);
 		unregister_pernet_subsys(&ip6table_rawpost_net_ops);
	}
#endif

	return ret;
}

static void __exit ip6table_rawpost_fini(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	unregister_pernet_subsys(&ip6table_rawpost_net_ops);
	kfree(rawposttable_ops);
#else
	xt_hook_unlink(&packet_rawpost, rawposttable_ops);
	unregister_pernet_subsys(&ip6table_rawpost_net_ops);
#endif
}

module_init(ip6table_rawpost_init);
module_exit(ip6table_rawpost_fini);
MODULE_LICENSE("GPL");
