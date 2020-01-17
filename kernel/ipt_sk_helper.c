/*
 *	ipt_sk - Netfilter helper module to match cgroup/owner
 *
 *	(C) 2020 Vitaly Lavrov <vel21ripn@gnail.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>

#include <net/net_namespace.h>
#include <net/ip.h>

#include <net/netfilter/nf_socket.h>

#include <linux/netfilter/x_tables.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#error Unsupported kernel version. Use 4.4+
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaly Lavrov <vel21ripn@gnail.com>");
MODULE_DESCRIPTION("Xtables: Netfilter helper module");

static unsigned int sk_early_on(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	struct net *net = state->net;
	const struct iphdr *iph = ip_hdr(skb);

	if( skb->sk || net->ipv4.sysctl_ip_early_demux < 2 ||
	    ip_is_fragment(iph)) 
		return NF_ACCEPT;
	skb->sk = nf_sk_lookup_slow_v4(net, skb, state->in);
	if(skb->sk)
		*((uint32_t *)&skb->cb[4]) = 0x4b534e4f; // SKON

	return NF_ACCEPT;
}

static unsigned int sk_early_off(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	if( (*((uint32_t *)&skb->cb[4]) == 0x4b534e4f) && skb->sk )
		skb->sk = NULL;

	return NF_ACCEPT;
}


static struct nf_hook_ops nf_sk_ipv4_ops[] = {
	{
		.hook		= sk_early_on,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_MANGLE - 1,
	},
	{
		.hook		= sk_early_off,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FILTER + 1,
	}
};

static int __net_init sk_net_init(struct net *net) {
	return nf_register_net_hooks(net, nf_sk_ipv4_ops,
		    ARRAY_SIZE(nf_sk_ipv4_ops));

}
static void __net_exit sk_net_exit(struct net *net) {

	nf_unregister_net_hooks(net, nf_sk_ipv4_ops,
			      ARRAY_SIZE(nf_sk_ipv4_ops));

}

static struct pernet_operations sk_net_ops = {
	.init   = sk_net_init,
	.exit   = sk_net_exit,
};


static int __init sk_mt_init(void)
{
	return register_pernet_subsys(&sk_net_ops) < 0 ? -EOPNOTSUPP : 0;
}

static void __exit sk_mt_exit(void)
{
	return unregister_pernet_subsys(&sk_net_ops);
}

module_init(sk_mt_init);
module_exit(sk_mt_exit);
