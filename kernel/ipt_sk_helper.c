/*
 *	ipt_sk_helper - Netfilter helper module to match cgroup
 *
 *	(C) 2020 Vitaly Lavrov <vel21ripn@gnail.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
#error Unsupported kernel version. Use 4.4+
#endif

#include <linux/skbuff.h>
#include <linux/proc_fs.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <net/ip.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#include <net/netfilter/nf_socket.h>
#endif

#include <linux/netfilter/x_tables.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaly Lavrov <vel21ripn@gnail.com>");
MODULE_DESCRIPTION("Xtables: Netfilter helper module");

/*
static int early_ip_demux = 0;
module_param(early_ip_demux, int, 0644);
MODULE_PARM_DESC(early_ip_demux, "early_ip_demux on/off");
*/

static const char *name_state = "early_demux_ip4";


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
#define pde_data(inode) PDE_DATA(inode)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define ACCESS_OK(a,b,c) access_ok(b,c)
#else
#define ACCESS_OK(a,b,c) access_ok(a,b,c)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
/// {{{{
/*
 * copy from net/ipv4/netfilter/nf_socket.c
 */
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

#include <net/inet_hashtables.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#endif

static int
extract_icmp4_fields(const struct sk_buff *skb, u8 *protocol,
		     __be32 *raddr, __be32 *laddr,
		     __be16 *rport, __be16 *lport)
{
	unsigned int outside_hdrlen = ip_hdrlen(skb);
	struct iphdr *inside_iph, _inside_iph;
	struct icmphdr *icmph, _icmph;
	__be16 *ports, _ports[2];

	icmph = skb_header_pointer(skb, outside_hdrlen,
				   sizeof(_icmph), &_icmph);
	if (icmph == NULL)
		return 1;

	switch (icmph->type) {
	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		break;
	default:
		return 1;
	}

	inside_iph = skb_header_pointer(skb, outside_hdrlen +
					sizeof(struct icmphdr),
					sizeof(_inside_iph), &_inside_iph);
	if (inside_iph == NULL)
		return 1;

	if (inside_iph->protocol != IPPROTO_TCP &&
	    inside_iph->protocol != IPPROTO_UDP)
		return 1;

	ports = skb_header_pointer(skb, outside_hdrlen +
				   sizeof(struct icmphdr) +
				   (inside_iph->ihl << 2),
				   sizeof(_ports), &_ports);
	if (ports == NULL)
		return 1;

	/* the inside IP packet is the one quoted from our side, thus
	 * its saddr is the local address */
	*protocol = inside_iph->protocol;
	*laddr = inside_iph->saddr;
	*lport = ports[0];
	*raddr = inside_iph->daddr;
	*rport = ports[1];

	return 0;
}

static struct sock *
nf_socket_get_sock_v4(struct net *net, struct sk_buff *skb, const int doff,
		      const u8 protocol,
		      const __be32 saddr, const __be32 daddr,
		      const __be16 sport, const __be16 dport,
		      const struct net_device *in)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return inet_lookup(net, &tcp_hashinfo, 
                   skb, doff,
				   saddr, sport, daddr, dport,
				   in->ifindex);
	case IPPROTO_UDP:
		return udp4_lib_lookup(net, saddr, sport, daddr, dport,
				       in->ifindex);
	}
	return NULL;
}

struct sock *nf_sk_lookup_slow_v4(struct net *net, const struct sk_buff *skb,
				  const struct net_device *indev)
{
	__be32 uninitialized_var(daddr), uninitialized_var(saddr);
	__be16 uninitialized_var(dport), uninitialized_var(sport);
	const struct iphdr *iph = ip_hdr(skb);
	struct sk_buff *data_skb = NULL;
	u8 uninitialized_var(protocol);
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	enum ip_conntrack_info ctinfo;
	struct nf_conn const *ct;
#endif
	int doff = 0;

	if (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP) {
		struct tcphdr _hdr;
		struct udphdr *hp;

		hp = skb_header_pointer(skb, ip_hdrlen(skb),
					iph->protocol == IPPROTO_UDP ?
					sizeof(*hp) : sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return NULL;

		protocol = iph->protocol;
		saddr = iph->saddr;
		sport = hp->source;
		daddr = iph->daddr;
		dport = hp->dest;
		data_skb = (struct sk_buff *)skb;
		doff = iph->protocol == IPPROTO_TCP ?
			ip_hdrlen(skb) + __tcp_hdrlen((struct tcphdr *)hp) :
			ip_hdrlen(skb) + sizeof(*hp);

	} else if (iph->protocol == IPPROTO_ICMP) {
		if (extract_icmp4_fields(skb, &protocol, &saddr, &daddr,
					 &sport, &dport))
			return NULL;
	} else {
		return NULL;
	}

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* Do the lookup with the original socket address in
	 * case this is a reply packet of an established
	 * SNAT-ted connection.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (ct &&
	    ((iph->protocol != IPPROTO_ICMP &&
	      ctinfo == IP_CT_ESTABLISHED_REPLY) ||
	     (iph->protocol == IPPROTO_ICMP &&
	      ctinfo == IP_CT_RELATED_REPLY)) &&
	    (ct->status & IPS_SRC_NAT_DONE)) {

		daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
		dport = (iph->protocol == IPPROTO_TCP) ?
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port :
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
	}
#endif

	return nf_socket_get_sock_v4(net, data_skb, doff, protocol, saddr,
				     daddr, sport, dport, indev);
}
#else
// }}}}
#endif

struct early_net {
	int	state;
    struct proc_dir_entry   *pe;
};

#if  LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#define PROC_OPS(s,o,r,w,l,d) static const struct file_operations s = { \
        .open    = o , \
        .read    = r , \
        .write   = w , \
        .llseek  = l , \
        .release = d \
}
#else
  #if  LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    #define PROC_OPS(s,o,r,w,l,d) static const struct proc_ops s = { \
        .proc_open    = o , \
        .proc_read    = r , \
        .proc_write   = w , \
        .proc_lseek   = l , \
        .proc_release = d  \
    }
  #else
    #define PROC_OPS(s,o,r,w,l,d) static const struct proc_ops s = { \
        .proc_open    = o , \
        .proc_read    = r , \
        .proc_write   = w , \
        .proc_release = d \
    }
  #endif
#endif

static int nstate_proc_open(struct inode *inode, struct file *file)
{
        return 0;
}

static int nstate_proc_close(struct inode *inode, struct file *file)
{
        return 0;
}

static ssize_t nstate_proc_read(struct file *file, char __user *buffer,
                              size_t count, loff_t *ppos)
{
    struct early_net *n = pde_data(file_inode(file));
    char data[4];
	
	if (*ppos > 0) return 0;

    data[0] = n->state ? '1':'0';
    data[1] = '\n';
	if (!(ACCESS_OK(VERIFY_WRITE, buffer, 2) &&
               !__copy_to_user(buffer, data, 2))) return -EFAULT;
    (*ppos) += 2;
	return 2;
}
static ssize_t nstate_proc_write(struct file *file, const char __user *buffer,
                     size_t length, loff_t *loff)
{
    struct early_net *n = pde_data(file_inode(file));
    char data[4];
    int l;
    memset(data,0,sizeof(data));
    l = min(length,sizeof(data)-1);
    if (!(ACCESS_OK(VERIFY_READ, buffer, l) &&
                !__copy_from_user(&data[0], buffer, l))) return -EFAULT;
    n->state = data[0] == '1' ? 1:0;
    return length;
}

PROC_OPS(nstate_proc_fops, nstate_proc_open,nstate_proc_read,nstate_proc_write,noop_llseek,nstate_proc_close);

static int early_net_id=0;
static inline struct early_net *early_pernet(struct net *net)
{
	return net_generic(net, early_net_id);
}

static unsigned int sk_early_on(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	struct net *net = state->net;
    struct early_net  *n = early_pernet(net);
	const struct iphdr *iph = ip_hdr(skb);

	if( skb->sk || !n->state ||
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

    struct early_net  *n = early_pernet(net);
    n->state = 0;
    n->pe = proc_create_data(name_state, S_IRUGO | S_IWUSR,
                                         net->proc_net, &nstate_proc_fops, n);
    if(!n->pe) return -ENOMEM;

	return nf_register_net_hooks(net, nf_sk_ipv4_ops,
		    ARRAY_SIZE(nf_sk_ipv4_ops));

}
static void __net_exit sk_net_exit(struct net *net) {

    struct early_net  *n = early_pernet(net);
    if(n->pe) proc_remove(n->pe);
	nf_unregister_net_hooks(net, nf_sk_ipv4_ops,
			      ARRAY_SIZE(nf_sk_ipv4_ops));

}

static struct pernet_operations sk_net_ops = {
	.init   = sk_net_init,
	.exit   = sk_net_exit,
	.id     = &early_net_id,
	.size   = sizeof(struct early_net),
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

/* vim: set ts=4 sw=4 et foldmarker={{{{,}}}} foldmethod=marker : */
