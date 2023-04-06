#include "snull.h"

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>

int snull_open(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);

    if (dev == snull_devs[1]) {
        dev->dev_addr[ETH_ALEN - 1]++;
    }

    if (use_napi) {
        napi_enable(&priv->napi);
    }

    netif_start_queue(dev);
    return 0;
}

int snull_stop(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);

    netif_stop_queue(dev);

    if (use_napi) {
        napi_disable(&priv->napi);
    }

    return 0;
}

static int snull_hw_tx(char* buf, int len, struct net_device* dev, enum snull_packet_type type, void* skb)
{
    struct iphdr* ih;
    struct net_device* dest;
    struct snull_priv* priv;
    u32 *saddr, *daddr;
    struct snull_packet_tx* tx_buffer;
    char shortpkt[ETH_ZLEN];

    pr_debug("run\n");

    if (len < ETH_ZLEN) {
        memset(shortpkt, 0, ETH_ZLEN);
        memcpy(shortpkt, buf, len);
        len = ETH_ZLEN;
        buf = shortpkt;
    }

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        pr_err("packet too short (%i octets)\n", len);
        return -EINVAL;
    }

    ih = (struct iphdr*)(buf + sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;

    ((u8*)saddr)[2] ^= 1; /* change the third octet (class C) */
    ((u8*)daddr)[2] ^= 1;

    ih->check = 0; /* and rebuild the checksum (ip needs it) */
    ih->check = ip_fast_csum((unsigned char*)ih, ih->ihl);

    if (dev == snull_devs[0])
        pr_info("%08x:%05i --> %08x:%05i\n",
            ntohl(ih->saddr), ntohs(((struct tcphdr*)(ih + 1))->source),
            ntohl(ih->daddr), ntohs(((struct tcphdr*)(ih + 1))->dest));
    else
        pr_info("%08x:%05i <-- %08x:%05i\n",
            ntohl(ih->daddr), ntohs(((struct tcphdr*)(ih + 1))->dest),
            ntohl(ih->saddr), ntohs(((struct tcphdr*)(ih + 1))->source));

    dest = snull_devs[dev == snull_devs[0] ? 1 : 0];
    priv = netdev_priv(dest);
    pr_debug("snull_get_tx_buffer\n");
    // FIXME: it is deadlock here?
    tx_buffer = snull_get_tx_buffer(dev);

    if (!tx_buffer) {
        pr_info("Out of tx buffer, len is %i\n", len);
        return -EBUSY;
    }

    switch (type) {
    case SNULL_PACKET_SKB:
        tx_buffer->skb = skb;
        break;
    case SNULL_PACKET_XDP:
        tx_buffer->xframe = skb;
        break;
    default:
        break;
    }

    tx_buffer->datalen = len;
    tx_buffer->data = buf;

    pr_debug("Before enqueue\n");
    // enqueue in destination interface
    snull_enqueue_buf(dest, tx_buffer);
    if (priv->rx_int_enabled) {
        priv->status |= SNULL_RX_INTR;
        pr_debug("before remote interrupt\n");
        snull_interrupt(0, dest, NULL);
        pr_debug("after remote interrupt\n");
    }

    priv = netdev_priv(dev);
    priv->status |= SNULL_TX_INTR;

    pr_debug("Before local interrupt\n");

    if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
        /* Simulate a dropped transmit interrupt */
        netif_stop_queue(dev);
        pr_info("Simulate lockup at %ld, txp %ld\n", jiffies,
            (unsigned long)priv->stats.tx_packets);
    } else
        snull_interrupt(0, dev, NULL);

    pr_debug("After local interrupt\n");
    return 0;
}

#define snull_hw_tx_skb(skb, dev) snull_hw_tx(skb->data, skb->len, dev, SNULL_PACKET_SKB, skb);

#define snull_hw_tx_xdp(xframe, dev) snull_hw_tx(xframe->data, xframe->len, dev, SNULL_PACKET_XDP, xframe);

netdev_tx_t snull_xmit(struct sk_buff* skb, struct net_device* dev)
{
    int err = snull_hw_tx_skb(skb, dev);
    netif_trans_update(dev);
    return err ? NETDEV_TX_BUSY : NETDEV_TX_OK;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
void snull_tx_timeout(struct net_device* dev)
#else
void snull_tx_timeout(struct net_device* dev, unsigned int txqueue)
#endif
{
    struct snull_priv* priv = netdev_priv(dev);
    struct netdev_queue* txq = netdev_get_tx_queue(dev, 0);
    pr_debug("Transmit timeout at %ld, latency %ld\n", jiffies, jiffies - txq->trans_start);
    priv->status |= SNULL_TX_INTR;
    snull_interrupt(0, dev, NULL);
    priv->stats.tx_errors++;

    spin_lock(&priv->lock);
    snull_teardown_pool(dev);
    snull_setup_pool(dev);
    spin_unlock(&priv->lock);

    netif_wake_queue(dev);
}

struct net_device_stats* snull_get_stats(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    return &priv->stats;
}

int snull_ioctl(struct net_device* dev, struct ifreq* ifr, int cmd)
{
    return 0;
}

int snull_config(struct net_device* dev, struct ifmap* map)
{
    if (dev->flags & IFF_UP) /* can't act on a running interface */
        return -EBUSY;

    /* Don't allow changing the I/O address */
    if (map->base_addr != dev->base_addr) {
        pr_warn("Can't change I/O address\n");
        return -EOPNOTSUPP;
    }

    /* Allow changing the IRQ */
    if (map->irq != dev->irq) {
        dev->irq = map->irq;
        /* request_irq() is delayed to open-time */
    }

    /* ignore other fields */
    return 0;
}

int snull_change_mtu(struct net_device* dev, int new_mtu)
{
    unsigned long flags;
    struct snull_priv* priv = netdev_priv(dev);
    spinlock_t* lock = &priv->lock;

    if ((new_mtu < 68) || (new_mtu > 1500))
        return -EINVAL;

    spin_lock_irqsave(lock, flags);
    dev->mtu = new_mtu;
    spin_unlock_irqrestore(lock, flags);

    return 0;
}

static int snull_xdp_set(struct net_device* dev, struct netdev_bpf* bpf)
{
    struct snull_priv* priv = netdev_priv(dev);
    struct bpf_prog* old_prog;
    unsigned long flags;

    if (dev->mtu > SNULL_RX_BUF_MAXSZ) {
        pr_warn("MTU %u is too big. Must be less then or equal to %lu\n", dev->mtu, SNULL_RX_BUF_MAXSZ);
        return -EINVAL;
    }

    spin_lock_irqsave(&priv->lock, flags);
    old_prog = priv->rxq.xdp_prog;
    priv->rxq.xdp_prog = bpf->prog;

    if (old_prog) {
        bpf_prog_put(old_prog);
    }

    spin_unlock_irqrestore(&priv->lock, flags);
    return 0;
}

int snull_xdp(struct net_device* dev, struct netdev_bpf* bpf)
{
    switch (bpf->command) {
    case XDP_SETUP_PROG:
        return snull_xdp_set(dev, bpf);
    case XDP_SETUP_XSK_POOL:
    default:
        break;
    }

    return -EINVAL;
}

int snull_xdp_xmit_one(struct xdp_frame* xframe, struct net_device* dev)
{
    pr_debug("run\n");
    return snull_hw_tx_xdp(xframe, dev);
}

int snull_xdp_xmit(struct net_device* dev, int n, struct xdp_frame** xdp, u32 flags)
{
    int i, nxmit;
    struct xdp_frame* xframe;
    struct snull_priv* priv;

    if (flags & ~XDP_XMIT_FLAGS_MASK) {
        return -EINVAL;
    }

    priv = netdev_priv(dev);

    for (i = 0; i < n; i++) {
        xframe = xdp[i];
        if (!xframe)
            continue;

        if (snull_xdp_xmit_one(xframe, dev))
            break;
        nxmit++;
    }

    return nxmit;
}

int snull_xsk_wakeup(struct net_device* dev, u32 queue_id, u32 flags)
{
    return -EINVAL;
}
