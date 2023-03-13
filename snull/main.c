#include <linux/module.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "snull.h"

struct net_device* snull_devs[2];
int timeout;
int lockup = 0;
bool use_napi = false;
snull_interrupt_t snull_interrupt;
int pool_size = 8;

struct net_device_ops snull_ops = {
    .ndo_open = snull_open,
    .ndo_start_xmit = snull_xmit,
    .ndo_tx_timeout = snull_tx_timeout,
    .ndo_get_stats = snull_get_stats,
    .ndo_change_mtu = snull_change_mtu,
    .ndo_do_ioctl = snull_ioctl,
    .ndo_set_config = snull_config,
    // XDP NDOs
    .ndo_bpf = NULL,
    .ndo_xsk_wakeup = NULL,
    .ndo_xdp_xmit = NULL,
};

void snull_setup_pool(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    int i;
    struct snull_packet* pkt;

    priv->ppool = NULL;
    for (i = 0; i < pool_size; i++) {
        pkt = kmalloc(sizeof(struct snull_packet), GFP_KERNEL);
        if (pkt == NULL) {
            printk(SNULL_NOTICE "Ran out of memory allocating packet pool\n");
            return;
        }
        pkt->dev = dev;
        pkt->next = priv->ppool;
        priv->ppool = pkt;
    }
}

void snull_teardown_pool(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet* pkt;

    while ((pkt = priv->ppool)) {
        priv->ppool = pkt->next;
        kfree(pkt);
        /* FIXME - in-flight packets ? */
    }
}

struct snull_packet* snull_get_tx_buffer(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    unsigned long flags;
    struct snull_packet* pkt;

    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->ppool;
    if (!pkt) {
        printk(SNULL_DEBUG "Out of Pool\n");
        return pkt;
    }
    priv->ppool = pkt->next;
    if (priv->ppool == NULL) {
        printk(SNULL_INFO "Pool empty\n");
        netif_stop_queue(dev);
    }
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

void snull_release_buffer(struct snull_packet* pkt)
{
    unsigned long flags;
    struct snull_priv* priv = netdev_priv(pkt->dev);

    spin_lock_irqsave(&priv->lock, flags);
    pkt->next = priv->ppool;
    priv->ppool = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);
    if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
        netif_wake_queue(pkt->dev);
}

void snull_enqueue_buf(struct net_device* dev, struct snull_packet* pkt)
{
    unsigned long flags;
    struct snull_priv* priv = netdev_priv(dev);

    spin_lock_irqsave(&priv->lock, flags);
    pkt->next = priv->rx_queue; /* FIXME - misorders packets */
    priv->rx_queue = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);
}

struct snull_packet* snull_dequeue_buf(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet* pkt;
    unsigned long flags;

    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->rx_queue;
    if (pkt != NULL)
        priv->rx_queue = pkt->next;
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

void snull_rx_bottom_ints(struct net_device* dev, int enable)
{
    struct snull_priv* priv = netdev_priv(dev);
    priv->rx_int_enabled = enable;
}

void snull_rx(struct net_device* dev, struct snull_packet* pkt)
{
    struct sk_buff* skb;
    struct snull_priv* priv = netdev_priv(dev);

    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        if (printk_ratelimit()) {
            printk(SNULL_NOTICE "rx low on mem - packet dropped\n");
        }

        priv->stats.rx_dropped++;
        return;
    }

    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    priv->stats.rx_packets++;
    priv->stats.rx_bytes += pkt->datalen;
    netif_rx(skb);
}

static void snull_regular_interrupt(int irq, void* dev_id, struct pt_regs* regs)
{
    int statusword;
    struct snull_priv* priv;
    struct snull_packet* pkt = NULL;

    struct net_device* dev = (struct net_device*)dev_id;
    if (!dev)
        return;

    priv = netdev_priv(dev);

    spin_lock(&priv->lock);

    statusword = priv->status;
    priv->status = 0;

    if (statusword & SNULL_RX_INTR) {
        /* send it to snull_rx for handling */
        pkt = priv->rx_queue;
        if (pkt) {
            priv->rx_queue = pkt->next;
            snull_rx(dev, pkt);
        }
    }

    if (statusword & SNULL_TX_INTR) {
        /* a transmission is over: free the skb */
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->tx_packetlen;
        dev_kfree_skb(priv->skb);
    }

    spin_unlock(&priv->lock);

    if (pkt)
        snull_release_buffer(pkt);
}

static int snull_poll(struct napi_struct* napi, int budget)
{
    int npackets = 0;
    unsigned long flags;
    struct sk_buff* skb;
    struct net_device* dev = napi->dev;
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet* pkt;

    while (npackets < budget) {
        pkt = snull_dequeue_buf(dev);
        skb = dev_alloc_skb(pkt->datalen + 2);

        if (!skb) {
            if (printk_ratelimit())
                printk(KERN_NOTICE "snull: packet dropped\n");
            priv->stats.rx_dropped++;
            snull_release_buffer(pkt);
            continue;
        }
        // add 2 bytes to head so it fits in 16bytes and the IP header is aligned on 16bytes
        skb_reserve(skb, 2);
        memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
        skb->dev = dev;
        skb->protocol = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        netif_receive_skb(skb);

        npackets++;
        priv->stats.rx_packets++;
        priv->stats.rx_bytes += pkt->datalen;
        snull_release_buffer(pkt);
    }

    /* If we processed all packets, we're done; tell the kernel and reenable ints */
    if (npackets < budget) {
        spin_lock_irqsave(&priv->lock, flags);
        if (napi_complete_done(napi, npackets))
            snull_rx_bottom_ints(dev, 1);
        spin_unlock_irqrestore(&priv->lock, flags);
    }

    return npackets;
}

static void snull_napi_interrupt(int irq, void* dev_id, struct pt_regs* regs)
{
    int statusword;
    struct snull_priv* priv;
    struct snull_packet* pkt = NULL;

    struct net_device* dev = (struct net_device*)dev_id;
    if (!dev)
        return;

    priv = netdev_priv(dev);

    spin_lock(&priv->lock);

    statusword = priv->status;
    priv->status = 0;

    if (statusword & SNULL_RX_INTR) {
        // disable bottom interrupts because when there is at least one packet available then no need to fire this again just tell NAPI, at least there is one packet available for fetching.
        snull_rx_bottom_ints(dev, 0);
        // snull_rx call is deffered/scheduled to snull_poll, that is managed by NAPI budget
        napi_schedule(&priv->napi);
    }

    if (statusword & SNULL_TX_INTR) {
        /* a transmission is over: free the skb */
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->tx_packetlen;
        dev_kfree_skb(priv->skb);
    }

    spin_unlock(&priv->lock);

    if (pkt)
        snull_release_buffer(pkt);
}

static void snull_dev_init(struct net_device* dev)
{
    struct snull_priv* priv;

    ether_setup(dev);
    dev->netdev_ops = &snull_ops;
    dev->watchdog_timeo = timeout;
    dev->flags |= IFF_NOARP;
    dev->features |= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA;

    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct snull_priv));
    if (use_napi) {
        netif_napi_add(dev, &priv->napi, snull_poll, SNULL_NAPI_WEIGHT);
    }
    spin_lock_init(&priv->lock);
    snull_rx_bottom_ints(dev, 1);
    snull_setup_pool(dev);
}

static void snull_exit(void)
{
    int i;
    struct net_device* dev;

    for (i = 0; i < 2; i++) {
        dev = snull_devs[i];
        if (dev) {
            unregister_netdev(dev);
            snull_teardown_pool(dev);
            free_netdev(dev);
        }
    }
}

static int __init snull_init(void)
{
    int i, result = -ENOMEM;

    snull_interrupt = use_napi ? snull_napi_interrupt : snull_regular_interrupt;

    snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_dev_init);
    snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d", NET_NAME_UNKNOWN, snull_dev_init);

    if (snull_devs[0] == NULL || snull_devs[1] == NULL) {
        goto out;
    }

    for (i = 0; i < 2; i++)
        if ((result = register_netdev(snull_devs[i])))
            printk(SNULL_ERROR "error %i registering device \"%s\"\n",
                result, snull_devs[i]->name);

out:
    if (result) {
        snull_exit();
    }

    return result;
}

module_init(snull_init);
module_exit(snull_exit);
module_param(timeout, int, 0);
module_param(lockup, int, 0);
module_param(use_napi, bool, 0);

MODULE_LICENSE("GPL");
