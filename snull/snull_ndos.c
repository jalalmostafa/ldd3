#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "snull.h"

int snull_open(struct net_device* dev)
{
    memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);

    if (dev == snull_devs[1]) {
        dev->dev_addr[ETH_ALEN - 1]++;
    }

    netif_start_queue(dev);
    return 0;
}

int snull_stop(struct net_device* dev)
{
    netif_stop_queue(dev);
    return 0;
}

static void snull_hw_tx(char* buf, int len, struct net_device* dev)
{
    /*
     * This function deals with hw details. This interface loops
     * back the packet to the other snull interface (if any).
     * In other words, this function implements the snull behaviour,
     * while all other procedures are rather device-independent
     */
    struct iphdr* ih;
    struct net_device* dest;
    struct snull_priv* priv;
    u32 *saddr, *daddr;
    struct snull_packet* tx_buffer;

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        printk(SNULL_ERROR "packet too short (%i octets)\n",
            len);
        return;
    }

    ih = (struct iphdr*)(buf + sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;

    ((u8*)saddr)[2] ^= 1; /* change the third octet (class C) */
    ((u8*)daddr)[2] ^= 1;

    ih->check = 0; /* and rebuild the checksum (ip needs it) */
    ih->check = ip_fast_csum((unsigned char*)ih, ih->ihl);

    if (dev == snull_devs[0])
        printk(SNULL_INFO "%08x:%05i --> %08x:%05i\n",
            ntohl(ih->saddr), ntohs(((struct tcphdr*)(ih + 1))->source),
            ntohl(ih->daddr), ntohs(((struct tcphdr*)(ih + 1))->dest));
    else
        printk(SNULL_INFO "%08x:%05i <-- %08x:%05i\n",
            ntohl(ih->daddr), ntohs(((struct tcphdr*)(ih + 1))->dest),
            ntohl(ih->saddr), ntohs(((struct tcphdr*)(ih + 1))->source));

    /*
     * Ok, now the packet is ready for transmission: first simulate a
     * receive interrupt on the twin device, then  a
     * transmission-done on the transmitting device
     */
    dest = snull_devs[dev == snull_devs[0] ? 1 : 0];
    priv = netdev_priv(dest);
    tx_buffer = snull_get_tx_buffer(dev);

    if (!tx_buffer) {
        printk(SNULL_INFO "Out of tx buffer, len is %i\n", len);
        return;
    }

    tx_buffer->datalen = len;
    memcpy(tx_buffer->data, buf, len);
    snull_enqueue_buf(dest, tx_buffer);
    if (priv->rx_int_enabled) {
        priv->status |= SNULL_RX_INTR;
        snull_interrupt(0, dest, NULL);
    }

    priv = netdev_priv(dev);
    priv->tx_packetlen = len;
    priv->tx_packetdata = buf;
    priv->status |= SNULL_TX_INTR;

    if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
        /* Simulate a dropped transmit interrupt */
        netif_stop_queue(dev);
        printk(SNULL_INFO "Simulate lockup at %ld, txp %ld\n", jiffies,
            (unsigned long)priv->stats.tx_packets);
    } else
        snull_interrupt(0, dev, NULL);
}

netdev_tx_t snull_xmit(struct sk_buff* skb, struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    int len = skb->len;
    char *data = skb->data, shortpkt[ETH_ZLEN];

    if (len < ETH_ZLEN) {
        memset(shortpkt, 0, ETH_ZLEN);
        memcpy(shortpkt, skb->data, skb->len);
        len = ETH_ZLEN;
        data = shortpkt;
    }

    netif_trans_update(dev);
    priv->skb = skb;
    snull_hw_tx(data, len, dev);
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
void snull_tx_timeout(struct net_device* dev)
#else
void snull_tx_timeout(struct net_device* dev, unsigned int txqueue)
#endif
{
    struct snull_priv* priv = netdev_priv(dev);
    struct netdev_queue* txq = netdev_get_tx_queue(dev, 0);
    printk(SNULL_DEBUG "Transmit timeout at %ld, latency %ld\n", jiffies, jiffies - txq->trans_start);
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
        printk(KERN_WARNING "snull: Can't change I/O address\n");
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