#include "snull.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/page_pool.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <linux/bpf_trace.h>

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
    .ndo_bpf = snull_xdp,
    .ndo_xdp_xmit = snull_xdp_xmit,
    // .ndo_xsk_wakeup = snull_xsk_wakeup,
};

int snull_setup_pool(struct net_device* dev)
{
    int i, err;
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet_tx* pkt;
    struct page_pool_params pp_params = {
        .dev = dev->dev.parent,
        .dma_dir = DMA_NONE,
        .flags = 0,
        .max_len = SNULL_RX_BUF_MAXSZ,
        .nid = NUMA_NO_NODE,
        .offset = 0,
        .pool_size = pool_size,
        .order = 0,
    };

    // initialize tx pool
    priv->txq.head = NULL;
    for (i = 0; i < pool_size; i++) {
        pkt = kmalloc(sizeof(struct snull_packet_tx), GFP_KERNEL);
        if (pkt == NULL) {
            pr_notice("Ran out of memory allocating packet pool\n");
            return -ENOMEM;
        }

        pkt->dev = dev;
        pkt->datalen = 0;
        pkt->next = priv->txq.ppool;
        priv->txq.ppool = pkt;
    }

    // initialize rx pool
    priv->rxq.ppool = page_pool_create(&pp_params);
    priv->rxq.head = NULL;
    if (IS_ERR(priv->rxq.ppool)) {
        err = PTR_ERR(priv->rxq.ppool);
        goto error;
    }

    err = xdp_rxq_info_reg(&priv->rxq.xdp_rq, dev, 0, 0);
    if (err) {
        pr_err("xdp_rxq_info_reg failed\n");
        goto xdp_reg_error;
    }

    err = xdp_rxq_info_reg_mem_model(&priv->rxq.xdp_rq, MEM_TYPE_PAGE_POOL,
        priv->rxq.ppool);
    if (err) {
        pr_err("xdp_rxq_info_reg_mem_model failed");
        goto xdp_mem_reg_err;
    }

    return 0;

xdp_mem_reg_err:
    xdp_rxq_info_unreg_mem_model(&priv->rxq.xdp_rq);
xdp_reg_error:
    page_pool_destroy(priv->rxq.ppool);
error:
    priv->rxq.ppool = NULL;
    return err;
}

void snull_teardown_pool(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet_tx* pkttx;

    while ((pkttx = priv->txq.ppool)) {
        priv->txq.ppool = pkttx->next;
        kfree(pkttx);
        /* FIXME - in-flight packets ? */
    }
    priv->txq.head = NULL;

    xdp_rxq_info_unreg_mem_model(&priv->rxq.xdp_rq);
    xdp_rxq_info_unreg(&priv->rxq.xdp_rq);

    if (priv->rxq.ppool) {
        page_pool_destroy(priv->rxq.ppool);
        priv->rxq.ppool = NULL;
    }
    priv->rxq.head = NULL;
}

struct snull_packet_tx* snull_get_tx_buffer(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    unsigned long flags;
    struct snull_packet_tx* pkt;

    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->txq.ppool;

    if (!pkt) {
        pr_debug("Out of Pool\n");
        goto out;
    }

    priv->txq.ppool = pkt->next;
    if (priv->txq.ppool == NULL) {
        pr_debug("Pool empty\n");
        netif_stop_queue(dev);
    }

    pkt->next = priv->txq.head;
    priv->txq.head = pkt;

out:
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

void snull_release_tx(struct snull_packet_tx* pkt)
{
    unsigned long flags;
    struct snull_priv* priv = netdev_priv(pkt->dev);

    spin_lock_irqsave(&priv->lock, flags);
    priv->txq.head = pkt->next;
    pkt->next = priv->txq.ppool;
    priv->txq.ppool = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);

    if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
        netif_wake_queue(pkt->dev);
}

void snull_release_rx(struct snull_packet_rx* pkt, bool recycle)
{
    struct snull_priv* priv = netdev_priv(pkt->dev);

    if (!priv->rxq.ppool) {
        pr_debug("snull_release_rx null page pool\n");
        return;
    }

    recycle ? page_pool_recycle_direct(priv->rxq.ppool, pkt->page) : page_pool_release_page(priv->rxq.ppool, pkt->page);
}

void snull_enqueue_buf(struct net_device* target, struct snull_packet_tx* pkt_tx)
{
    unsigned long flags;
    struct snull_priv* priv = netdev_priv(target);
    struct snull_packet_rx* pkt_rx;
    struct page* page;
    u8* hardstart;

    if (!priv->rxq.ppool) {
        pr_debug("Null Page Pool\n");
        return;
    }

    page = page_pool_dev_alloc_pages(priv->rxq.ppool);
    if (!page) {
        pr_debug("page_pool_dev_alloc_pages returns NULL\n");
        return;
    }
    hardstart = page_address(page);
    memset(hardstart, 0, PAGE_SIZE);
    pkt_rx = (struct snull_packet_rx*)hardstart;
    pkt_rx->page = page;
    pkt_rx->dev = target;

    if (READ_ONCE(priv->rxq.xdp_prog)) {
        xdp_init_buff(&pkt_rx->xbuf, PAGE_SIZE, &priv->rxq.xdp_rq);
        xdp_prepare_buff(&pkt_rx->xbuf, hardstart, SNULL_RX_HEADROOM, pkt_tx->datalen, false);
        pkt_rx->xbuf.data = memcpy(hardstart + SNULL_RX_HEADROOM, pkt_tx->data, pkt_tx->datalen);
    } else {
        pkt_rx->skb.datalen = pkt_tx->datalen;
        pkt_rx->skb.data = memcpy(hardstart + SNULL_RX_HEADROOM, pkt_tx->data, pkt_rx->skb.datalen);
    }

    spin_lock_irqsave(&priv->lock, flags);
    pkt_rx->next = priv->rxq.head;
    priv->rxq.head = pkt_rx;
    spin_unlock_irqrestore(&priv->lock, flags);
}

struct snull_packet_rx* snull_dequeue_buf(struct net_device* dev)
{
    struct snull_priv* priv = netdev_priv(dev);
    struct snull_packet_rx* pkt;
    unsigned long flags;

    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->rxq.head;
    if (pkt != NULL)
        priv->rxq.head = pkt->next;
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

void snull_rx_top_ints(struct net_device* dev, int enable)
{
    struct snull_priv* priv = netdev_priv(dev);
    priv->rx_int_enabled = enable;
}

static struct sk_buff* snull_build_skb(struct snull_packet_rx* pkt)
{
    struct sk_buff* skb;
    struct snull_priv* priv = netdev_priv(pkt->dev);

    skb = netdev_alloc_skb_ip_align(pkt->dev, pkt->skb.datalen);
    if (!skb) {
        if (printk_ratelimit())
            pr_notice("low mem - packet dropped\n");
        priv->stats.rx_dropped++;
        return ERR_PTR(-ENOMEM);
    }

    memcpy(skb_put(skb, pkt->skb.datalen), pkt->skb.data, pkt->skb.datalen);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb->protocol = eth_type_trans(skb, pkt->dev);

    priv->stats.rx_packets++;
    priv->stats.rx_bytes += skb->len;

    return skb;
}

static int snull_rcv_skb(struct snull_packet_rx* pkt, bool napi)
{
    struct sk_buff* skb;
    skb = snull_build_skb(pkt);
    if (IS_ERR(skb))
        return PTR_ERR(skb);

    return napi ? netif_receive_skb(skb) : netif_rx(skb);
}

static int snull_xdp_pass(struct xdp_buff* xbuf, struct net_device* dev, bool napi)
{
    struct xdp_frame* xframe;
    struct sk_buff* skb;

    xframe = xdp_convert_buff_to_frame(xbuf);
    pr_debug("xframe %p\n", xframe);
    skb = xdp_build_skb_from_frame(xframe, dev);
    if (!skb) {
        return -ENOMEM;
    }

    return napi ? netif_receive_skb(skb) : netif_rx(skb);
}

static int snull_xdp_tx(struct xdp_buff* xbuf, struct net_device* dev)
{
    struct xdp_frame* xframe;
    pr_debug("[dev: %p] transmitting xdp_frame\n", dev);
    xframe = xdp_convert_buff_to_frame(xbuf);
    return snull_xdp_xmit_one(xframe, dev);
}

static int snull_rcv_xdp(struct bpf_prog* xdp_prog, struct snull_packet_rx* pkt,
    struct net_device* dev, bool napi)
{
    int err = 0;
    u32 verdict;

    pr_debug("wants to run xdp\n");
    verdict = bpf_prog_run_xdp(xdp_prog, &pkt->xbuf);
    pr_debug("switch verdict\n");

    switch (verdict) {
    case XDP_ABORTED:
        pr_debug("XDP Aborting\n");
        err = -1;
        break;
    case XDP_DROP:
        pr_debug("XDP Dropping\n");
        break;
    case XDP_PASS:
        pr_debug("XDP Passing\n");
        err = snull_xdp_pass(&pkt->xbuf, dev, napi);
        break;
    case XDP_TX:
        pr_debug("XDP TXing\n");
        err = snull_xdp_tx(&pkt->xbuf, dev);
        break;
    case XDP_REDIRECT:
        pr_debug("XDP Redirecting\n");
        err = xdp_do_redirect(dev, &pkt->xbuf, xdp_prog);
        break;
    default:
        pr_debug("XDP Unknown: %u\n", verdict);
        bpf_warn_invalid_xdp_action(verdict);
        break;
    }

    if (err < 0) {
        pr_debug("err=%d\n", err);
        trace_xdp_exception(dev, xdp_prog, verdict);
    }

    return err;
}

static void snull_regular_interrupt(int irq, void* dev_id, struct pt_regs* regs)
{
    int statusword;
    struct snull_priv* priv;
    struct snull_packet_rx* pkt = NULL;
    struct net_device* dev = (struct net_device*)dev_id;
    pr_debug("run\n");

    if (!dev)
        return;

    priv = netdev_priv(dev);

    spin_lock(&priv->lock);
    statusword = priv->status;
    priv->status = 0;
    spin_unlock(&priv->lock);

    if (statusword & SNULL_RX_INTR) {
        /* send it to snull_rx for handling */
        pkt = READ_ONCE(priv->rxq.head);
        if (!pkt) {
            return;
        }

        spin_lock(&priv->lock);
        priv->rxq.head = pkt->next;
        spin_unlock(&priv->lock);

        if (priv->rxq.xdp_prog) {
            snull_rcv_xdp(priv->rxq.xdp_prog, pkt, dev, false);
        } else {
            snull_rcv_skb(pkt, false);
        }
        snull_release_rx(pkt, !!priv->rxq.xdp_prog);
    }

    if (statusword & SNULL_TX_INTR) {
        /* a transmission is over: free the skb */
        spin_lock(&priv->lock);
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->txq.head->datalen;
        if (!priv->rxq.xdp_prog) {
            dev_kfree_skb(priv->txq.head->skb);
        }
        spin_unlock(&priv->lock);

        snull_release_tx(priv->txq.head);
    }
}

static int snull_poll(struct napi_struct* napi, int budget)
{
    int npackets = 0;
    unsigned long flags;
    struct snull_packet_rx* pkt;
    struct net_device* dev = napi->dev;
    struct snull_priv* priv = netdev_priv(dev);
    struct bpf_prog* xdp_prog = READ_ONCE(priv->rxq.xdp_prog);

    while (npackets < budget && priv->rxq.head) {
        pkt = snull_dequeue_buf(dev);
        if (!pkt) {
            pr_debug("rx pkt NULL\n");
            break;
        }

        pr_debug("npackets: %d\n", npackets);
        if (xdp_prog) {
            snull_rcv_xdp(xdp_prog, pkt, dev, true);
            snull_release_rx(pkt, true);
        } else {
            snull_rcv_skb(pkt, true);
            snull_release_rx(pkt, false);
        }

        npackets++;
    }

    /* If we processed all packets, we're done; tell the kernel and reenable ints */
    if (npackets < budget) {
        spin_lock_irqsave(&priv->lock, flags);
        if (napi_complete_done(napi, npackets))
            snull_rx_top_ints(dev, 1);
        spin_unlock_irqrestore(&priv->lock, flags);
    }

    return npackets;
}

static void snull_napi_interrupt(int irq, void* dev_id, struct pt_regs* regs)
{
    int statusword;
    struct snull_priv* priv;

    struct net_device* dev = (struct net_device*)dev_id;
    if (!dev)
        return;

    priv = netdev_priv(dev);

    spin_lock(&priv->lock);
    statusword = priv->status;
    priv->status = 0;
    spin_unlock(&priv->lock);

    if (statusword & SNULL_RX_INTR && napi_schedule_prep(&priv->napi)) {
        // disable top interrupts because when there is at least one packet available then no need to fire this again just tell NAPI, at least there is one packet available for fetching.
        snull_rx_top_ints(dev, 0);
        // snull_rx call is deffered/scheduled to snull_poll, that is managed by NAPI budget
        __napi_schedule(&priv->napi);
    }

    if (statusword & SNULL_TX_INTR) {
        /* a transmission is over: free the skb */
        spin_lock(&priv->lock);
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->txq.head->datalen;
        dev_kfree_skb(priv->txq.head->skb);
        spin_unlock(&priv->lock);
        snull_release_tx(priv->txq.head);
    }
}

int snull_header(struct sk_buff* skb, struct net_device* dev,
    unsigned short type, const void* daddr, const void* saddr,
    unsigned len)
{
    struct ethhdr* eth = (struct ethhdr*)skb_push(skb, ETH_HLEN);

    eth->h_proto = htons(type);
    memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
    memcpy(eth->h_dest, daddr ? daddr : dev->dev_addr, dev->addr_len);
    eth->h_dest[ETH_ALEN - 1] ^= 0x01; /* dest is us xor 1 */
    return (dev->hard_header_len);
}

struct header_ops snull_header_ops = {
    .create = snull_header,
};

static void snull_dev_init(struct net_device* dev)
{
    struct snull_priv* priv;

    ether_setup(dev);
    dev->netdev_ops = &snull_ops;
    dev->header_ops = &snull_header_ops;
    dev->watchdog_timeo = timeout;
    dev->flags |= IFF_NOARP;
    dev->features |= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA;

    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct snull_priv));
    if (use_napi) {
        netif_napi_add(dev, &priv->napi, snull_poll, SNULL_NAPI_WEIGHT);
    }
    spin_lock_init(&priv->lock);
    snull_rx_top_ints(dev, 1);
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
            pr_err("error %i registering device \"%s\"\n",
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
