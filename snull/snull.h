#ifndef _SNULL_H
#define _SNULL_H
#define DEBUG

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <net/xdp.h>

#define SNULL_TX_INTR (1 << 0)
#define SNULL_RX_INTR (1 << 1)

#define SNULL_TIMEOUT 5
#define SNULL_NAPI_WEIGHT 2

enum snull_packet_type {
    SNULL_PACKET_SKB,
    SNULL_PACKET_XDP,
};

struct snull_packet_tx {
    int datalen;
    char* data;
    struct net_device* dev;
    union {
        struct sk_buff* skb;
        struct xdp_frame* xframe;
    };
    struct snull_packet_tx* next;
};

struct snull_rx_skb {
    int datalen;
    u8* data;
};

struct snull_packet_rx {
    union {
        struct snull_rx_skb skb;
        struct xdp_buff xbuf;
    };
    struct net_device* dev;
    struct page* page;
    struct snull_packet_rx* next;
};

#define SNULL_XDP_META XDP_PACKET_HEADROOM
#define SNULL_RX_HEADROOM (SNULL_XDP_META + sizeof(struct snull_packet_rx))
#define SNULL_RX_BUF_MAXSZ (PAGE_SIZE - SNULL_RX_HEADROOM)

struct snull_rxq {
    struct snull_packet_rx* head;
    struct page_pool* ppool;
    struct bpf_prog* xdp_prog;
    struct xdp_rxq_info xdp_rq;
};

struct snull_txq {
    struct snull_packet_tx* ppool;
    struct snull_packet_tx* head;
};

struct snull_priv {
    struct net_device_stats stats;
    struct snull_rxq rxq;
    struct snull_txq txq;
    int status;
    int rx_int_enabled;
    spinlock_t lock;
    struct napi_struct napi;
};

// NDOs
int snull_open(struct net_device* dev);
int snull_stop(struct net_device* dev);
netdev_tx_t snull_xmit(struct sk_buff* skb, struct net_device* dev);
int snull_ioctl(struct net_device* dev, struct ifreq* ifr, int cmd);
int snull_config(struct net_device* dev, struct ifmap* map);
int snull_change_mtu(struct net_device* dev, int new_mtu);
void snull_tx_timeout(struct net_device* dev, unsigned int txqueue);
struct net_device_stats* snull_get_stats(struct net_device* dev);
int snull_xdp(struct net_device* dev, struct netdev_bpf* bpf);
int snull_xdp_xmit(struct net_device* dev, int n, struct xdp_frame** xdp, u32 flags);
int snull_xsk_wakeup(struct net_device* dev, u32 queue_id, u32 flags);

int snull_setup_pool(struct net_device* dev);
void snull_teardown_pool(struct net_device* dev);
struct snull_packet_tx* snull_get_tx_buffer(struct net_device* dev);
void snull_release_tx(struct snull_packet_tx* pkt);
void snull_release_rx(struct snull_packet_rx* pkt, bool recycle);

void snull_enqueue_buf(struct net_device* dev, struct snull_packet_tx* pkt);
struct snull_packet_rx* snull_dequeue_buf(struct net_device* dev);

typedef void (*snull_interrupt_t)(int irq, void* dev_id, struct pt_regs* regs);
extern snull_interrupt_t snull_interrupt;
extern struct net_device* snull_devs[2];
extern int timeout;
extern int lockup;
extern bool use_napi;

#endif
