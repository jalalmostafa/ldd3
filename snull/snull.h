#ifndef _SNULL_H
#define _SNULL_H

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>

struct snull_packet {
    int datalen;
    char data[10];
    struct net_device* dev;
    struct snull_packet* next;
};

struct snull_priv {
    struct net_device_stats stats;
    int status;
    struct snull_packet* ppool;
    struct snull_packet* rx_queue; /* List of incoming packets */
    int rx_int_enabled;
    int tx_packetlen;
    u8* tx_packetdata;
    struct sk_buff* skb;
    spinlock_t lock;
    struct napi_struct napi;
};

#define SNULL_INFO KERN_INFO "snull: "
#define SNULL_DEBUG KERN_DEBUG "snull: "
#define SNULL_ERROR KERN_ERR "snull: "
#define SNULL_NOTICE KERN_NOTICE "snull: "

// NDOs
int snull_open(struct net_device* dev);
int snull_stop(struct net_device* dev);
netdev_tx_t snull_xmit(struct sk_buff* skb, struct net_device* dev);
int snull_ioctl(struct net_device* dev, struct ifreq* ifr, int cmd);
int snull_config(struct net_device* dev, struct ifmap* map);
// int snull_change_mtu(struct net_device* dev, int new_mtu);
void snull_tx_timeout(struct net_device* dev, unsigned int txqueue);
struct net_device_stats* snull_get_stats(struct net_device* dev);

void snull_teardown_pool(struct net_device* dev);
struct snull_packet* snull_get_tx_buffer(struct net_device* dev);
void snull_release_buffer(struct snull_packet* pkt);
void snull_enqueue_buf(struct net_device* dev, struct snull_packet* pkt);
struct snull_packet* snull_dequeue_buf(struct net_device* dev);

typedef void (*snull_interrupt_t)(int irq, void* dev_id, struct pt_regs* regs);
extern snull_interrupt_t snull_interrupt;
extern struct net_device* snull_devs[2];
extern int timeout;
extern int lockup;
extern bool use_napi;

#define SNULL_TX_INTR (1 << 0)
#define SNULL_RX_INTR (1 << 1)

#define SNULL_TIMEOUT 5
#define SNULL_NAPI_WEIGHT 2
#endif
