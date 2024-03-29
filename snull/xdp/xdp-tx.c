/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#define OVER(x, d) (x + 1 > (typeof(x))d)
// static __u8 pong_reply[FRAME_SIZE];

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// unsigned short from32to16(unsigned int x)
// {
//     /* add up 16-bit and 16-bit for 16+c bit */
//     x = (x & 0xffff) + (x >> 16);
//     /* add up carry.. */
//     x = (x & 0xffff) + (x >> 16);
//     return x;
// }

// /*
//  * This function code has been taken from
//  * Linux kernel lib/checksum.c
//  */
// __u32 from64to32(__u64 x)
// {
//     /* add up 32-bit and 32-bit for 32+c bit */
//     x = (x & 0xffffffff) + (x >> 32);
//     /* add up carry.. */
//     x = (x & 0xffffffff) + (x >> 32);
//     return (__u32)x;
// }

// /*
//  * This function code has been taken from
//  * Linux kernel lib/checksum.c
//  */
// unsigned int inet_csum(const unsigned char* buff, int len)
// {
//     unsigned int result = 0;
//     int odd;

//     if (len <= 0)
//         goto out;
//     odd = 1 & (unsigned long)buff;
//     if (odd) {
// #ifdef __LITTLE_ENDIAN
//         result += (*buff << 8);
// #else
//         result = *buff;
// #endif
//         len--;
//         buff++;
//     }
//     if (len >= 2) {
//         if (2 & (unsigned long)buff) {
//             result += *(unsigned short*)buff;
//             len -= 2;
//             buff += 2;
//         }
//         if (len >= 4) {
//             const unsigned char* end = buff + ((unsigned int)len & ~3);
//             unsigned int carry = 0;

//             do {
//                 unsigned int w = *(unsigned int*)buff;

//                 buff += 4;
//                 result += carry;
//                 result += w;
//                 carry = (w > result);
//             } while (buff < end);
//             result += carry;
//             result = (result & 0xffff) + (result >> 16);
//         }
//         if (len & 2) {
//             result += *(unsigned short*)buff;
//             buff += 2;
//         }
//     }
//     if (len & 1)
// #ifdef __LITTLE_ENDIAN
//         result += *buff;
// #else
//         result += (*buff << 8);
// #endif
//     result = from32to16(result);
//     if (odd)
//         result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
// out:
//     return result;
// }

__sum16 inet_fast_csum(const void* addr, unsigned int count)
{
    long sum = 0;

    while (count > 1) {
        /* This is the inner loop */
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
        sum += *(unsigned char*)addr;

    /*  Fold 32-bit sum to 16 bits */
    // while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

void csum_replace2(__u16* sum, __u16 old, __u16 new)
{
    __u16 csum = ~*sum;

    csum += ~old;
    csum += csum < (__u16)~old;

    csum += new;
    csum += csum < (__u16) new;

    *sum = ~csum;
}

SEC("xdp")
int xdp_tx(struct xdp_md* ctx)
{
    struct ethhdr* eth;
    struct iphdr* iph;
    struct icmphdr* icmph;
    char mac[6];
    __u32 ipaddr;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    // int datalen, len = data_end - data;
    bpf_printk("XDP TX\n");

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    eth = data;
    iph = (data + sizeof(struct ethhdr));
    icmph = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (eth->h_proto != htons(ETH_P_IP)) {
        bpf_printk("NOT IPv4 frame.\n");
        return XDP_PASS;
    }

    if (OVER(iph, data_end)) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    if (iph->protocol != 1) {
        // bpf_printk("NOT ICMP Packet - protocol: %d.\n", iph->protocol);
        return XDP_PASS;
    }

    if (OVER(icmph, data_end)) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    bpf_printk("constructing ping\n");

    // datalen = len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    // swap macs
    memcpy(mac, eth->h_dest, sizeof(mac));
    memcpy(eth->h_dest, eth->h_source, sizeof(mac));
    memcpy(eth->h_source, mac, sizeof(mac));

    // build echo reply

    icmph->type = ICMP_ECHOREPLY;
    icmph->code = 0;
    icmph->checksum = 0;
    // icmph->checksum = inet_fast_csum(icmph, 2 + datalen);

    // swap ips
    ipaddr = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = ipaddr;
    iph->check = 0;
    // iph->check = inet_fast_csum(iph, iph->ihl * 4);
    // csum_replace2(&iph->check, htons(old_ttl << 8), htons(iph->ttl << 8));

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
