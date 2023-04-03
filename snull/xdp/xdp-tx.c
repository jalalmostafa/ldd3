/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define OVER(x, d) (x + 1 > (typeof(x))d)
// static __u8 pong_reply[FRAME_SIZE];

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

unsigned short from32to16(unsigned int x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__u32 from64to32(__u64 x)
{
    /* add up 32-bit and 32-bit for 32+c bit */
    x = (x & 0xffffffff) + (x >> 32);
    /* add up carry.. */
    x = (x & 0xffffffff) + (x >> 32);
    return (__u32)x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
unsigned int inet_csum(const unsigned char* buff, int len)
{
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char* end = buff + ((unsigned int)len & ~3);
            unsigned int carry = 0;

            do {
                unsigned int w = *(unsigned int*)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short*)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
        result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}

__sum16 inet_fast_csum(const void* data, unsigned int size)
{
    return (__sum16)~inet_csum(data, size);
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

__u8* construct_pong(struct ethhdr* frame, __u32 len)
{
    char mac[6];
    __u32 ipaddr;
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    int datalen = len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    struct icmphdr* pong = (struct icmphdr*)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    // swap macs
    memcpy(mac, frame->h_dest, sizeof(mac));
    memcpy(frame->h_dest, frame->h_source, sizeof(mac));
    memcpy(frame->h_source, mac, sizeof(mac));

    // build echo reply

    pong->type = ICMP_ECHOREPLY;
    pong->code = 0;
    pong->checksum = 0;
    pong->checksum = inet_fast_csum(packet, 2 + datalen);

    // swap ips
    ipaddr = packet->daddr;
    packet->daddr = packet->saddr;
    packet->saddr = ipaddr;
    packet->check = 0;
    pong->checksum = 0;
    pong->checksum = inet_fast_csum(packet, packet->ihl * 4);

    return (__u8*)frame;
}

SEC("xdp")
int xdp_tx(struct xdp_md* ctx)
{
    struct ethhdr* eth;
    struct iphdr* iph;
    struct icmphdr* icmph;

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    bpf_printk("XDP TX\n");

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    eth = data;
    iph = (data + sizeof(struct ethhdr));
    icmph = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (eth->h_proto != 0x0008) {
        bpf_printk("NOT Ether frame.\n");
        return XDP_PASS;
    }

    if (OVER(iph, data_end)) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    if (iph->protocol != 1) {
        bpf_printk("NOT ICMP Packet - protocol: %d.\n", iph->protocol);
        return XDP_PASS;
    }

    if (OVER(icmph, data_end)) {
        bpf_printk("Invalid packet.\n");
        return XDP_DROP;
    }

    // csum_replace2(&iph->check, htons(old_ttl << 8), htons(iph->ttl << 8));

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
