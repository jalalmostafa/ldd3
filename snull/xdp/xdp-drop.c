/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md* ctx)
{
    bpf_printk("XDP DROP\n");
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
