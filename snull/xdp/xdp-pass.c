/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md* ctx)
{
    bpf_printk("XDP PASS\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
