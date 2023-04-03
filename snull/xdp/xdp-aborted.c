/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_aborted(struct xdp_md* ctx)
{
    bpf_printk("XDP ABORTED\n");
    return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
