/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md* ctx)
{
    bpf_trace_printk("bpf_printk: %d\n", ctx->rx_queue_index);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
