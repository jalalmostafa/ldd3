# SNULL Network Driver

Progress: LDD3 - Chapter 17 + XDP Support + AF_XDP Copy Mode

This example uses `page_pool` as a packet pool instead of the original `kmalloc`
pool. 

- The original `kmalloc` driver is accesible through [`5b568fd`](https://github.com/jalalmostafa/ldd3/tree/5b568fd1a741157bb86ec5bd9de13ca6654abfa8).
- No XDP Support version but with `page_pool`: [`f17e70e`](https://github.com/jalalmostafa/ldd3/tree/f17e70e8d4d452e7ed041b67b87ba6066041475d)

## XDP test compilation

`apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) libbpf-dev linux-tools-generic linux-cloud-tools-generic`
