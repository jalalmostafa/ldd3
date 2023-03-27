# SNULL Network Driver

Progress: LDD3 - Chapter 17

This example uses `page_pool` as a packet pool instead of the original `kmalloc`
pool. However, the original `kmalloc` driver is accesible through [`5b568fd`](https://github.com/jalalmostafa/ldd3/tree/5b568fd1a741157bb86ec5bd9de13ca6654abfa8)
