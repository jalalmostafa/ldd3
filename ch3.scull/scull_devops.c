#include <linux/slab.h>

#include "scull.h"

int scull_trim(scull_device_t* dev)
{
    struct scull_qset *next, *dptr;
    int qset = dev->qset, i;

    for (dptr = dev->data; dptr != NULL; dptr = next) {
        if (dptr->data) {
            for (i = 0; i < qset; i++) {
                kfree(dptr->data[i]);
            }
            dptr->next = NULL;
            kfree(dptr->data);
        }
        next = dptr->next;
        kfree(dptr);
    }

    dev->data = NULL;
    dev->qset = 0;
    dev->quantum = scull_quantum;
    dev->size = 0;

    return 0;
}

struct scull_qset* scull_follow(scull_device_t* dev, int n)
{
    struct scull_qset* qs = dev->data;

    /* Allocate first qset explicitly if need be */
    if (!qs) {
        qs = dev->data = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
        if (qs == NULL)
            return NULL; /* Never mind */
        memset(qs, 0, sizeof(struct scull_qset));
    }

    /* Then follow the list */
    while (n--) {
        if (!qs->next) {
            qs->next = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
            if (qs->next == NULL)
                return NULL; /* Never mind */
            memset(qs->next, 0, sizeof(struct scull_qset));
        }
        qs = qs->next;
        continue;
    }
    return qs;
}
