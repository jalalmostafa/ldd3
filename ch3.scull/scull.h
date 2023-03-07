#ifndef _SCULL_H
#define _SCULL_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#define SCULL_NAME "scull"
#define SCULL_COUNT 4
#define SCULL_QUANTUM 4000
#define SCULL_QSET 1000
#define SCULL_MAJOR 0
#define SCULL_MINOR 0

#define SCULL_DEBUG KERN_DEBUG "Scull: "
#define SCULL_INFO KERN_DEBUG "Scull: "

struct scull_qset {
    void **data;
    struct scull_qset* next;
};

typedef struct {
    struct cdev cdev;
    struct scull_qset* data;
    int quantum;
    int qset;
    unsigned long size;
    unsigned int access_key;
    struct semaphore sem;
} scull_device_t;

extern int scull_major;
extern int scull_minor;
extern int scull_quantum;

int scull_trim(scull_device_t* dev);
struct scull_qset* scull_follow(scull_device_t* dev, int n);

#endif
