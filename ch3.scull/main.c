#include <linux/module.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>

#include "scull.h"
#include "scull_fops.h"

MODULE_LICENSE("GPL");

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .llseek = scull_llseek,
    .read = scull_read,
    .write = scull_write,
    .unlocked_ioctl = scull_ioctl,
    .open = scull_open,
    .release = scull_release
};

static scull_device_t* devices;
int scull_major = SCULL_MAJOR;
int scull_minor = SCULL_MINOR;
int scull_quantum = SCULL_QUANTUM;

static void scull_exit(void)
{
    dev_t dev = MKDEV(scull_major, scull_minor);
    int i;

    if (devices) {
        for (i = 0; i < SCULL_COUNT; i++) {
            cdev_del(&devices[i].cdev);
        }
        kfree(devices);
    }

    unregister_chrdev_region(dev, SCULL_COUNT);
    printk(KERN_INFO "scull removed\n");
}

static int __init scull_init(void)
{
    int result, i;
    dev_t dev;

    if (scull_major) {
        dev = MKDEV(scull_major, scull_minor);
        result = register_chrdev_region(dev, SCULL_COUNT, SCULL_NAME);
    } else {
        result = alloc_chrdev_region(&dev, 0, SCULL_COUNT, SCULL_NAME);
        scull_major = MAJOR(dev);
    }

    if (result < 0) {
        printk(SCULL_DEBUG "Cannot register cdev regions\n");
        return result;
    }

    devices = kmalloc_array(SCULL_COUNT, sizeof(scull_device_t), GFP_KERNEL);
    if (!devices) {
        result = -ENOMEM;
        goto fail;
    }

    for (i = 0; i < SCULL_COUNT; i++) {
        dev_t mdev = MKDEV(scull_major, scull_minor + i);
        cdev_init(&devices[i].cdev, &fops);
        devices[i].cdev.owner = THIS_MODULE;
        result = cdev_add(&devices[i].cdev, mdev, 1);
        if (result < 0) {
            printk(SCULL_DEBUG "Error adding cdev(%d, %d)\n", scull_major, scull_minor + i);
        }
    }

    printk(SCULL_INFO "scull loaded\n");
    return 0;

fail:
    scull_exit();
    return result;
}

module_init(scull_init);
module_exit(scull_exit);
module_param(scull_major, int, S_IRUGO);
module_param(scull_minor, int, S_IRUGO);
