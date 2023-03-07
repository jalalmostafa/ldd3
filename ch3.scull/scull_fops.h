#ifndef _SCULL_FOPS_H
#define _SCULL_FOPS_H

#include <linux/fs.h>

loff_t scull_llseek(struct file*, loff_t, int);
ssize_t scull_read(struct file*, char __user*, size_t, loff_t*);
ssize_t scull_write(struct file*, const char __user*, size_t, loff_t*);
long scull_ioctl(struct file*, unsigned int, unsigned long);
int scull_open(struct inode*, struct file*);
int scull_release(struct inode*, struct file*);

#endif
