/*
 * SO2 kprobe based tracer header file
 *
 * this is shared with user space
 */

#ifndef TRACER_H__
#define TRACER_H__ 1

#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */



#define TRACER_DEV_MINOR 42
#define TRACER_DEV_NAME "tracer"

#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)

#define CURRENT_NR_PROBES 6

static int tracer_open(struct inode *inode, struct file *file);

static int tracer_release(struct inode *inode, struct file *file);

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#define proc_name "tracer"

char kmalloc_sym[20] = "__kmalloc";

char kfree_sym[20] = "kfree";

char up_sym[20] = "up";

char down_sym[30] = "down_interruptible";

char sched_sym[20] = "sched";

char mutex_sym[30] = "mutex_lock_nested";


#endif /* TRACER_H_ */
