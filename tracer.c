#include "tracer.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>


MODULE_DESCRIPTION("Kprobing tracer");
MODULE_AUTHOR("Carol Bontas <carol.bontas@yahoo.com>");
MODULE_LICENSE("GPL v2");


struct tracer_device_data {

	struct miscdevice miscdev;
	atomic_t access;
};

struct stats_list {

    /* chain used to link other stats */
    struct list_head chain;

    pid_t target_pid;
    
    /* params used for memeory monitoring */
    /* sentinel to a list of memory zones of type mm_stats_list */
    struct list_head *mm_head;

    /* total amount of memory allocated */
    int total_mm_alloc;

    /* total amount of memory freed */
    int total_mm_free;

};


struct mm_stats_list {

    /* starting memory address zone */
    unsigned long addr;

    /* size of memory zone */
    int size;

    /* chain used to link to other zones */
    struct list_head subchain;

};

static struct tracer_device_data surveilant;

static LIST_HEAD(global_head);

const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = tracer_open,
    .release = tracer_release,
    .unlocked_ioctl = tracer_ioctl
};

static int add_pid(pid_t p)
{
    struct stats_list *elem = kmalloc(sizeof(struct stats_list), GFP_ATOMIC);

    if(!elem)
    {
        pr_info("Memory allocation failed for PID argument: %d\n", p);
        return -EFAULT;
    }

    /* add pid */
    elem->target_pid = p;

    /* create sentinel for mm stats zones */
    elem->mm_head = kmalloc(sizeof(struct list_head), GFP_ATOMIC);
    elem->mm_head->prev = elem->mm_head;
    elem->mm_head->next = elem->mm_head;

    /* init mm stats */
    elem->total_mm_alloc = 0;
    elem->total_mm_free = 0;

    list_add(&(elem->chain), &global_head);

    return 0;
}

/* function used to add new mm zone to the list contained in a stats_list according to the pid */
static int add_mm_zone(struct stats_list *ple, unsigned long addr, int size)
{

    struct mm_stats_list elem = kmalloc(sizeof(struct mm_stats_list), GFP_ATOMIC);

    if(!elem)
    {
        pr_info("Memory allocation failed for PID %d at addr %d of size %d\n", ple->pid, addr, size);

        return -EFAULT;
    }

    elem->addr = addr;
    elem->size = size;

    list_add(&(elem->subchain), ple->mm_head);

    ple->total_mm_alloc += size;

    return 0;

}

static int remove_mm_zone(struct stats_list *ple, unsigned long addr)
{
    struct list_head *i, *tmp;
    struct mm_stats_list *elem;
    
    list_for_each_safe(i, tmp, ple->mm_head)
    {
        elem = list_entry(i, struct mm_stats_list, subchain);

        if(elem->addr == addr)
        {
            ple->total_mm_free += elem->size;
            list_del(i);
            kfree(elem);
            return 0;
        }
    }

    return -EINVAL;

}

static void remove_pid(pid_t p)
{
    struct list_head *i, *tmp;

    struct stats_list elem;

    list_for_each_safe(i, tmp, &global_head)
    {
        elem = list_entry(i, struct stats_list, chain);

        if(elem->target_pid == p)
        {
            list_del(i);
            destroy_mm_stats_list(elem->mm_head);
            kfree(elem->mm_head);
            kfree(elem);
            return 0;
        }
    }

    return -EINVAL;

}

static void destroy_stats_list()
{
    struct list_head *i, *n;
    struct stats_list *ple;

    list_for_each_safe(i, n, &global_head) {
        ple = list_entry(i, struct stats_list, list);
        list_del(i);
        kfree(ple);
    }
}

static void destroy_mm_stats_list(struct list_head *sentinel)
{
    struct list_head *i, *n;
    struct mm_stats_list *ple;

    list_for_each_safe(i, n, sentinel) {
        ple = list_entry(i, struct mm_stats_list, list);
        list_del(i);
        kfree(ple);
    }

}

static struct kretprobe kmalloc_probe = {
    .handler = kmalloc_post_handler,
    .entry_handler = kmalloc_pre_handler,
    .maxactive = 32
};

static struct kretprobe kfree_probe = {
    .handler = kfree_post_handler,
    .entry_handler = kfree_pre_handler,
    .maxactive = 32
};

static int kmalloc_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    /* skip kernel threads */
    if(!current->mm)
        return 1;

    
    
}

static int tracer_open(struct inode *inode, struct file *file)
{
	struct tracer_device_data *data;

	pr_info("Open called\n");

	if (atomic_cmpxchg(&data->access, 0, 1) != 0)
    {   
        pr_info("Device is already being used\n");
		return -EBUSY;
    }

    
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	pr_info("Close called\n");

	atomic_set(&data->access, 0);

	return 0;
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_info("Ioctl called\n");
    int res;
    switch (cmd)
    {
    case TRACER_ADD_PROCESS:
        pr_info("Adding proccess with PID: %d\n", arg);
        res = add_pid((pid_t) arg);
        break;
    
    case TRACER_REMOVE_PROCESS:
        pr_info("Removing proccess with PID: %d\n", arg);
        res = remove_pid((pid_t) arg);
        break;
    default:
        res = -EINVAL;
        break;
    }

    return res;
}

static int tracer_init(void)
{
    /* init access */
    atomic_set(&(surveilant.access), 0);

    /* init miscdevice struct */
    surveilant.miscdev = {
        .minor = TRACER_DEV_MINOR,
        .name = TRACER_DEV_NAME,
        .fops = &fops;
    };

    /* register miscdevice */
    int err;
    err = misc_register(&(surveilant.miscdev));

    if(err)
    {
        pr_info("Error in registering miscdevice\n");
        add_pid(arg);
        return err;
    }

    pr_info("Surveilant init done\n");
    return 0;

}

static int tracer_exit(void)
{
    misc_deregister(&(surveilant.miscdev));
    pr_info("Miscdevice deregister done\n");

    destroy_list();
    pr_info("Destroy stats_list chain done\n");

    pr_info("Surveilant exit done\n");
}

module_init(tracer_init);
module_exit(tracer_exit);