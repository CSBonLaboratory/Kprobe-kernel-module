
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
#include <linux/kprobes.h>
#include "tracer.h"
MODULE_DESCRIPTION("Kprobing tracer");
MODULE_AUTHOR("Carol Bontas <carol.bontas@yahoo.com>");
MODULE_LICENSE("GPL v2");

/* --------------------------------- MISCDEVICE  --------------------------------------- */

struct tracer_device_data {

	struct miscdevice miscdev;
	atomic_t access;
};

static struct tracer_device_data surveilant;


/* --------------------------------- STATS LISTS --------------------------------------- */
struct stats_list {

    /* chain used to link other stats */
    struct list_head chain;

    pid_t target_pid;
    
    /* sentinel to a list of memory zones of type mm_stats_list */
    struct list_head *mm_head;

    /* total amount of memory allocated */
    int total_mm_alloc;

    /* total amount of memory freed */
    int total_mm_free;

    int kmallocs;

    int kfrees;

    int scheds;

    int ups;

    int downs;

    int locks;

    int unlocks;

};


static LIST_HEAD(global_head);

static int add_pid(pid_t p)
{
    struct stats_list *elem = (struct stats_list*)kmalloc(sizeof(struct stats_list), GFP_ATOMIC);

    if(!elem)
    {
        pr_info("Memory allocation failed for PID argument in add_pid func: %d\n", p);
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
    elem->kmallocs = 0;
    elem->kfrees = 0;
    elem->scheds = 0;
    elem->ups = 0;
    elem->downs = 0;
    elem->locks = 0;
    elem->unlocks = 0;

    list_add(&(elem->chain), &global_head);

    pr_info("Successfully added stats elem for pid in add_pid func: %d\n", p);
    return 0;
}

static struct stats_list* find_pid(pid_t p)
{
    struct list_head *i, *tmp;

    struct stats_list *elem;

    list_for_each_safe(i, tmp, &global_head)
    {
        elem = list_entry(i, struct stats_list, chain);

        if(elem->target_pid == p)
        {
            return elem;
        }
    }

    return NULL;
}

static int remove_mm_zone(struct stats_list *ple, unsigned long addr);

static void destroy_mm_stats_list(struct list_head *mm_head);

static int remove_pid(pid_t p)
{
    struct list_head *i, *tmp;

    struct stats_list *elem;

    list_for_each_safe(i, tmp, &global_head)
    {
        elem = list_entry(i, struct stats_list, chain);

        if(elem->target_pid == p)
        {
            pr_info("Removing pid in remove_pid func: %d\n", p);
            list_del(i);
            destroy_mm_stats_list(elem->mm_head);
            kfree(elem->mm_head);
            kfree(elem);
            return 0;
        }
    }

    pr_info("Cannot remove pid in remove_pid func: %d\n", p);
    return -EINVAL;

}

static void destroy_stats_list(void)
{
    struct list_head *i, *n;
    struct stats_list *ple;

    list_for_each_safe(i, n, &global_head) {
        ple = list_entry(i, struct stats_list, chain);
        destroy_mm_stats_list(ple->mm_head);
        list_del(i);
        kfree(ple);
    }

    pr_info("Successfully destroyed stats_list\n");
}

/* ---------------------------------------- MEMORY STATS LIST ------------------------- */
struct mm_stats_list {

    /* starting memory address zone */
    unsigned long addr;

    /* size of memory zone */
    unsigned long size;

    /* chain used to link to other zones */
    struct list_head subchain;

};

/* function used to add new mm zone to the list contained in a stats_list according to the pid */
static int add_mm_zone(struct stats_list *ple, unsigned long addr, unsigned long size)
{

    struct mm_stats_list *elem = (struct mm_stats_list*)kmalloc(sizeof(struct mm_stats_list), GFP_ATOMIC);

    if(!elem)
    {
        pr_info("Memory allocation failed for PID %d at addr %ld of size %ld in add_mm_zone func\n", ple->target_pid, addr, size);

        return -EFAULT;
    }

    elem->addr = addr;
    elem->size = size;

    list_add(&(elem->subchain), ple->mm_head);

    ple->total_mm_alloc += size;

    pr_info("Successfully added new mm zone for pid %d with address %ld of size %ld in add_mm_zone func\n", ple->target_pid, addr, size);
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
            pr_info("Successfully removed mm zone for pid %d with address %ld of size %ld in remove_mm_zone func\n", ple->target_pid, elem->addr, elem->size);
            ple->total_mm_free += elem->size;
            list_del(i);
            kfree(elem);
            return 0;
        }
    }

    pr_info("Cannot remvoe mm zone for pid %d with address %ld in remove_mm_zone_func\n", ple->target_pid, addr);
    return -EINVAL;

}

static void destroy_mm_stats_list(struct list_head *mm_head)
{
    struct list_head *i, *n;
    struct mm_stats_list *ple;

    list_for_each_safe(i, n, mm_head) {
        ple = list_entry(i, struct mm_stats_list, subchain);
        list_del(i);
        kfree(ple);
    }

    pr_info("Successfully destroyed mm_stats_list\n");
}

/* ------------------------------------- FILE OPERATIONS -------------------- */
const struct file_operations miscfops = {
    .owner = THIS_MODULE,
    .open = tracer_open,
    .release = tracer_release,
    .unlocked_ioctl = tracer_ioctl
};


/* ----------------------------------- KMALLOC HANDLERS -------------------- */
static int kmalloc_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    int size;
    int *data;
    /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get param values which is the size needed for allocation */
    
    size = regs->di;

    /* put param value inside private data probe instance, to be used at return time */
    
    data = (int*)ri->data;
    *data = size;

    return 0;
}

static int kmalloc_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int *size;
    /* get return value which is the address alocated */
    unsigned long ret_addr = regs_return_value(regs);

    /* get current proccess pid */
    pid_t current_pid = current->tgid;

    /* find the stats of the current_pid */
    struct stats_list* elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in kmalloc_post_handler\n", current_pid);
        return -EINVAL;
    }

    elem->kmallocs++;

    /* combine it with size saved in pre handler  and add mm zone*/
    size = (int*)ri->data;

    add_mm_zone(elem, ret_addr, *size);

    return 0;
}

/* --------------------------- KFREE HANDLERS --------------------------------- */
static int kfree_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    pid_t current_pid;
    struct stats_list* elem;
    /* skip kernel threads */
    if(!current->mm)
        return 1;
    
    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
       //pr_info("Cannot find pid %d in kfree_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->kfrees++;

    /* remove mm zone */
    remove_mm_zone(elem, regs->di);

    return 0;


}

static int kfree_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}
/* ------------------------------- SEMAPHORE UP/DOWN HANDLERS --------------------- */
static int up_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    pid_t current_pid;
    struct stats_list* elem;
    /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in up_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->ups++;
    
    return 0;
}

static int up_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

static int down_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    pid_t current_pid;
    struct stats_list* elem;
    /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in up_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->downs++;
    
    return 0;
}

static int down_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

/* --------------------------- SCHEDULE HANDLER -------------------- */

static int sched_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    pid_t current_pid;
    struct stats_list* elem;
    /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in sched_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->scheds++;

    return 0;
}

static int sched_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

/* ------------------------------ MUTEX HANDLER --------------------------- */
static int mutex_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    pid_t current_pid;
    struct stats_list* elem;
     /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in sched_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->locks++;

    return 0;
}

static int mutex_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{   
    pid_t current_pid;
    struct stats_list* elem;
     /* skip kernel threads */
    if(!current->mm)
        return 1;

    /* get current proccess pid */
    current_pid = current->tgid;

    /* find the stats of the current_pid */
    elem = find_pid(current_pid);

    if(elem == NULL)
    {
        //pr_info("Cannot find pid %d in sched_pre_handler\n", current_pid);
        return -EINVAL;
    }

    elem->unlocks++;

    return 0;
}


/* -------------------------- DEFINE KRETPROBES -------------------- */
static struct kretprobe kmalloc_probe = {
    .handler = kmalloc_post_handler,
    .entry_handler = kmalloc_pre_handler,
    .data_size = sizeof(unsigned long), 
    .maxactive = 32
};

static struct kretprobe kfree_probe = {
    .handler = kfree_post_handler,
    .entry_handler = kfree_pre_handler,
    .maxactive = 32
};

static struct kretprobe up_probe = {
    .handler = up_post_handler,
    .entry_handler = up_pre_handler,
    .maxactive = 32
};

static struct kretprobe down_probe = {
    .handler = down_post_handler,
    .entry_handler = down_pre_handler,
    .maxactive = 32
};

static struct kretprobe sched_probe = {
    .handler = sched_post_handler,
    .entry_handler = sched_pre_handler,
    .maxactive = 32
};

static struct kretprobe mutex_probe = {
    .handler = mutex_post_handler,
    .entry_handler = mutex_pre_handler,
    .maxactive = 32
};

static struct kretprobe* all_probes[CURRENT_NR_PROBES] = {
    &kmalloc_probe,
    &kfree_probe,
    &up_probe,
    &down_probe,
    &sched_probe,
    &mutex_probe
};

static char* all_sym_names[CURRENT_NR_PROBES] = {
    kmalloc_sym,
    kfree_sym,
    up_sym,
    down_sym,
    sched_sym,
    mutex_sym
};

static int init_register_probes(void)
{   
    int i;
    int ret;
    for(i = 0; i < CURRENT_NR_PROBES; i++)
    {
        ret = register_kretprobe(all_probes[i]);

        if(ret < 0)
        {
            pr_info("Error in registering probe for function %s\n", all_sym_names[i]);

            return 1;
        }
    }

    return 0;
}

/* --------------------- FOPS FUNCTIONS FOR /dev/tracer --------------- */
static int tracer_open(struct inode *inode, struct file *file)
{

	pr_info("Open called\n");

	if (atomic_cmpxchg(&(surveilant.access), 0, 1) != 0)
    {   
        pr_info("Device is already being used\n");
		return -EBUSY;
    }

    
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	pr_info("Close called\n");

	atomic_set(&(surveilant.access), 0);

	return 0;
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int res;
    pr_info("Ioctl called\n");
    
    switch (cmd)
    {
    case TRACER_ADD_PROCESS:
        pr_info("Adding proccess with PID: %ld\n", arg);
        res = add_pid((pid_t) arg);
        break;
    
    case TRACER_REMOVE_PROCESS:
        pr_info("Removing proccess with PID: %ld\n", arg);
        res = remove_pid((pid_t) arg);
        break;
    default:
        res = -EINVAL;
        break;
    }

    return res;
}

struct proc_dir_entry *proc;

static int show_stats(struct seq_file *m, void *v)
{
    struct list_head *i;
    struct stats_list *elem;

    list_for_each(i,&global_head)
    {
        elem = list_entry(i, struct stats_list, chain);

        seq_printf(m,
        "%d %d %d %d %d %d %d %d %d %d\n",
        elem->target_pid,
        elem->kmallocs,
        elem->kfrees,
        elem->total_mm_alloc,
        elem->total_mm_free,
        elem->scheds,
        elem->ups,
        elem->downs,
        elem->locks,
        elem->unlocks
        );
    }

    return 0;
}

static int monitor_open(struct inode *inode, struct  file *file)
{
    return single_open(file, show_stats, NULL);
}

struct proc_ops proc_fops = {
    .proc_open = monitor_open,
    .proc_read = seq_read,
    .proc_release = single_release,
};

static int tracer_init(void)
{   
    int err;

    struct miscdevice misc_aux = {
        .minor = TRACER_DEV_MINOR,
        .name = TRACER_DEV_NAME,
        .fops = &miscfops,
    };

    /* init access */
    atomic_set(&(surveilant.access), 0);

    /* init miscdevice struct */
    surveilant.miscdev = misc_aux;

    /* register miscdevice */
    
    err = misc_register(&(surveilant.miscdev));

    if(err)
    {
        pr_info("Error in registering miscdevice\n");
        return err;
    }

    pr_info("Sucessfully registered miscdevice\n");

    proc = proc_create(proc_name, 0000, NULL, &proc_fops);

    if(proc == NULL)
    {
        pr_info("Error in creating process\n");

        return -ENOMEM;
    }

    pr_info("Successfully created tracer process\n");


    err = init_register_probes();

    if(err != 0)
    {
        return err;
    }

    pr_info("Successfully registered all probes\n");

    pr_info("Surveilant init done\n");
    
    return 0;

}

static void tracer_exit(void)
{
    misc_deregister(&(surveilant.miscdev));
    pr_info("Miscdevice deregister done\n");

    destroy_stats_list();
    pr_info("Destroy stats_list chain done\n");

    pr_info("Surveilant exit done\n");


}

module_init(tracer_init);
module_exit(tracer_exit);