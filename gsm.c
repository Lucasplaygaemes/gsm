#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define TARGET_SYSCALL __NR_unlinkat
#define GSM_PASSWORD "luke123"
#define UNLOCK_TIME_SEC 60

static int gsm_locked = 1;
static struct timer_list unlock_timer;
static unsigned long *sys_call_table_ptr;
typedef asmlinkage long (*t_sys_unlinkat)(const struct pt_regs *);
static t_sys_unlinkat original_unlinkat;

// Timer logic
void timer_callback(struct timer_list *t) {
    gsm_locked = 1;
    printk(KERN_INFO "GSM: Time finished! Protection reactivated.\n");
}

// Interface /proc

static ssize_t gsm_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[32];
    size_t len = count > 31 ? 31 : count;

    if (copy_from_user(buf, ubuf, len)) return -EFAULT;
    buf[len] = '\0';
    
    // Cleaning: Remove \n ou \r at the end of the string
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' ')) {
        buf[--len] = '\0';
    }

    if (strcmp(buf, GSM_PASSWORD) == 0) {
        gsm_locked = 0;
        mod_timer(&unlock_timer, jiffies + msecs_to_jiffies(UNLOCK_TIME_SEC * 1000));
        printk(KERN_INFO "GSM: Password Correct! System unlocked.\n");
    }
    return count;
}

static const struct proc_ops gsm_proc_fops = {
    .proc_write = gsm_proc_write,
};

// Hook of the Syscall
asmlinkage long gsm_unlinkat(const struct pt_regs *regs) {
    char __user *filename = (char *)regs->si;
    char buf[256];
    if (gsm_locked && copy_from_user(buf, filename, sizeof(buf)) == 0) {
        if (strstr(buf, "luke") || strstr(buf, "/etc/")) {
            printk(KERN_ALERT "GSM BLOCKED: %s tried to delete %s!\n", current->comm, buf);
            return -EACCES;
        }
    }
    return original_unlinkat(regs);
}

// Memory Manipulation (CR0) 
static inline void write_forced_cr0(unsigned long val) {
    asm volatile("mov %0, %%cr0" : : "r" (val) : "memory");
}
static void unprotected_memory(void) { write_forced_cr0(read_cr0() & ~0x00010000); }
static void protect_memory(void) { write_forced_cr0(read_cr0() | 0x00010000); }

// initializing via Kprobes
static unsigned long get_syscall_table(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    typedef unsigned long (*t_lookup)(const char*);
    t_lookup lookup;
    register_kprobe(&kp);
    lookup = (t_lookup)kp.addr;
    unregister_kprobe(&kp);
    return lookup("sys_call_table");
}

static int __init gsm_init(void) {
    sys_call_table_ptr = (unsigned long *)get_syscall_table();
    if (!sys_call_table_ptr) return -1;
    // create a entry
    proc_create("gsm_control", 0222, NULL, &gsm_proc_fops);
    
    // Timer config
    timer_setup(&unlock_timer, timer_callback, 0);
    unprotected_memory();
    original_unlinkat = (t_sys_unlinkat)sys_call_table_ptr[TARGET_SYSCALL];
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)gsm_unlinkat;
    protect_memory();
    printk(KERN_INFO "GSM: General Security Manager Started and locked.\n");
    return 0;
}


static void __exit gsm_exit(void) {
    unprotected_memory();
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)original_unlinkat;
    protect_memory();
    del_timer(&unlock_timer);
    remove_proc_entry("gsm_control", NULL);
    printk(KERN_INFO "GSM: General Security Manager Finished.\n");
}

module_init(gsm_init);
module_exit(gsm_exit);
MODULE_LICENSE("GPL");
