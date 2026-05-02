#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <crypto/hash.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <crypto/hash.h>     // for sha256
#include <linux/xattr.h>     // for reading tags (gsm_protected)
#include <linux/file.h>      // for manipulating file structures
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include "gsm_shared.h"

#define TARGET_SYSCALL_WRITE __NR_write
#define TARGET_SYSCALL __NR_unlinkat
#define TARGET_SYSCALL_EXECVE __NR_execve
#define TARGET_SYSCALL_EXECVEAT __NR_execveat
#define GSM_PASSWORD "luke123"
#define UNLOCK_TIME_SEC 60

static u8 gsm_password_hash[32]; // saves the hash instead of the pure key
static int gsm_locked = 1;
static int password_set = 0;
static struct timer_list unlock_timer;
static unsigned long *sys_call_table_ptr;

typedef struct file *(*t_get_task_exe_file)(struct task_struct *task);
static t_get_task_exe_file p_get_task_exe_file;

typedef asmlinkage long (*t_sys_unlinkat)(const struct pt_regs *);
typedef asmlinkage long (*t_sys_write)(const struct pt_regs *);
typedef asmlinkage long (*t_sys_execve)(const struct pt_regs *);
typedef asmlinkage long (*t_sys_execveat)(const struct pt_regs *);

static t_sys_unlinkat original_unlinkat;
static t_sys_write original_write;
static t_sys_execve original_execve;
static t_sys_execveat original_execveat;

// variables for daemon communication
static int major_number;
static struct class *gsm_class = NULL;
static struct device *gsm_device = NULL;

static gsm_event_t current_event;
static int data_ready = 0;
DECLARE_WAIT_QUEUE_HEAD(wq);

// function to wake up the daemon
void gsm_notify_daemon(const char *path, int action) {
    current_event.pid = current->pid;
    current_event.uid = from_kuid(&init_user_ns, current_uid());
    current_event.action_taken = action;
    get_task_comm(current_event.process_name, current);
    strncpy(current_event.target_path, path, 256);
    
    data_ready = 1;
    wake_up_interruptible(&wq);
}

// function to kill the process (received by the daemon)
void kill_malicious_process(int pid) {
    struct task_struct *task;
    struct pid *pid_struct = find_get_pid(pid);
    if (pid_struct) {
        task = get_pid_task(pid_struct, PIDTYPE_PID);
        if (task) {
            kill_pid(pid_struct, SIGKILL, 1);
            printk(KERN_ALERT "gsm: process %d killed because it was marked as a threat!\n", pid);
            put_task_struct(task);
        } 
        put_pid(pid_struct);
    }
}

// device operations (/dev/gsm) 
static ssize_t dev_read(struct file *filep, char __user *buffer, size_t len, loff_t *offset) {
    if (len < sizeof(gsm_event_t)) return -EINVAL;
    if (wait_event_interruptible(wq, data_ready == 1)) return -ERESTARTSYS;
    if (copy_to_user(buffer, &current_event, sizeof(gsm_event_t)) != 0) return -EFAULT;
    data_ready = 0;
    return sizeof(gsm_event_t);
}

static ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset) {
    int pid_to_kill;
    char kbuf[16];
    if (len > sizeof(kbuf) - 1) return -EINVAL;
    if (copy_from_user(kbuf, buffer, len)) return -EFAULT;
    kbuf[len] = '\0';
    pid_to_kill = simple_strtol(kbuf, NULL, 10);
    if (pid_to_kill > 0) kill_malicious_process(pid_to_kill);
    return len;
}

static struct file_operations fops = {
    .read = dev_read,
    .write = dev_write,
};

static int calculate_sha256(const char *input, u8 *output) {
    struct crypto_shash *alg;
    struct shash_desc *desc;
    int ret;
    alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg)) return PTR_ERR(alg);
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(alg), GFP_KERNEL);
    if (!desc) { crypto_free_shash(alg); return -ENOMEM; }
    desc->tfm = alg;
    ret = crypto_shash_digest(desc, input, strlen(input), output);
    kfree(desc);
    crypto_free_shash(alg);
    return ret;
}

// timer logic
void timer_callback(struct timer_list *t) {
    gsm_locked = 1;
    printk(KERN_INFO "gsm: time finished! protection reactivated.\n");
}

// /proc interface
static ssize_t gsm_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[32];
    u8 attempt_hash[32];
    size_t len = count > 31 ? 31 : count;

    if (copy_from_user(buf, ubuf, len)) 
        return -EFAULT;
    
    buf[len] = '\0';
    
    // string formatting (remove \n, \r or spaces)
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' ')) {
        buf[--len] = '\0';
    }

    // password logic
    if (!password_set) {
        // defines the password for the first time
        calculate_sha256(buf, gsm_password_hash);
        password_set = 1;
        printk(KERN_INFO "gsm: password successfully defined! (sha-256 hash).\n");
    } else {
        // verify the key sent
        calculate_sha256(buf, attempt_hash);
        if (memcmp(attempt_hash, gsm_password_hash, 32) == 0) {
            gsm_locked = 0;
            mod_timer(&unlock_timer, jiffies + msecs_to_jiffies(UNLOCK_TIME_SEC * 1000));
            printk(KERN_INFO "gsm: authenticated! system unlocked for %d seconds.\n", UNLOCK_TIME_SEC);
        } else {
            printk(KERN_WARNING "gsm: incorrect password!\n");
        }
    }
    return count;
}

static const struct proc_ops gsm_proc_fops = {
    .proc_write = gsm_proc_write,
};

// kprobe handlers
static int handle_pre_vfs_open(struct kprobe *p, struct pt_regs *regs) {
    struct path *path = (struct path *)regs->di;
    char buffer[256];
    char *tpath = d_path(path, buffer, 256);
    
    // ignore if the process opening the file is the "gsmc" daemon itself
    if (strcmp(current->comm, "gsmc") == 0) {
        return 0;
    }

    if (!IS_ERR(tpath)) {
         if (strncmp(tpath, "/dev", 4) != 0 && strncmp(tpath, "/proc", 5) != 0) {
             gsm_notify_daemon(tpath, 1); // 1 = monitoring action
         }
    }
    return 0;
}

// kprobe for process execution monitoring (from gsmc.c)
static int handle_pre_do_execve(struct kprobe *p, struct pt_regs *regs) {
    char name[16];
    get_task_comm(name, current);
    
    // check for suspicious processes
    if (strstr(name, "malware") || strstr(name, "hack")) {
        printk(KERN_ALERT "gsm: suspicious process detected: %s (pid: %d)\n", name, current->pid);
        gsm_notify_daemon(name, 0); // 0 = suspicious action
    }
    return 0;
}

static struct kprobe kp_open = {
    .symbol_name = "vfs_open",
    .pre_handler = handle_pre_vfs_open
};

static struct kprobe kp_execve = {
    .symbol_name = "do_execve",
    .pre_handler = handle_pre_do_execve
};

// check if file is marked as malicious or in quarantine
static int is_file_malicious(const char *filename) {
    struct file *f;
    char value[16];
    int ret = 0;

    if (!filename || strlen(filename) == 0) return 0;

    f = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(f)) {
        return 0;
    }

    // check if malicious
    ret = vfs_getxattr(&nop_mnt_idmap, f->f_path.dentry, GSM_MALICIOUS_TAG, value, sizeof(value));
    if (ret > 0 && value[0] == '1') {
        fput(f);
        return 1;
    }

    // check if in quarantine
    ret = vfs_getxattr(&nop_mnt_idmap, f->f_path.dentry, GSM_QUARANTINE_TAG, value, sizeof(value));
    if (ret > 0 && value[0] == '1') {
        fput(f);
        return 1;
    }

    fput(f);
    return 0;
}

asmlinkage long gsm_execve(const struct pt_regs *regs) {
    char __user *filename = (char *)regs->di;
    char buf[256];
    
    if (copy_from_user(buf, filename, sizeof(buf)) == 0) {
        if (is_file_malicious(buf)) {
            printk(KERN_ALERT "gsm [block] execve: %s (threat detected)\n", buf);
            gsm_notify_daemon(buf, 2); 
            return -EACCES;
        }
    }
    return original_execve(regs);
}

asmlinkage long gsm_execveat(const struct pt_regs *regs) {
    char __user *filename = (char *)regs->si; 
    char buf[256];
    
    if (copy_from_user(buf, filename, sizeof(buf)) == 0) {
        if (is_file_malicious(buf)) {
            printk(KERN_ALERT "gsm [block] execveat: %s (threat detected)\n", buf);
            gsm_notify_daemon(buf, 2); 
            return -EACCES;
        }
    }
    return original_execveat(regs);
}

// syscall hook
// check if current process is suspect (based on original executable)
static int is_current_process_suspect(void) {
    struct file *exe_file;
    char value[16];
    int ret = 0;

    if (!p_get_task_exe_file) return 0;

    exe_file = p_get_task_exe_file(current);
    if (exe_file) {
        ret = vfs_getxattr(&nop_mnt_idmap, exe_file->f_path.dentry, GSM_SUSPECT_TAG, value, sizeof(value));
        if (ret > 0 && value[0] == '1') {
            printk(KERN_INFO "gsm debug: process %s (pid %d) is suspect!\n", current->comm, current->pid);
            fput(exe_file);
            return 1;
        }
        fput(exe_file);
    }
    return 0;
}

asmlinkage long gsm_unlinkat(const struct pt_regs *regs) {
    char __user *filename = (char *)regs->si;
    char buf[256];
    
    // if the one deleting is the daemon itself, we allow it (necessary for quarantine)
    if (strcmp(current->comm, "gsmc") == 0) {
        return original_unlinkat(regs);
    }

    if (copy_from_user(buf, filename, sizeof(buf)) == 0) {
        // always block if it's a file marked as malicious
        if (is_file_malicious(buf)) {
            return -EACCES;
        }

        // if it's a suspect process trying to delete something, notify the daemon
        if (is_current_process_suspect()) {
            printk(KERN_WARNING "gsm [suspect action] %s (pid %d) trying to delete %s\n", current->comm, current->pid, buf);
            gsm_notify_daemon(buf, 3); // 3 = suspicious activity
        }

        if (gsm_locked) {
            printk(KERN_ALERT "gsm blocked: %s tried to delete %s!\n", current->comm, buf);
            gsm_notify_daemon(buf, 0); 
            return -EACCES;
        }
    }
    return original_unlinkat(regs);
}

// check if the file or ANY of its parent folders is protected
static int is_file_protected(struct file *f) {
    struct dentry *dentry;
    char value[16];
    int ret;

    if (!f || !f->f_path.dentry) return 0;
    
    // start from the file and go up to the root (/)
    dentry = f->f_path.dentry;
    
    // increment dentry usage to ensure it doesn't vanish during check
    dget(dentry);
    
    while (dentry != NULL) {
        ret = vfs_getxattr(&nop_mnt_idmap, dentry, GSM_TAG, value, sizeof(value));
        if (ret > 0 && value[0] == '1') {
            dput(dentry);
            return 1;
        }
        
        // go up to the parent
        if (IS_ROOT(dentry)) {
            break;
        }
        
        struct dentry *parent = dget_parent(dentry);
        dput(dentry);
        dentry = parent;
    }
    
    if (dentry) dput(dentry);
    return 0;
}

asmlinkage long gsm_write(const struct pt_regs *regs) {
    int fd = (int)regs->di;
    struct file *f = fget(fd);
    
    if (strcmp(current->comm, "tee") == 0 || strcmp(current->comm, "gsm_manager") == 0 || strcmp(current->comm, "gsmc") == 0) {
        if (f) fput(f);
        return original_write(regs);
    }
    
    if (f) {
        // if it's a suspect process trying to write to files, notify
        if (is_current_process_suspect()) {
            char buffer[256];
            char *tpath = d_path(&f->f_path, buffer, 256);
            if (!IS_ERR(tpath)) {
                gsm_notify_daemon(tpath, 3);
            }
        }

        if (gsm_locked && is_file_protected(f)) {
            char buffer[256];
            char *tpath = d_path(&f->f_path, buffer, 256);
            if (!IS_ERR(tpath)) gsm_notify_daemon(tpath, 0);
            
            fput(f);
            printk(KERN_ALERT "gsm: writing blocked in a protected file!\n");
            return -EACCES;
        }
        fput(f);
    }
    return original_write(regs);
}

// memory manipulation (cr0) 
static inline void write_forced_cr0(unsigned long val) {
    asm volatile("mov %0, %%cr0" : : "r" (val) : "memory");
}
static void unprotected_memory(void) { write_forced_cr0(read_cr0() & ~0x00010000); }
static void protect_memory(void) { write_forced_cr0(read_cr0() | 0x00010000); }

static int __init gsm_init(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    typedef unsigned long (*t_lookup)(const char*);
    t_lookup lookup;
    
    register_kprobe(&kp);
    lookup = (t_lookup)kp.addr;
    unregister_kprobe(&kp);

    if (!lookup) return -1;

    sys_call_table_ptr = (unsigned long *)lookup("sys_call_table");
    p_get_task_exe_file = (t_get_task_exe_file)lookup("get_task_exe_file");

    if (!sys_call_table_ptr) 
        return -1;
    
    // start the device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    gsm_class = class_create(CLASS_NAME);
    
    gsm_device = device_create(gsm_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    
    // register kprobes for file operations and process execution
    register_kprobe(&kp_open);
    register_kprobe(&kp_execve);
    
    // create an entry
    proc_create("gsm_control", 0222, NULL, &gsm_proc_fops);
    // timer config
    timer_setup(&unlock_timer, timer_callback, 0);
    
    unprotected_memory();
    
    original_write = (t_sys_write)sys_call_table_ptr[TARGET_SYSCALL_WRITE];
    sys_call_table_ptr[TARGET_SYSCALL_WRITE] = (unsigned long)gsm_write;
    
    original_unlinkat = (t_sys_unlinkat)sys_call_table_ptr[TARGET_SYSCALL];
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)gsm_unlinkat;
    
    original_execve = (t_sys_execve)sys_call_table_ptr[TARGET_SYSCALL_EXECVE];
    sys_call_table_ptr[TARGET_SYSCALL_EXECVE] = (unsigned long)gsm_execve;
    
    original_execveat = (t_sys_execveat)sys_call_table_ptr[TARGET_SYSCALL_EXECVEAT];
    sys_call_table_ptr[TARGET_SYSCALL_EXECVEAT] = (unsigned long)gsm_execveat;
    
    protect_memory();
    printk(KERN_INFO "gsm: general security manager started and locked.\n");
    return 0;
}

static void __exit gsm_exit(void) {
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_execve);
    
    unprotected_memory();
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)original_unlinkat;
    sys_call_table_ptr[TARGET_SYSCALL_WRITE] = (unsigned long)original_write;
    sys_call_table_ptr[TARGET_SYSCALL_EXECVE] = (unsigned long)original_execve;
    sys_call_table_ptr[TARGET_SYSCALL_EXECVEAT] = (unsigned long)original_execveat;
    protect_memory();
    
    del_timer(&unlock_timer);
    remove_proc_entry("gsm_control", NULL);
    
    device_destroy(gsm_class, MKDEV(major_number, 0));
    class_unregister(gsm_class);
    class_destroy(gsm_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    
    printk(KERN_INFO "gsm: general security manager finished.\n");
}

module_init(gsm_init);
module_exit(gsm_exit);
MODULE_LICENSE("GPL");
