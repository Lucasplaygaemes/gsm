#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <crypto/hash.h>     // for the sha256
#include <linux/xattr.h>     // For reading the tags (GSM_PROTECTED)
#include <linux/file.h>      // For manipulating the files structure

#define TARGET_SYSCALL_WRITE __NR_write
#define TARGET_SYSCALL __NR_unlinkat
#define GSM_PASSWORD "luke123"
#define UNLOCK_TIME_SEC 60

static u8 gsm_password_hash[32]; // Saves the hash instead of the pure key
static int gsm_locked = 1;
static int password_set = 0;
static struct timer_list unlock_timer;
static unsigned long *sys_call_table_ptr;


typedef asmlinkage long (*t_sys_unlinkat)(const struct pt_regs *);
typedef asmlinkage long (*t_sys_write)(const struct pt_regs *);

static t_sys_unlinkat original_unlinkat;
static t_sys_write original_write;

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

// Timer logic
void timer_callback(struct timer_list *t) {
    gsm_locked = 1;
    printk(KERN_INFO "GSM: Time finished! Protection reactivated.\n");
}

// Interface /proc
static ssize_t gsm_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[32];
    u8 attempt_hash[32];
    size_t len = count > 31 ? 31 : count;

    if (copy_from_user(buf, ubuf, len)) 
        return -EFAULT;
    
    buf[len] = '\0';
    
    // string formatting (Remove \n, \r or spaces)
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' ')) {
        buf[--len] = '\0';
    }

    // password logic
    if (!password_set) {
        // Defines the password for the firts time
        calculate_sha256(buf, gsm_password_hash);
        password_set = 1;
        printk(KERN_INFO "GSM: Password sucessfuly defined! (Hash SHA-256).\n");
    } else {
        // verifiy the key send
        calculate_sha256(buf, attempt_hash);
        if (memcmp(attempt_hash, gsm_password_hash, 32) == 0) {
            gsm_locked = 0;
            mod_timer(&unlock_timer, jiffies + msecs_to_jiffies(UNLOCK_TIME_SEC * 1000));
            printk(KERN_INFO "GSM: Autenthicated! System unclocked for %d seconds.\n", UNLOCK_TIME_SEC);
        } else {
            printk(KERN_WARNING "GSM: Incorrect Password!\n");
        }
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

// Write file hook ("sys_write") and tag verification
static int is_file_protected(struct file *f) {
    char value[16];
    int ret;
    if (!f || !f->f_path.dentry) return 0;
    // Try to read the atribute user.gsm_protected
    ret = vfs_getxattr(&nop_mnt_idmap, f->f_path.dentry, "user.gsm_protected", value, sizeof(value));
    
    if (ret > 0 && value[0] == '1') return 1;
    return 0;
}


asmlinkage long gsm_write(const struct pt_regs *regs) {
    int fd = (int)regs->di;
    struct file *f = fget(fd);
    int protected = 0;
    
    if (strcmp(current->comm, "tee") == 0 || strcmp(current->comm, "gsm_manager") == 0) {
        return original_write(regs);
    }
    
    if (gsm_locked && f) {
        protected = is_file_protected(f);
        if (protected) {
            fput(f);
            printk(KERN_ALERT "GSM: Writing blocked in a protected file!\n");
            return -EACCES;
        }
        fput(f);
    }
    return original_write(regs);
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
    
    original_write = (t_sys_write)sys_call_table_ptr[TARGET_SYSCALL_WRITE];
    sys_call_table_ptr[TARGET_SYSCALL_WRITE] = (unsigned long)gsm_write;
    
    // Timer config
    original_unlinkat = (t_sys_unlinkat)sys_call_table_ptr[TARGET_SYSCALL];
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)gsm_unlinkat;
    
    protect_memory();
    printk(KERN_INFO "GSM: General Security Manager Started and locked.\n");
    return 0;
}

static void __exit gsm_exit(void) {
    unprotected_memory();
    sys_call_table_ptr[TARGET_SYSCALL] = (unsigned long)original_unlinkat;
    sys_call_table_ptr[TARGET_SYSCALL_WRITE] = (unsigned long)original_write;
    protect_memory();
    del_timer(&unlock_timer);
    remove_proc_entry("gsm_control", NULL);
    printk(KERN_INFO "GSM: General Security Manager Finished.\n");
}

module_init(gsm_init);
module_exit(gsm_exit);
MODULE_LICENSE("GPL");
