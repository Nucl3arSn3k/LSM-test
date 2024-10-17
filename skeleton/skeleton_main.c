// lsm.c //this version throws RIP: 0010:skeleton_cred_prepare
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "include/skeleton.h"
static int skeleton_bprm_check_security(struct linux_binprm *bprm)
{
    struct skeleton_info *info = current->security;
    if (info)
    {
        printk(KERN_INFO "SKELETON LSM: Process %s (PID: %d) has SKELETON ID %d\n", current->comm, current->pid, info->skeleton_id);
    }
    else
    {
        printk(KERN_ERR "SKELETON LSM: current->security is null, allocating new skeleton_info (PID: %d)\n",current->pid);
#if 0
       info = kzalloc(sizeof(struct skeleton_info), GFP_KERNEL);

        if (!info)
        {
            printk(KERN_ERR "SKELETON LSM: Failed to allocate skeleton_info for current process\n");
            return -ENOMEM;
        }
        info->skeleton_id = SKELETON_INVALID;
        current->security = info;
        printk(KERN_INFO "SKELETON LSM: Allocated new skeleton_info for current process\n");
#endif
    }
    return 0;
}

static int skeleton_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    struct skeleton_info *info = kzalloc(sizeof(struct skeleton_info), gfp);
    if (!info)
    {
        printk(KERN_ERR "SKELETON LSM: Failed to allocate skeleton_info during cred_alloc_blank for process (PID: %d)\n",current->pid);
        return -ENOMEM;
    }
    info->skeleton_id = SKELETON_INVALID;
    cred->security = info;
    printk(KERN_INFO "SKELETON LSM: Allocated skeleton_info during cred_alloc_blank for process (PID: %d)\n",current->pid);
    return 0;
}

static void skeleton_cred_free(struct cred *cred)
{
    struct skeleton_info *info = cred->security;
    if (info)
    {
        printk(KERN_INFO "SKELETON LSM: Freeing skeleton_info during cred_free for process (PID: %d)\n",current->pid);
        kfree(info);
        cred->security = NULL;
    }
    else
    {
        printk(KERN_ERR "SKELETON LSM: cred->security is null during cred_free for process (PID: %d)\n",current->pid);
    }
}

static int skeleton_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp) //When security field null,this called
{
    struct skeleton_info *old_info = old->security;
    struct skeleton_info *new_info = new->security;

    if (!new_info) {
        new_info = kzalloc(sizeof(struct skeleton_info), gfp);
        if (!new_info)
        {
            printk(KERN_ERR "SKELETON LSM: Failed to allocate skeleton_info during cred_prepare (PID: %d)\n",current->pid);
            return -ENOMEM;
        }
        new->security = new_info;
        printk(KERN_INFO "SKELETON LSM: Allocated new skeleton_info during cred_prepare (PID: %d)\n",current->pid);
    }

    if (old_info) {
        new_info->skeleton_id = old_info->skeleton_id;
        printk(KERN_INFO "SKELETON LSM: Copied skeleton_id from old to new during cred_prepare (PID: %d)\n",current->pid);
    } else {
        new_info->skeleton_id = SKELETON_INVALID;
        printk(KERN_ERR "SKELETON LSM: old_info is null during cred_prepare (PID: %d)\n",current->pid);
    }

    return 0;
}
static struct security_hook_list skeleton_hooks[] = {
    LSM_HOOK_INIT(bprm_check_security, skeleton_bprm_check_security),
    LSM_HOOK_INIT(cred_alloc_blank, skeleton_cred_alloc_blank),
    LSM_HOOK_INIT(cred_free, skeleton_cred_free),
    LSM_HOOK_INIT(cred_prepare, skeleton_cred_prepare),
};
static int __init skeleton_init(void)
{
    security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks), "skeleton");
    printk(KERN_INFO "SKELETON LSM loaded\n");
    return 0;
}
DEFINE_LSM(skeleton_lsm) = {
    .init = skeleton_init,
    .name = "skeleton",
};
