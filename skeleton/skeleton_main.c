#include <linux/lsm_hooks.h>

#include <linux/security.h>
 

static int skel_check (struct linux_binprm *bprm)
{
    printk(KERN_INFO "SKELETON LSM check of\n" );
    return 0;
}


static struct security_hook_list skeleton_hooks[] = {
    LSM_HOOK_INIT(bprm_check_security, skel_check),
};




static int __init sk_init(void)
{
    security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks), "Skeleton");
    printk(KERN_INFO "Skeleton LSM loaded \n");
    return 0;
}


/*
 * Ensure the initialization code is called.
 */
DEFINE_LSM(can_exec_init) = {
        .init = sk_init,
        .name = "skeleton",
};

