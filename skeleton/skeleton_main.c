#include <linux/lsm_hooks.h>

#include <linux/security.h>
 

static int skel_check (struct linux_binprm *bprm)
{
    printk(KERN_INFO "SKELETON LSM check of %s\n", bprm->filename);
    return 0;
}


static struct security_hook_list skeleton_hooks[] = {
    LSM_HOOK_INIT(bprm_check_security, skel_check),
};





static void __init sk_init(void)
{
    security_add_hooks(steve_hooks, ARRAY_SIZE(steve_hooks), "Skeleton");
    printk(KERN_INFO "Skeleton LSM loaded \n");
}



