 #include <linux/lsm_hooks.h>

//log stuff
 static int skeleton_bprm_check_security(struct linux_binprm *bprm)
 {
     printk(KERN_INFO "skeleton LSM check of %s\n", bprm->filename);
     return 0;
 }
//Check exec
 static struct security_hook_list skeleton_hooks[] = {
     LSM_HOOK_INIT(bprm_check_security, skeleton_bprm_check_security),
 };

//Setup
 static void __init skeleton_init(void)
 {
     security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks), "skeleton");
     printk(KERN_INFO "skeleton LSM initialized\n");
 }
