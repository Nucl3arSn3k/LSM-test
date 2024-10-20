#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "skeleton.h"
//Basic check of files being accessed as a test function
static int skel_check (struct linux_binprm *bprm)
{
    printk(KERN_INFO "SKELETON LSM check of %s\n",bprm->filename);
    return 0;
}



//Testing kernel memory allocation. Using kzalloc
int skel_task_alloc(struct task_struct *task,unsigned long clone_flags){
	printk(KERN_INFO "allocing for %s\n",task->comm);
	struct skeleton_info *tsec;
	tsec = kzalloc(sizeof(struct skeleton_info), GFP_KERNEL);
	if (!tsec){
		printk(KERN_INFO "alloc failed");
		return -ENOMEM;
	}

	tsec->skeleton_id = 22;
	task->security = tsec;
	printk(KERN_INFO "alloc functional for task with PID:%d and name:%s\n",task->pid,task->comm);
	return 0;
}


void skel_task_free(struct task_struct *task){
	struct skeleton_info *tsec = task->security;
	if (tsec){
		printk(KERN_INFO "freeing for %s\n",task->comm);
		kfree(tsec);
		task->security = NULL;
	}
	
	
}

static struct security_hook_list skeleton_hooks[] = {
    //LSM_HOOK_INIT(bprm_check_security, skel_task_alloc),
    LSM_HOOK_INIT(task_alloc,skel_task_alloc),
    LSM_HOOK_INIT(task_free,skel_task_free),
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
