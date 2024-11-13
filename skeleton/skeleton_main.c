#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/sched.h>	
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include "skeleton.h"
#include "file.h"



//Basic check of files being accessed as a test function
static int skel_check(struct linux_binprm *bprm)
{
    printk(KERN_INFO "SKELETON LSM check of %s\n", bprm->filename);
    return 0;
}

//Testing kernel memory allocation. Using kzalloc
int skel_task_alloc(struct task_struct *task, unsigned long clone_flags) {
    printk(KERN_INFO "allocing for %s\n", task->comm);
    struct skeleton_info *tsec;
    tsec = kzalloc(sizeof(struct skeleton_info), GFP_KERNEL);
    if (!tsec) {
        printk(KERN_INFO "alloc failed");
        return -ENOMEM;
    }
    tsec->skeleton_id = 22;
    tsec->parent_uid = current_uid().val;
    task->security = tsec;
    return 0;
}

void skel_task_free(struct task_struct *task) {
    struct skeleton_info *tsec = task->security;
    if (tsec) {
        printk(KERN_INFO "freeing for %s uid is %i\n", task->comm, tsec->parent_uid);
        kfree(tsec);
        task->security = NULL;
    }	
}

// File label management functions
struct fl_min *create_label_min(const char *appid) { //Create the minlabel
    struct fl_min *minl;
    minl = kzalloc(sizeof(struct fl_min), GFP_KERNEL);
    if (!minl) {
        printk(KERN_ERR "File label alloc failed\n");
        return ERR_PTR(-ENOMEM);
    }
    minl->appid = kstrdup(appid, GFP_KERNEL);
    if (!minl->appid) {
        kfree(minl);
        return ERR_PTR(-ENOMEM);
    }
    atomic_set(&minl->ref_count, 1);
    return minl;
}

void free_min(struct fl_min *label) { //Free the minlabel
    if (label) {
        if (label->appid != NULL) {
            kfree(label->appid);
        }
        kfree(label);
    }
}

void put_min(struct fl_min *label) {
    if (label) {
        //printk("Freeing minlabel for file"
        if (atomic_dec_and_test(&label->ref_count)) {
            free_min(label);
        }
    }
}

// New function to get and increment atromic reference count
struct fl_min *get_min(struct fl_min *label) {
    if (label) {
        atomic_inc(&label->ref_count);
    }
    return label;
}

void free_nest(struct fl_nest *wrapper) { //Outer label cleanup
    if (wrapper) {
        struct fl_min *minl = rcu_dereference(wrapper->min);
        if (minl) {
            put_min(minl);  // This will handle the inner label cleanup
        }
        kfree(wrapper);
    }
}

struct fl_nest *get_fl(struct file *file) { //Get a label if needed
    struct fl_nest *reqfl;
    rcu_read_lock();
    reqfl = rcu_dereference(file->f_security);
    rcu_read_unlock();
    return reqfl;
}

// File security hooks
int skel_file_alloc_security(struct file *file) {
    struct fl_nest *wrapper;
    struct fl_min *minl;
    static const char *appid_placehold = "CAFEBABE";
    wrapper = kzalloc(sizeof(struct fl_nest), GFP_KERNEL);
    if (!wrapper) {
        printk(KERN_ERR "Failed to allocate fl_nest\n");
        return -ENOMEM;
    }
    spin_lock_init(&wrapper->lock);
    
    minl = create_label_min(appid_placehold);
    if (IS_ERR(minl)) {
        kfree(wrapper);
        return PTR_ERR(minl);
    }
    
    rcu_assign_pointer(wrapper->min, minl);
    file->f_security = wrapper;
    
    return 0;
}

void print_filepath(struct file *file, struct fl_min *minl) { //Handle printing filepath
    char *path;
    path = kzalloc(PATH_MAX, GFP_KERNEL);
    if (path) {
        if (!IS_ERR(d_path(&file->f_path, path, PATH_MAX))) {
            printk(KERN_INFO "Freeing security for file %s with appid %s\n",
                   path, minl ? minl->appid : "NULL");
        }
        kfree(path);
    }
}

void skel_file_free_security(struct file *file) { //Free file security field
    struct fl_nest *wrapper = file->f_security;
    if (wrapper) {
        struct fl_min *minl = rcu_dereference(wrapper->min);
        print_filepath(file, minl);
        free_nest(wrapper);
        file->f_security = NULL;
    }
}

// Updated hook list
static struct security_hook_list skeleton_hooks[] = {
    LSM_HOOK_INIT(task_alloc, skel_task_alloc),
    LSM_HOOK_INIT(task_free, skel_task_free),
    LSM_HOOK_INIT(file_alloc_security, skel_file_alloc_security),
    LSM_HOOK_INIT(file_free_security, skel_file_free_security),
};

static int __init sk_init(void)
{
    security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks), "Skeleton");
    printk(KERN_INFO "Skeleton LSM loaded\n");
    return 0;
}

DEFINE_LSM(can_exec_init) = {
    .init = sk_init,
    .name = "skeleton",
};
