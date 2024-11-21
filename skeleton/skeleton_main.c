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

//Problem of making attributes PERSIST.
//not entirely clear,additional security info on inodes,and HOW does that info get to and from disk?

//Basic check of files being accessed as a test function
static int skel_check(struct linux_binprm *bprm)
{
    printk(KERN_INFO "SKELETON LSM check of %s\n", bprm->filename);
    return 0;
}



struct fl_min *create_label_min (int app_id){
	struct fl_min *minl;
	minl = kzalloc(sizeof(struct fl_min),GFP_KERNEL);
	if (!minl){
		printk(KERN_INFO "alloc failed");
		return ERR_PTR(-ENOMEM);
	}
	minl->appid = app_id;
	atomic_set(&minl->ref_count,1);
	return minl;
}


void free_min(struct fl_min *label){ //Free label
	if (label){
		kfree(label);
	}
}


void put_min(struct fl_min *label) { //decrement and check label,free if 0
    if (label && atomic_dec_and_test(&label->ref_count)) {
        free_min(label);
    }
}

// New function to get and increment atromic reference count
struct fl_min *get_min(struct fl_min *label) {
    if (label) {
        atomic_inc(&label->ref_count);
    }
    return label;
}
 


struct fl_nest *set_fl(struct inode *node){ //Create the holding struct
	int app_id = 0xDEADBEEF;
	struct fl_nest *contained; //fl = file label
	contained = kzalloc(sizeof(struct fl_nest),GFP_KERNEL);
	if(!contained){
		ERR_PTR(-ENOMEM);
	}
	spin_lock_init(&contained->lock);
	struct fl_min *pandora = create_label_min(app_id);
	if(IS_ERR(pandora)){
		kfree(contained);
		return ERR_PTR(PTR_ERR(pandora));
	}
	spin_lock(&contained->lock);
	rcu_assign_pointer(contained->min,pandora);
	spin_unlock(&contained->lock);
	
	node->i_security = contained;

	return contained;
}









void free_nest(struct fl_nest *wrapper) { //Outer label cleanup
    synchronize_rcu();
    if (wrapper) {
        struct fl_min *minl = rcu_dereference(wrapper->min);
        if (minl) {
            put_min(minl);  // This will handle the inner label cleanup
        }
        kfree(wrapper);
    }
}

struct fl_nest *get_fl(struct inode *node) { //Get a label if needed
    struct fl_nest *reqfl;
    rcu_read_lock();
    reqfl = rcu_dereference(node->i_security);
    rcu_read_unlock();
    return reqfl;
}



void skl_inode_free(struct inode *file) { //Free file security field
    struct fl_nest *wrapper = file->i_security;
    if (wrapper) {
	printk(KERN_DEBUG "Skeleton LSM: Freeing security for inode %lu\n", file->i_ino);
        free_nest(wrapper);
        file->i_security = NULL;
    }
}

static int skl_alloc_inode(struct inode *node) { //Extended attribute calls to actually put this on disk
    struct fl_nest *nest;
    
    if (!node)
        return -EINVAL;
        
    nest = set_fl(node);  
    if (IS_ERR(nest))
        return PTR_ERR(nest);
        
    return 0;
}

//File structs are created when?
//best guess is open,pipe and socket
//File descriptor is index into array of struct file pointers,access ctrl info is cached.
//NOT A ON DISK REPRESNTATIVE!!!!
//May not actually be putting attribute on a on disk file,may be applying to PIPES
//file->f_security possibly being called on open
//inode alloc,inode free,and inode init
//persesitent is d_inode in some places (BSD probably)

// Updated hook list
static struct security_hook_list skeleton_hooks[] = {
    LSM_HOOK_INIT(inode_free_security, skl_inode_free),
    LSM_HOOK_INIT(inode_alloc_security, skl_alloc_inode),
    //LSM_HOOK_INIT(file_alloc_security, skel_file_alloc_security),
    //LSM_HOOK_INIT(file_free_security, skel_file_free_security),
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
