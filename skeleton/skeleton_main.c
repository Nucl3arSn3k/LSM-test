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
#include <linux/init.h>
#include "skeleton.h" //Not sure if this is actually being used,but I suspect not
#include "file.h"
#include "xattrhandle.h"
//Problem of making attributes PERSIST.
//not entirely clear,additional security info on inodes,and HOW does that info get to and from disk?
//Creates a blob so the nested structure plays nice with other security modules
struct lsm_blob_sizes skeleton_blob_sizes __ro_after_init = { //blob sizes set
  .lbs_inode = sizeof(struct fl_nest),
  .lbs_task = sizeof(struct process_attatched),

};


int appid_creator(void){ //Config process IDs. What differing approach should we take
  pid_t pid;
  pid = task_pid_nr(current);
  
  int app_id = pid +100;
  return app_id;
}


//Solving that problem, I'm creating a struct for my xattrs
struct x_value *create_xattr_struct (int app_id){
  struct x_value *xval;
  xval = kzalloc(sizeof(struct x_value),GFP_KERNEL);
  if (!xval){
      printk(KERN_INFO "xattrs alloc failed");
      return ERR_PTR(-ENOMEM);
  }
  xval->appid = app_id;
  xval->perms = SKELETON_RW; //More appropriate base16 teststr
  return xval; //You absolute MORON!!!
}


static int skl_inode_perms(struct inode *inode){ //Need to modify t deal with bits. Find filesystem hook
  struct fl_nest *inode_sec = get_fl(inode);
  struct process_attatched *process_sec = skeleton_task(current); //grabs process security field
  
  if(!inode_sec || !process_sec|| system_state < SYSTEM_RUNNING){
    printk("System not booted"); //Pass the check by default WHILE system boots
    return 0;
  }
  rcu_read_lock();
  struct fl_min *f_label = rcu_dereference(inode_sec->min); //Shouldn't be null
  if (!f_label){
    panic("f_label is null");
    return -1;
  }
  if (process_sec->appid == 0){ //allow the op,doesn't matter what the perm bits are
    rcu_read_unlock();
    return 0;
  }
  
  if (process_sec->appid == f_label->appid){ //Allow read. Need to find hook for filesystem read/write
    rcu_read_unlock();
    return 0;
  }
  
  //Just appID matching
  
  printk(KERN_INFO "Skeleton LSMv11: access denied. Process with appid %d failed to access file with appid %d",process_sec->appid,f_label->appid);
  rcu_read_unlock();
  return -1;
}


char* serialize_xattr(struct x_value *xval) {
    // Allocate memory for the serialized string
    char *buffer = kmalloc(32, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_INFO "serialization buffer allocation failed");
        return ERR_PTR(-ENOMEM);
    }
    
    snprintf(buffer, 32, "%d:%x", xval->appid, xval->perms);
    return buffer;
}

//Basic check of files being accessed as a test function

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

// New function to get and increment atomic reference count
struct fl_min *get_min(struct fl_min *label) {
    if (label) {
        atomic_inc(&label->ref_count);
    }
    return label;
}
 


struct fl_nest *set_fl(struct inode *node){ //Create the holding struct
	if (system_state < SYSTEM_RUNNING) {
	        printk(KERN_INFO "Skeleton LSMv11: Skipping label during early boot\n");
	        return NULL;
    	}
	int app_id = appid_creator(); //Swapped for real appid creation
	struct fl_nest *contained = node->i_security; //fl = file label
	
	
	spin_lock_init(&contained->lock);
	struct fl_min *pandora = create_label_min(app_id);
	if(IS_ERR(pandora)){
		return ERR_PTR(PTR_ERR(pandora));
	}
	spin_lock(&contained->lock);
	rcu_assign_pointer(contained->min,pandora);
	spin_unlock(&contained->lock);
	
	 //= contained; //TODO:Modify for blob utilization

	return contained;
}



void free_nest(struct fl_nest *wrapper) { //Outer label cleanup
    synchronize_rcu();
    if (wrapper) {
        struct fl_min *minl = rcu_dereference(wrapper->min);
        if (minl) {
            put_min(minl);  // This will handle the inner label cleanup
        }
        //kfree(wrapper);
    }
}

struct fl_nest *get_fl(struct inode *node) { //Get a label if needed
    struct fl_nest *reqfl;
    rcu_read_lock();
    reqfl = skeleton_inode(node);//tweaking to safe call
    rcu_read_unlock();
    return reqfl;
}



void skl_inode_free(struct inode *file) { //Free file security field
    struct fl_nest *wrapper = file->i_security;
    if (wrapper) {
	printk(KERN_DEBUG "Skeleton LSMv11: Freeing security for inode %lu\n", file->i_ino); //Tweak v num with everybuild
        
        free_nest(wrapper);
        //file->i_security = NULL;
    }
}
//Allocate the INODE security field
static int skl_alloc_inode(struct inode *node) { //Extended attribute calls to actually put this on disk
    struct fl_nest *nest;
    
    if (!node){
        return -EINVAL;
    }
    nest = set_fl(node);  
    if (IS_ERR(nest)){
        return PTR_ERR(nest);
    }
    return 0;
}


static int skl_alloc_procsec(struct task_struct *task, unsigned long clone_flags){ //Allocate task security struct with appid and perms
  if (!task){
    return -EINVAL;
  }
  struct process_attatched *contained = skeleton_task(task);//Blob style assignment
  //atomic_inc_return(&app_id_increment)
  contained->appid = appid_creator();
  contained->perms = 42;
  


  if (IS_ERR(contained)){
    return PTR_ERR(contained);
  }

  //Now setting clone flags to determine rules for fork
  printk(KERN_INFO "Process %s assigned appID %d\n",task->comm,contained->appid);
  printk(KERN_INFO "Security structure allocated for task %s\n",task->comm); //Should be able to directly grab from comm field
  return 0;

}

static void skl_free_procsec(struct task_struct *task){ //Freeing task security struct. Should be handled by allocated blob
  struct process_attatched *label = task->security;
  printk("Freeing appid security structure");


}



//Let's document!
//qstr is a custom struct for a string that has the hash?
//Xattrs are used in some sort of odd callback that's not the direct implementation,but looks like some type of VFS abstraction over EXT4,NTFS,what have you
//need to figure out what dir does
//explain input and return types.
static int skl_init_security(struct inode *node, struct inode *dir, const struct qstr *qstr,const char **name,void **value,size_t *len){
  *name = "security.skl"; //Name set
  struct task_struct *mytask = current; //use current macro?
  struct process_attatched *locstruct=NULL; //Should probably nullcheck this
  int hard = 0;
  if(mytask){
    locstruct = skeleton_task(mytask);
    hard = locstruct->appid;
    printk(KERN_INFO "Got appid %d from task %s\n",hard,mytask->comm);
  }
  else{
    hard = 22;
    printk(KERN_INFO "Using fallback appid %d from task %s\n",hard,mytask->comm);
  }
  struct x_value *new = create_xattr_struct(hard); //Value set from hard
  char* vals = serialize_xattr(new);
  
  
  if (IS_ERR(new)){
    return PTR_ERR(new);
  }
  int stored_appid = new->appid;
  kfree(new);
  *value = vals; //passed back as void. Implict cast?
  *len = strlen(vals) + 1;
 //Does it expect pointer to data structure and size?
  printk(KERN_INFO "Setting XATTR for task %s on inode %lu, id value %d\n", 
           mytask->comm, node->i_ino, stored_appid);

  return 0;
} 


int skl_inode_permission(struct inode *node, int mask){
	if (!node){
		return 0;
	}
	else{
		return skl_inode_perms(node);
	}
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
    LSM_HOOK_INIT(inode_init_security, skl_init_security),
    LSM_HOOK_INIT(task_alloc,skl_alloc_procsec),
    LSM_HOOK_INIT(task_free,skl_free_procsec),
    LSM_HOOK_INIT(inode_permission, skl_inode_permission),
    //LSM_HOOK_INIT(file_alloc_security, skel_file_alloc_security),
    //LSM_HOOK_INIT(file_free_security, skel_file_free_security),
};

static int __init sk_init(void)
{
    printk(KERN_INFO "Skeleton LSM loaded\n");
    security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks), "Skeleton");
    printk(KERN_INFO "Hooks registered\n");
    return 0;
}

DEFINE_LSM(can_exec_init) = {
    .init = sk_init,
    .name = "skeleton",
    .blobs = &skeleton_blob_sizes,
};
