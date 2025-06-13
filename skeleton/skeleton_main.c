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
  .lbs_inode = sizeof(struct fl_min),
  .lbs_task = sizeof(struct process_attatched),
};


int appid_creator(void){ //Config process IDs. What differing approach should we take
  pid_t pid;
  pid = task_pid_nr(current);
  
  int app_id = 0;
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


static int skl_inode_perms(struct inode *inode){ 
  if(system_state < SYSTEM_RUNNING || current->pid<=1000){ //try noty blocking init processes
    printk("System not booted"); //Pass the check by default WHILE system boots
    return 0;
  }
  
  struct fl_min *inode_sec = skeleton_inode(inode);
  struct process_attatched *proc_sec = skeleton_task(current); //grabs process security field
  //
  if (!proc_sec){
    panic("The process shouldn't be null! %d",current->pid);
  }
  if (current->flags & PF_KTHREAD){ //pthread bit is set
    printk("Not labeling a kthread , nice try.");
    return 0;
  }
  if (!inode_sec){
    panic("The inode security field should never be null if inode is initalized!");
  }
  //struct fl_min *f_label = inode_sec->min; //Shouldn't be null
  if (proc_sec->appid == 0 || proc_sec->appid == 100){ //allow the op,doesn't matter what the perm bits are
    printk(KERN_INFO "Skeleton LSMv13:Process has root appid of %d,allow access",proc_sec->appid);
    return 0;
  }
  
  if (inode_sec->appid == proc_sec->appid){ //Allow read. Need to find hook for filesystem read/write
    printk("Skeleton LSMv13: Read allowed.");
    return 0;
  }
  
  //Just appID matching
  
  printk(KERN_INFO "Skeleton LSMv13: access denied. Process with appid %d failed to access file with appid %d",proc_sec->appid,inode_sec->appid);
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



void skl_inode_free(struct inode *file) { //Free file security field
    struct fl_min *actual = skeleton_inode(file); //Swapping away from nest
    if (actual) {
	printk(KERN_DEBUG "Skeleton LSMv13: Freeing security for inode %lu\n", file->i_ino); //Tweak v num with everybuild
        
        //free_nest(wrapper);
        //file->i_security = NULL;
    }
}


static int skl_alloc_inodesimp(struct inode *inode){ //Simplified inode alloc
  if(!inode){
    return -EINVAL;
  }
  
  struct fl_min *outer = skeleton_inode(inode);
  outer->appid = 0; //testing ids
  outer->perms = 5; //read write executex
  if (IS_ERR(outer)){
    return PTR_ERR(outer);
  }
  
  printk(KERN_INFO "Inode %lu assigned appID %d\n",inode->i_ino,outer->appid);
  printk(KERN_INFO "Security structure allocated for task %lu\n",inode->i_ino);
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
  //struct process_attatched *label = task->security;
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
		return 0; //Permission granted
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
    LSM_HOOK_INIT(inode_alloc_security, skl_alloc_inodesimp),
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
    struct process_attatched *task_0;
    task_0 = skeleton_task(current);
    if (!task_0){
	printk("inital task is null");
    }
    task_0->appid = 0;
    task_0->perms = 22;
    return 0;
}

DEFINE_LSM(sk_init) = {
    .init = sk_init,
    .name = "skeleton",
    .blobs = &skeleton_blob_sizes,
};
