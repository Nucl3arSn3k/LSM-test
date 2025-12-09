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
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/xattr.h>
#include "skeleton.h" //Not sure if this is actually being used,but I suspect not
#include "file.h"
#include "xattrhandle.h"


#define XATTR_SKELETON_SUFFIX "skeleton"
#define XATTR_NAME_SKELETON XATTR_SECURITY_PREFIX XATTR_SKELETON_SUFFIX
//Problem of making attributes PERSIST.
//not entirely clear,additional security info on inodes,and HOW does that info get to and from disk?
//Creates a blob so the nested structure plays nice with other security modules
struct lsm_blob_sizes skeleton_blob_sizes __ro_after_init = {
	//blob sizes set
	.lbs_inode = sizeof(struct fl_min),
	.lbs_task = sizeof(struct process_attatched),
};

int appid_creator(void)
{ //Config process IDs. What differing approach should we take
	pid_t pid;
	pid = task_pid_nr(current);

	int app_id = 0;
	return app_id;
}







static int skl_set_proc(const char *name, void *value, size_t size)
{
	printk("SKELETONv13:setting proc. Name is %s\n",
	       name); //Hook called about 3 times on kernel boot, yet no proc file
	if (strcmp(name, "current") == 0) {
		//parse appid
		int newval;
		int v = kstrtoint((char *)value, 10, &newval);
		if (v) {
			return -1;
		}
		struct process_attatched *proc_sec = skeleton_task(current);
		if (!proc_sec){
      		return -EINVAL;
    	}
			
		proc_sec->appid = newval;
		printk(KERN_INFO "Process %s with PID %d appid changed to %d\n",current->comm,current->pid, newval);
		return size;

	} else {
		return -EOPNOTSUPP;
	}
}

static int skl_get_proc(struct task_struct *p, const char *name, char **value)
{
	printk("SKELETONv13:getting proc. Name is %s\n", name);
	if (strcmp(name, "current") == 0) {
		struct process_attatched *proc_sec = skeleton_task(p);
		if (!proc_sec){
      		return -EINVAL;
    	}
			
		char *buffer = kmalloc(16, GFP_KERNEL);
		if (!buffer){
      		return -ENOMEM;
    	}
			

		int r = sprintf(buffer, "%d\n", proc_sec->appid);
		*value = buffer;

		return r;
	} else {
		return -EOPNOTSUPP;
	}
}

//Solving that problem, I'm creating a struct for my xattrs
struct x_value *create_xattr_struct(int app_id,int group_id)
{
	struct x_value *xval;
	xval = kzalloc(sizeof(struct x_value), GFP_KERNEL);
	if (!xval) {
		printk(KERN_INFO "xattrs alloc failed");
		return ERR_PTR(-ENOMEM);
	}
	xval->appid = app_id; //ownered id
	xval->groupid = group_id;
	xval->read_perm = SKELETON_READ; //owner bits
	xval->write_perm= 0;
	xval->exec_perm= 0;//More appropriate base16 teststr
	xval->g_readperm=0;
	xval->g_writeperm=0;
    xval->g_execperm=0;
	xval->o_readperm = SKELETON_READ; //read allowed on ownership bits and on other bits
	xval->o_writeperm = 0;
	xval->o_execperm = 0;
	return xval; //You absolute MORON!!!
}


static int skl_inode_setxattr(struct mnt_idmap *idmap,struct dentry *dentry,const char *name,const void *value,size_t size, int flags) {
	struct inode *inode = d_backing_inode(dentry);
    struct fl_min *inode_sec = skeleton_inode(inode);
    struct process_attatched *proc_sec = skeleton_task(current);
	if (proc_sec->appid == 0 || proc_sec->appid == 100) {
        printk(KERN_INFO "Skeleton LSMv13: Root process setting xattr %s\n", name);
        return 0;
    } else if(strcmp(name, XATTR_NAME_SKELETON) == 0){
		if(proc_sec->appid == inode_sec->appid){
			printk(KERN_INFO "Changing perms allowed for proc %s on non-root id\n",current->comm);
			return 0;
		} else{
            printk(KERN_WARNING "Skeleton LSMv13: Denying %s (appid %d) from setting security.skl on file owned by appid %d\n",current->comm, proc_sec->appid, inode_sec->appid);
            return -EACCES;
        }
	} else {
		printk(KERN_WARNING "Skeleton LSMv13: String comparison for xattrs failed");
		return -EACCES;
	}
	return 1;
}

/* 
This function is called post-xattr set. Function will change in-memory representation of inode in accordance with on-disk xattrs.
*dentry which is a single entry in a directory?
params are *name which is the xattr name
*value which is the xattr value
size which is the size of the xattr string
flags which is an access flag?

*/
void skl_inode_post_setxattr(struct dentry *dentry, const char *name,const void *value, size_t size, int flags) { //TODO: modify prints to make sure this hook is firing,since I know the previous hook is. Also check logic
	struct inode *inode = d_backing_inode(dentry);
    struct fl_min *inode_sec = skeleton_inode(inode);
	if (!inode || !inode_sec) {
        printk(KERN_WARNING "Skeleton LSM: Invalid inode or security context\n");
        return;
    } else if (strcmp(name, XATTR_NAME_SKELETON) != 0){
		printk(KERN_WARNING "Skeleton LSM: xattr string comparison failed\n");
		return;
	} else {
	    if (!value) {
	        printk(KERN_WARNING "Skeleton LSM: NULL xattr value\n");
	        return;
	    }
    	const char *xattrstring = value;
		if (size >= 65) {
		    printk(KERN_WARNING "Skeleton LSM: xattr value too large\n");
		    return;
		}
		char temp_buf[65];
	    memcpy(temp_buf, value, size);
	    temp_buf[size] = '\0';
		//int first_int = 0;
		int xattr_buf[11];
		int count = sscanf(temp_buf, "%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d",&xattr_buf[0], &xattr_buf[1], &xattr_buf[2], &xattr_buf[3], &xattr_buf[4], &xattr_buf[5],&xattr_buf[6], &xattr_buf[7], &xattr_buf[8],&xattr_buf[9], &xattr_buf[10]);
		if (count == 11) {
		    inode_sec->appid = xattr_buf[0];
		    inode_sec->groupid = xattr_buf[1];         //gid
		    inode_sec->read_perm = xattr_buf[2];       
		    inode_sec->write_perm = xattr_buf[3];     
		    inode_sec->exec_perm = xattr_buf[4];       
		    inode_sec->g_readperm = xattr_buf[5];      
		    inode_sec->g_writeperm = xattr_buf[6];     
		    inode_sec->g_execperm = xattr_buf[7];      
		    inode_sec->o_readperm = xattr_buf[8];      
		    inode_sec->o_writeperm = xattr_buf[9];     
		    inode_sec->o_execperm = xattr_buf[10];    
	    	printk("Skeleton LSM: Swapping inode ID to %d:%d (inode %lu, ptr %p) due to xattr change\n",xattr_buf[0], xattr_buf[1], inode->i_ino, inode);
		} else {
    		printk(KERN_WARNING "Skeleton LSM: Failed to parse xattr values (got %d fields, expected 11)\n", count);
    		return;
		}
	}
	
}

/* 
Checks the security fields on the inode
inode passes in the inode in question
mask is the bitmask specifying file operations

*/
static int skl_inode_perms(struct inode *inode, int mask)
{
	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode)) {
    	return 0;  // Not a regular file or a directory, allow by default
	}
	
	else{
    	if (system_state < SYSTEM_RUNNING || current->pid <= 0 ||(current->pid > 0 && current->pid < 1000)) { //try noty blocking init processes
			//printk("System not booted"); //Pass the check by default WHILE system boots
			return 0; //Check passes! Replace with a static constant
		}
		struct fl_min *inode_sec = skeleton_inode(inode); //Carries security fields now
		struct process_attatched *proc_sec = skeleton_task(current); //grabs process security field
		//
		if (!proc_sec) {
			panic("The process shouldn't be null! %d", current->pid);
		}
		if (current->flags & PF_KTHREAD) { //pthread bit is set
			printk("Not labeling a kthread , nice try.");
			return 0;
		}
		if (!inode_sec) {
			panic("The inode security field should never be null if inode is initalized!");
		}
		//struct fl_min *f_label = inode_sec->min; //Shouldn't be null
		if (proc_sec->appid == 0 ||proc_sec->appid == 100) { //allow the op,doesn't matter what the perm bits are
			printk(KERN_INFO "Skeleton LSMv13:Process has root appid of %d and inode appid %d along with inode number %lu, pid %d, allow access\n",
	      proc_sec->appid, inode_sec->appid, inode->i_ino, current->pid);
			return 0;
		}
		if (inode_sec->appid == proc_sec->appid) {  //Check inode numbers properly.
			printk("Skeleton LSMv13: appid/inode nonroot match, inode %lu, pid %d\n", inode->i_ino, current->pid);
			if (mask & MAY_READ) {
			    if (inode_sec->read_perm != SKELETON_READ) {
			        printk("Owner Permission bit checking: read on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Owner Permission bit checking: read on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}

			if (mask & MAY_WRITE) {
			    if (inode_sec->write_perm != SKELETON_WRITE) {
			        printk("Owner Permission bits checking: write on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Owner Permission bits checking: write on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}

			if (mask & MAY_EXEC) {
			    if (inode_sec->exec_perm != SKELETON_EXECUTE) {
			        printk("Owner Permission bits checking: exec on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Owner Permission bits checking: exec on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}
			return 0;
		}

		if  (inode_sec->groupid != 0 && inode_sec->groupid == proc_sec->groupid){
			if (mask & MAY_READ) {
			    if (inode_sec->g_readperm != SKELETON_READ) {
			        printk("Group Permission bit checking: read on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Group Permission bit checking: read on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}
			if (mask & MAY_WRITE) {
			    if (inode_sec->g_writeperm != SKELETON_WRITE) {
			        printk("Group Permission bits checking: write on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Group Permission bits checking: write on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}
			if (mask & MAY_EXEC) {
			    if (inode_sec->g_execperm != SKELETON_EXECUTE) {
			        printk("Group Permission bits checking: exec on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Group Permission bits checking: exec on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}
			printk("Permission bit checking: access on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			return 0;

			
		}

		if (proc_sec->appid != 0 && proc_sec->appid != 100) { //check extended attributes (other)
			// Check if requested operation matches allowed "other" permissions
			if (mask & MAY_READ) {
			    if (inode_sec->o_readperm != SKELETON_READ) {
			        printk("Other Permission bit checking: read on inode %lu, pid %d denied\n", inode->i_ino, current->pid);
			        return -EACCES;
			    } 
				else { 
			        printk("Other Permission bit checking: read on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			    }
			}
			if (mask & MAY_WRITE) {
			    if (inode_sec->o_writeperm != SKELETON_WRITE) {
			        printk("Other Permission bits checking: write on inode %lu, pid %d and name %s denied\n", inode->i_ino, current->pid, current->comm);
			        return -EACCES;
			    } 
				else { 
			        printk("Other Permission bits checking: write on inode %lu, pid %d and name %s allowed\n", inode->i_ino, current->pid, current->comm);
			    }
			}
			if (mask & MAY_EXEC) {
			    if (inode_sec->o_execperm != SKELETON_EXECUTE) {
			        printk("Other Permission bits checking: exec on inode %lu, pid %d and name %s denied\n", inode->i_ino, current->pid, current->comm);
			        return -EACCES;
			    } 
				else { 
			        printk("Other Permission bits checking: exec on inode %lu, pid %d and name %s allowed\n", inode->i_ino, current->pid, current->comm);
			    }
			}
			printk("Permission bit checking: access on inode %lu, pid %d allowed\n", inode->i_ino, current->pid);
			return 0;
		}
		printk(KERN_INFO "Skeleton LSMv13: access denied. Process with appid %d, pid %d failed to access file with appid %d, inode %lu, ptr %p\n", proc_sec->appid, current->pid, inode_sec->appid, inode->i_ino, inode);
		return -EACCES;
	}
}
char *serialize_xattr(struct x_value *xval)
{
	char *buffer = kmalloc(64, GFP_KERNEL);
	if (!buffer) {
		printk(KERN_INFO "serialization buffer allocation failed");
		return ERR_PTR(-ENOMEM);
	}
	snprintf(buffer, 64, "%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", xval->appid, xval->groupid, xval->read_perm, xval->write_perm, xval->exec_perm, xval->g_readperm, xval->g_writeperm, 
	         xval->g_execperm, xval->o_readperm, xval->o_writeperm, xval->o_execperm);
	return buffer;
}
//Basic check of files being accessed as a test function

static void skl_inode_free(struct inode *file)
{ //Free file security field
	struct fl_min *actual = skeleton_inode(file); //Swapping away from nest
	if (actual) {
		printk(KERN_DEBUG"Skeleton LSMv13: Freeing security for inode %lu\n",file->i_ino); //Tweak v num with everybuild
		//free_nest(wrapper);
		//file->i_security = NULL;
	}
}

static int skl_alloc_inodesimp(struct inode *inode)
{ //Simplified inode alloc
	if (!inode) {
		return -EINVAL;
	}

	struct fl_min *outer = skeleton_inode(inode);
	outer->read_perm = 0;
  	outer->write_perm = 0;
  	outer->exec_perm = 0;
  	outer->o_readperm = SKELETON_READ; //setting readperm for other on allocation
  	outer->o_writeperm = 0;
  	outer->o_execperm = 0;
	outer->g_readperm = 0;
	outer->g_writeperm = 0;
	outer->g_execperm = 0;
	if (IS_ERR(outer)) {
		return PTR_ERR(outer);
	}

	printk(KERN_INFO "Inode %lu assigned appID %d\n", inode->i_ino,outer->appid);
	printk(KERN_INFO "Security structure allocated for task %lu\n",inode->i_ino);
	return 0;
}

static int skl_alloc_procsec(struct task_struct *task, unsigned long clone_flags)
{ //Allocate task security struct with appid and perms
	if (!task) {
		return -EINVAL;
	}
	struct process_attatched *current_proc = skeleton_task(current);
	struct process_attatched *contained = skeleton_task(task); //Blob style assignment
	//atomic_inc_return(&app_id_increment)
	//contained->appid = appid_creator();
	contained->perms = 42;
	
	contained->appid = current_proc->appid;
	contained->groupid = current_proc->groupid;
	if (IS_ERR(contained)) {
		return PTR_ERR(contained);
	}

	//Now setting clone flags to determine rules for fork
	printk(KERN_INFO "Process %s assigned appID %d\n", task->comm,contained->appid);
	printk(KERN_INFO "Security structure allocated for task %s\n", task->comm); //Should be able to directly grab from comm field
	return 0;
}

static void skl_free_procsec(struct task_struct *task)
{ //Freeing task security struct. Should be handled by allocated blob
	//struct process_attatched *label = task->security;
	printk("Freeing appid security structure");
}

//Let's document!
//qstr is a custom struct for a string that has the hash?
//Xattrs are used in some sort of odd callback that's not the direct implementation,but looks like some type of VFS abstraction over EXT4,NTFS,what have you
//need to figure out what dir does
//explain input and return types.
static int skl_init_security(struct inode *node, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len)
{
	*name = XATTR_SKELETON_SUFFIX; //Name set
	struct task_struct *mytask = current; //use current macro?
	struct process_attatched *locstruct = NULL; //Should probably nullcheck this
	int hard = 12; //placeholder ints for appid and groupid
	int soft = 42;
	if (mytask) {
		locstruct = skeleton_task(mytask);
		hard = locstruct->appid;
		soft = locstruct->groupid;
		printk(KERN_INFO "Got appid %d from task %s\n", hard,mytask->comm);
	} else {
		hard = 22;
		soft = 42;
		printk(KERN_INFO "Using fallback appid %d and groupid %d from task %s\n",hard,soft,mytask->comm);
	}
	struct x_value *new = create_xattr_struct(hard,soft); //Value set from hard
	char *vals = serialize_xattr(new);

	if (IS_ERR(new)) {
		return PTR_ERR(new);
	}
	int stored_appid = new->appid;
	kfree(new);
	*value = vals; //passed back as void. Implict cast?
	*len = strlen(vals) + 1;
	//Does it expect pointer to data structure and size?
	printk(KERN_INFO "Setting XATTR for task %s on inode %lu, id value %d\n", mytask->comm, node->i_ino, stored_appid);

	return 0;
}

/* 
Checks permission before accessing a inode.

struct inode *node is a pointer to the inode in question
int mask is a access mask

This wraps the skl_inode_perms function which contains the logic


*/

static int skl_inode_permission(struct inode *node, int mask)
{
	if (!node) {
		return 0; //Permission granted
	} else {
		return skl_inode_perms(node, mask);
	}
}

static int skl_path_chmod(const struct path *path, umode_t mode){ //Outline for chmod checks
	struct dentry *local = path->dentry;
	struct inode *filenode = d_backing_inode(local);
	struct fl_min *inode_sec = skeleton_inode(filenode);
	//if process id == inode id, you can change perms, if not not. Just a BASIC check to start
	struct process_attatched *current_proc = skeleton_task(current);
	//int hard = locstruct->appid;
	//int soft = locstruct->groupid;
	if (!filenode || !inode_sec || !current_proc) {
    	return -EINVAL;
	}
	if (current_proc->appid != 0 && current_proc->appid != 100){
	    if (current_proc->appid == inode_sec->appid){
			printk(KERN_INFO "chmod allowed for nonroot from process %d on %s\n",current->pid, local->d_name.name);
	        return 0;  
	    }
		printk(KERN_INFO "chmod operation from process %d on %s denied",current->pid, local->d_name.name);
    	return -EPERM;  
	}
	printk(KERN_INFO "chmod operation from process %d on %s allowed for root",current->pid, local->d_name.name);
	return 0;
}

//takes owner and group ids plus path. Unsure how to enforce on that

static int skl_path_chown(const struct path *path, kuid_t uid, kgid_t gid){
	struct dentry *local = path->dentry;
	struct inode *filenode = d_backing_inode(local);
	struct fl_min *inode_sec = skeleton_inode(filenode);
	struct process_attatched *current_proc = skeleton_task(current);
	if (!filenode || !inode_sec || !current_proc) {
    	return -EINVAL;
	}
	if (current_proc->appid != 0 && current_proc->appid != 100){
	    if (current_proc->appid == inode_sec->appid){
			printk(KERN_INFO "chown allowed for nonroot from process %d on %s\n",current->pid, local->d_name.name);
	        return 0;  
	    }
		printk(KERN_INFO "chown operation from process %d on %s denied",current->pid, local->d_name.name);
    	return -EPERM;  
	}
	printk(KERN_INFO "chown operation from process %d on %s allowed for root",current->pid, local->d_name.name);
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
	LSM_HOOK_INIT(inode_alloc_security, skl_alloc_inodesimp),
	LSM_HOOK_INIT(inode_init_security, skl_init_security),
	LSM_HOOK_INIT(task_alloc, skl_alloc_procsec),
	LSM_HOOK_INIT(task_free, skl_free_procsec),
	LSM_HOOK_INIT(inode_permission, skl_inode_permission),
	LSM_HOOK_INIT(getprocattr, skl_get_proc), //??????
	LSM_HOOK_INIT(setprocattr, skl_set_proc),
	LSM_HOOK_INIT(inode_setxattr, skl_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr,skl_inode_post_setxattr),
	LSM_HOOK_INIT(path_chmod,skl_path_chmod),
	LSM_HOOK_INIT(path_chown,skl_path_chown),
	//LSM_HOOK_INIT(file_alloc_security, skel_file_alloc_security),
	//LSM_HOOK_INIT(file_free_security, skel_file_free_security),
};

static int __init sk_init(void)
{
	printk(KERN_INFO "Skeleton LSM loaded\n");
	security_add_hooks(skeleton_hooks, ARRAY_SIZE(skeleton_hooks),"Skeleton");
	printk(KERN_INFO "Hooks registered\n");
	struct process_attatched *task_0;
	task_0 = skeleton_task(current);
	if (!task_0) {
		printk("inital task is null");
		return -ENOMEM;
	}
	task_0->groupid = 0;
	task_0->appid = 0;
	task_0->perms = 22;
	return 0;
}

DEFINE_LSM(sk_init) = {
	.init = sk_init,
	.name = "skeleton",
	.blobs = &skeleton_blob_sizes,
};
