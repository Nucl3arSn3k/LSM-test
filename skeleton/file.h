#ifndef _FILE_H_
#define _FILE_H_
#define SKELETON_READ 4 //powers of 2
#define SKELETON_WRITE 2 //defining custom security fields here. Looks better this way
#define SKELETON_EXECUTE 1

#define SKELETON_RW (SKELETON_READ|SKELETON_WRITE) //Or of both,puts bits into order
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
//This builds fine
struct fl_min{
	int appid; //Simplified from string,minimize complexity
	unsigned int perms; //Perm "field"
};

struct x_value{ //Just a custom struct for XATTRS
      int appid; //Stores the APPID or something
      int read_perm;
	  int write_perm;
	  int exec_perm;//Stores perms
	  int o_readperm
	  int o_writeperm
      int o_execperm
};

struct process_attatched{ //Security field for process filler
  int appid;
  unsigned int perms;

};




//Function prototpying

struct fl_min *create_label_min(int appid);

void put_min(struct fl_min *label);
void free_min(struct fl_min *label); //Free it
#endif /* FILE.H */
