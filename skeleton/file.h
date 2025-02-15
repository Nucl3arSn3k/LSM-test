#ifndef _FILE_H_
#define _FILE_H_



#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
//This builds fine
struct fl_min{
	atomic_t ref_count;//potentially start without this
	int appid; //Simplified from string,minimize complexity
	unsigned int perms; //Perm "field"
};

struct x_value{ //Just a custom struct for XATTRS
      int appid; //Stores the APPID or something
      unsigned int perms; //Stores perms
};



struct fl_nest{
	spinlock_t lock; //protect label when updating
	struct fl_min __rcu *min; //protected for concurrent reads
};

//Function prototpying

struct fl_min *create_label_min(int appid);
struct fl_nest *get_fl(struct inode *node);
void put_min(struct fl_min *label);
void free_min(struct fl_min *label); //Free it
#endif /* FILE.H */
