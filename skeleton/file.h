#ifndef _FILE_H_
#define _FILE_H_



#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
//This builds fine
struct fl_min{
	atomic_t ref_count;
	const char *appid;
	unsigned int perms;
};


struct fl_nest{
	spinlock_t lock; //protect label when updateing
	struct fl_min __rcu *min; //protected for concurrent reads
};

//Function prototpying

struct fl_min *create_label_min(const char *appid);
struct fl_nest *get_fl(struct file *file);
void put_min(struct fl_min *label);
void free_min(struct fl_min *label);
#endif /* FILE.H */
