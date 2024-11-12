#ifndef _FILE_H_
#define _FILE_H_



#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>


struct file_lable_min{
	atomic_t ref_count;
	const char *appid;
	unsigned int perms;
}


struct file_lable_nest {
	//lock here,spinlock or atomic?
	spinlock_t lock;
	struct file_lable_min __rcu *minlab;
}

