#ifndef _SKELETON_H_
#define _SKELETON_H_

#define SKELETON_INVALID -1
#include "file.h"
extern struct lsm_blob_sizes skeleton_blob_sizes;

static inline struct fl_min *skeleton_inode(const struct inode *inode){
  return inode->i_security + skeleton_blob_sizes.lbs_inode;
}

static inline struct process_attatched *skeleton_task(struct task_struct *task){
  return task->security + skeleton_blob_sizes.lbs_task;
}

#endif /* _SKELETON_H_ */
