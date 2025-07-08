#ifndef _SECURITY_SKELETON_H
#define _SECURITY_SKELETON_H

#include <linux/fs.h>
#include "file.h"  // holds label definitions

/* Inner label management */
struct fl_min *create_label_min(int app_id);
void free_min(struct fl_min *label);
void put_min(struct fl_min *label);
struct fl_min *get_min(struct fl_min *label);


/* Hook Implementation */
void skl_inode_free(struct inode *file);
int skl_alloc_inode(struct inode *node);

#endif /* _SECURITY_SKELETON_H */
