#include "xattrhandle.h"
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//imports

//macros
#define XATTR_SIZE 10000
#define TEST_PATH "/home/quinton/Documents/XattrTest"
//functions to print xattr,modified code from The Linux Programming Interface

int printdirattr(const char *dirpath) { //Function to print xattrs
    char list[XATTR_SIZE], value[XATTR_SIZE];
    ssize_t listLen, valueLen;
    int ns, k;
    bool hexDisplay = false;

    listLen = listxattr(dirpath, list, XATTR_SIZE);
    if (listLen == -1) {
		perror("listxattr failed!");
		exit(EXIT_FAILURE);
	}
        

    printf("%s:\n", dirpath);

    for (ns = 0; ns < listLen; ns += strlen(&list[ns]) + 1) {
        printf("        name=%s; ", &list[ns]);

        valueLen = getxattr(dirpath, &list[ns], value, XATTR_SIZE);
        if (valueLen == -1) {
            printf("couldn't get value");
        } else if (!hexDisplay) {
            printf("value=%.*s", (int) valueLen, value);
        } else {
            printf("value=");
            for (k = 0; k < valueLen; k++){
                printf("%02x ", (unsigned char) value[k]);
			}
        }
        printf("\n");
    }

    return 0;
}


int add_xattrs(){
  

  return 0;
}
