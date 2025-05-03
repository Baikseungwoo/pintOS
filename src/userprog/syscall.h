#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"

void syscall_init (void);
bool is_valid_ptr(const void *usr_ptr);
int wait(tid_t pid);
void exit(int status);
void halt(void);


#endif /* userprog/syscall.h */
