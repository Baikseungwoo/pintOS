#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"
#include "filesys/file.h"


typedef int tid_t;
struct file_descriptor {
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};


struct fdt {
    struct file_descriptor *table[64];
    int next_fd;    
};






struct file_descriptor *get_open_file(int fd);
void syscall_init (void);
bool is_valid_ptr(const void *usr_ptr);
int wait(tid_t pid);
void exit(int status);
void halt(void);
int write(int fd, const void *buffer, unsigned size);
int read (int fd, void *buffer, unsigned size);
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool create(const char *file_name, unsigned size);
bool remove(const char *file_name);
tid_t exec(const char *cmd_line);





#endif /* userprog/syscall.h */



