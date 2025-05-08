#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t child_tid);
void process_exit (void);
void process_activate (void);
void argument_stack(char* argv[], int argc, void **esp);

struct child_status {
    tid_t child_id;
    bool is_exit_called;
    bool has_been_waited;
    int child_exit_status;
    struct list_elem elem;
};

#endif /* userprog/process.h */

