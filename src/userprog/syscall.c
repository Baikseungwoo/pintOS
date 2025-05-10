#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"          // is_user_vaddr()
#include "userprog/pagedir.h"       // pagedir_get_page()
#include "devices/shutdown.h"       // shutdown_power_off()
#include "userprog/process.h"       // process_wait()
#include "filesys/file.h"
#include "threads/synch.h"
#include <stdlib.h>
#include "threads/malloc.h"

#define STDIN 0
#define STDOUT 1
#define STDERR 2

static void syscall_handler (struct intr_frame *);
static struct list open_files;
static struct lock fs_lock;        //lock for file system



void
syscall_init (void) 
{
  list_init(&open_files);          //initialize the open_files list
  lock_init(&fs_lock);        //initialize the fs_lock
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) {
    uint32_t *ustack = (uint32_t *)f->esp;
    /* Use existing argc from user stack (ustack[1]) as syscall number */
    int syscall_number = (int)ustack[0];
    /* Optionally validate more stack args depending on syscall */
    if (!is_valid_ptr(&ustack[0])) exit(-1);

    switch (syscall_number) {
    case SYS_HALT:
        halt();
        break;

    case SYS_EXIT:
        {
          if (!is_valid_ptr(&ustack[1]))
            exit(-1);
          int status = (int) ustack[1];
          exit(status);
          break;
        }
        

    case SYS_WAIT:
        {
          if (!is_valid_ptr(&ustack[1]))
            exit(-1);
          tid_t pid = (tid_t) ustack[1];
          f->eax = wait(pid);
          break;
        }
      

    case SYS_WRITE:
        {
            if (!is_valid_ptr(&ustack[1])
              || !is_valid_ptr(&ustack[2])
              || !is_valid_ptr(&ustack[3]))
              exit(-1);
            int fd            = (int)    ustack[1];
            const void *buf   = (void *) ustack[2];
            unsigned size     = (unsigned)ustack[3];

             
            if (buf == NULL
              || (size > 0
                  && (!is_valid_ptr(buf)
                     || !is_valid_ptr((uint8_t*)buf + size - 1))))
              exit(-1);

            f->eax = write(fd, buf, size);
            break;
        }
    case SYS_CREATE:
        {
            if (!is_valid_ptr(&ustack[1])
              || !is_valid_ptr(&ustack[2]))
              exit(-1);
            const char *file_name = (const char *) ustack[1];
            unsigned size         = (unsigned) ustack[2];

            f->eax = create(file_name, size);
            break;
        }
    case SYS_REMOVE:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            const char *file_name = (const char *) ustack[1];

            f->eax = remove(file_name);
            break;
        }

    case SYS_OPEN:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            const char *file_name = (const char *) ustack[1];

            f->eax = open(file_name);
            break;
        }

    case SYS_FILESIZE:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            f->eax = filesize((int)ustack[1]);
            break;
        }

    case SYS_SEEK:
        {
            if (!is_valid_ptr(&ustack[1]) || !is_valid_ptr(&ustack[2]))
              exit(-1);
            seek((int)ustack[1], (unsigned)ustack[2]);
            break;
        }  

    case SYS_READ:
        {
            if (!is_valid_ptr(&ustack[1])
              || !is_valid_ptr(&ustack[2])
              || !is_valid_ptr(&ustack[3]))
              exit(-1);
            int fd            = (int)    ustack[1];
            void *buf         = (void *) ustack[2];
            unsigned size     = (unsigned)ustack[3];

            
            if (buf == NULL
              || (size > 0
                  && (!is_valid_ptr(buf)
                     || !is_valid_ptr((uint8_t*)buf + size - 1))))
              exit(-1);

            f->eax = read(fd, buf, size);
            break;
        }  

    case SYS_TELL:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            f->eax = tell((int)ustack[1]);
            break;
        }

    case SYS_CLOSE:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            close((int)ustack[1]);
            break;
        }
    case SYS_EXEC:
        {
            if (!is_valid_ptr(&ustack[1]))
              exit(-1);
            const char *cmd_line = (const char *) ustack[1];
            f->eax = exec(cmd_line);
            break;
        }

    default:
        exit(-1);
    }
}




bool is_valid_ptr(const void *usr_ptr) {
    struct thread *cur = thread_current();
    bool not_null = usr_ptr != NULL;
    bool in_user_space = is_user_vaddr(usr_ptr);
    void *mapped_page = pagedir_get_page(cur->pagedir, usr_ptr);
    bool mapped = mapped_page != NULL;


    return not_null && in_user_space && mapped;
}


int wait(tid_t pid) {
  return process_wait(pid);
}


void exit(int status) {
    struct thread *cur = thread_current();


    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);


#ifdef USERPROG
    struct thread *parent = thread_get_by_id(cur->parent_id);


    if (parent != NULL) {
        lock_acquire(&parent->lock_child);


        struct list_elem *e;
        for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
            struct child_status *child = list_entry(e, struct child_status, elem);
            if (child->child_id == cur->tid) {
                child->is_exit_called = true;
                child->child_exit_status = status;
                break;
            }
        }


        lock_release(&parent->lock_child);
    }
#endif


    thread_exit();
}




void halt(void) {
  shutdown_power_off();
}

struct
file_descriptor *get_open_file(int fd){
  struct list_elem *e;                   //define e to iterate through the list
  for(e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e)){      //repeat until the end of the list
    struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);    //get the file descriptor struct from the list element
    if(fd_struct->fd_num == fd && fd_struct->owner == thread_current()->tid){           //check if the fd_num and owner match
      return fd_struct;                //return the file descriptor struct if found                             
    }
  }
  return NULL;            //if not found
}


int write(int fd, const void *buffer, unsigned size) {

    if (!is_valid_ptr(buffer)) {
        exit(-1);
    }

    lock_acquire(&fs_lock);

    if (fd == STDOUT) {
        putbuf(buffer, size);
        lock_release(&fs_lock);
        return size;
    }

    struct file_descriptor *fd_struct = get_open_file(fd);
    int status = -1;
    if (fd_struct && fd_struct->file_struct) {
        printf("[write] writing to file descriptor\n");
        status = file_write(fd_struct->file_struct, buffer, size);
    } else {
        printf("[write] invalid file descriptor\n");
    }

    lock_release(&fs_lock);
    return status;
}

bool
create(const char *file_name, unsigned size) {
  // 1. Validate the file name pointer
  if (file_name == NULL || !is_user_vaddr(file_name)) {
    exit(-1);  // Terminate process if the pointer is invalid
  }


  // 2. Acquire the file system lock
  lock_acquire(&fs_lock);


  // 3. Create the file
  bool status = filesys_create(file_name, size);


  // 4. Release the file system lock
  lock_release(&fs_lock);


  // 5. Return the result of file creation
  return status;
}


bool
remove(const char *file_name) {
  // 1. Validate the file name pointer
  if (file_name == NULL || !is_user_vaddr(file_name)) {
    exit(-1);  // Terminate the process if the pointer is invalid
  }


  // 2. Acquire the file system lock
  lock_acquire(&fs_lock);


  // 3. Remove the file
  bool status = filesys_remove(file_name);


  // 4. Release the file system lock
  lock_release(&fs_lock);


  // 5. Return the result of the file removal
  return status;
}

int 
open(const char *file_name) {
  //Validate pointer
  if (file_name == NULL || !is_valid_ptr(file_name)) {
    exit(-1); // invalid pointer
  }


  // Acquire file system lock
  lock_acquire(&fs_lock);

  //Try to open the file
  struct file *f = filesys_open(file_name);
  if (f == NULL) {
    lock_release(&fs_lock);
    return -1; // failed to open file
  }


  //Allocate new file descriptor
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  if (fd == NULL) {
    file_close(f);
    lock_release(&fs_lock);
    return -1; // failed to allocate memory
  }


  fd->fd_num = allocate_fd();       
  fd->owner = thread_current()->tid;
  fd->file_struct = f;


  list_push_back(&open_files, &fd->elem);

  // Release lock and return fd number
  lock_release(&fs_lock);
  return fd->fd_num;
}

int allocate_fd(void) {
  struct thread *curr = thread_current();
  int fd = curr->fdt->next_fd;
  if (fd >= 64) {
    return -1;
  }
  /* Increase the next available fd for the thread */
  curr->fdt->next_fd++;

  return fd;
}

int filesize(int fd) {
 
  lock_acquire(&fs_lock);


  struct file_descriptor *fd_struct = get_open_file(fd);


  int size = -1;
  if (fd_struct != NULL) {
    size = file_length(fd_struct->file_struct);
  }


  lock_release(&fs_lock);


  return size;
}

int read(int fd, void *buffer, unsigned size) {
 
  if (!is_valid_ptr(buffer)) {
    exit(-1);
  }


  lock_acquire(&fs_lock);


  int status = -1;


  if (fd == STDOUT) {
    lock_release(&fs_lock);
    return -1;
  }


  if (fd == STDIN) {
    unsigned i;
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    lock_release(&fs_lock);
    return size;
  }


  struct file_descriptor *fd_struct = get_open_file(fd);
  if (fd_struct != NULL) {
    status = file_read(fd_struct->file_struct, buffer, size);
  }


  lock_release(&fs_lock);
  return status;
}

void
seek(int fd, unsigned position) {
 
  lock_acquire(&fs_lock);


  struct file_descriptor *fd_struct = get_open_file(fd);


  if (fd_struct != NULL) {
    file_seek(fd_struct->file_struct, position);
  }
 
  lock_release(&fs_lock);
}

unsigned
tell(int fd) {


  lock_acquire(&fs_lock);


  struct file_descriptor *fd_struct = get_open_file(fd);


  unsigned position = 0;
  if (fd_struct != NULL) {
    position = file_tell(fd_struct->file_struct);
  }


  lock_release(&fs_lock);


  return position;
}

void close(int fd) {
  lock_acquire(&fs_lock);

  //Search for file_descriptor
  struct list_elem *e;
  struct file_descriptor *fd_struct = NULL;

  for (e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e)) {
    struct file_descriptor *entry = list_entry(e, struct file_descriptor, elem);
    if (entry->fd_num == fd) {
      fd_struct = entry;
      break;
    }
  }

  //If found and owner matches, delegate actual close
  if (fd_struct != NULL && fd_struct->owner == thread_tid()) {
    close_open_file(fd);
  }

  lock_release(&fs_lock);
}
/* Close an open file based on file descriptor. */
void 
close_open_file(int fd) {
  struct list_elem *e;

  for (e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e)) {
    struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);

    if (fd_struct->fd_num == fd) {
    
      list_remove(e);

     
      file_close(fd_struct->file_struct);

   
      free(fd_struct);
      return;
    }
  }
}

tid_t exec(const char *cmd_line) {
  tid_t tid;
  struct thread *cur = thread_current();


  if (!is_valid_ptr(cmd_line)) {
    exit(-1);
  }


  char *cmd_copy = palloc_get_page(0);
  if (cmd_copy == NULL) return -1;
  strlcpy(cmd_copy, cmd_line, PGSIZE);


  cur->child_load_status = 0;


  tid = process_execute(cmd_copy);
  if (tid == TID_ERROR) {
    palloc_free_page(cmd_copy);
    return -1;
  }


  lock_acquire(&cur->lock_child);


  while (cur->child_load_status == 0)
    cond_wait(&cur->cond_child, &cur->lock_child);


  if (cur->child_load_status == -1)
    tid = -1;


  lock_release(&cur->lock_child);


  return tid;
}

