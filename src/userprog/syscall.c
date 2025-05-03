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

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *esp = (uint32_t *) f->esp;   // esp is a pointer to the stack frame

  if(!is_valid_ptr(esp)){         // check if esp is a valid pointer
    exit(-1);                     // exit if not
  }

  int syscall_number = esp[0];     // syscall_number is the first element of the stack frame

  switch (syscall_number) {        //distributing the syscall_number by switch statement
    
    case SYS_HALT:             //if syscall_number is SYS_HALT
      halt();                  //call halt() function
      break;                    

    case SYS_EXIT:                 //if syscall_number is SYS_EXIT                 
      if(!is_valid_ptr((void *) esp[1])){  //since the function need a parameter, check if the parameter is valid
        exit(-1);                  // exit if not   
      }
      exit((int)esp[1]);        //call exit() function with the parameter 
      break;
    
    case SYS_WAIT:                 //if syscall_number is SYS_WAIT
      if(!is_valid_ptr((void *) esp[1])){   //check if the parameter is valid
        exit(-1);           // exit if not
      }
      f->eax = wait((tid_t) esp[1]); //call wait() function with the parameter and store the return value in f->eax
      break;
    
    default:               //if syscall_number is not in the list
      exit(-1);          // exit
  }
}

bool is_valid_ptr(const void *usr_ptr) {
    struct thread *cur = thread_current(); // Get the current thread
    bool not_null = usr_ptr != NULL; // Check if the pointer is not NULL
    bool in_user_space = is_user_vaddr(usr_ptr); // Check if the pointer is in user address space
    bool mapped = pagedir_get_page(cur->pagedir, usr_ptr) != NULL; // Check if the address is mapped in the page directory


    return not_null && in_user_space && mapped; // Return true if all checks pass
}

int wait(tid_t pid) {
  return process_wait(pid);
}


void exit(int status) {
    struct thread *t = thread_current();
    t->exit_status = status;
    printf("%s: exit(%d)\n", t->name, status);
    thread_exit();
}


void halt(void) {
  shutdown_power_off();
}

