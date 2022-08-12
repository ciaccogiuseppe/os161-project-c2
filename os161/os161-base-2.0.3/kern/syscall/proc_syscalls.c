/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys__exit.
 * It just avoids crash/panic. Full process exit still TODO
 * Address space is released
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <copyinout.h>
#include <syscall.h>
#include <lib.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <mips/trapframe.h>
#include <current.h>
#include <synch.h>

/*
 * system calls for process management
 */
void
sys__exit(int status)
{
#if OPT_SHELL
  struct proc *p = curproc;
  p->p_status = status & 0xff; /* just lower 8 bits returned */
  p->p_exited = 1;
  proc_remthread(curthread);
  proc_signal_end(p);
#else
  /* get address space of current process and destroy */
  struct addrspace *as = proc_getas();
  as_destroy(as);
#endif
  thread_exit();

  panic("thread_exit returned (should not happen)\n");
  (void) status; // TODO: status handling
}

static int is_valid_pointer(userptr_t addr, struct addrspace *as){
  unsigned int pointer = (unsigned int) addr;
  if (pointer >= MIPS_KSEG0)
    return 0;
  if(!(((pointer >= as->as_vbase1) && (pointer < as->as_vbase1 + PAGE_SIZE*as->as_npages1))||
  ((pointer >= as->as_vbase2) && (pointer < as->as_vbase2 + PAGE_SIZE*as->as_npages2))||
  (pointer>=MIPS_KSEG0 - PAGE_SIZE*DUMBVM_STACKPAGES)))
    return 0;
  return 1;
}

int sys_waitpid(pid_t pid, userptr_t statusp, int options, int *errp) {
  struct proc *p = proc_search_pid(pid);
  int s;
  
  // Check if the pid argument named a nonexistent process
  *errp = 0;
  if (p == NULL) {
	  *errp = ESRCH;
	  return -1;
  }
  
  // The options argument should be 0. It's not required to implement any options
  if (options != 0) {
    *errp = EINVAL;
    return -1;
  }

  // Check if the status argument was an invalid pointer  
  if(statusp != NULL && !is_valid_pointer(statusp, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  if((int)statusp%(sizeof(int))!=0){
    *errp = EFAULT;
    return -1;
  }

  // if the process that called the waitpid is not the parent
  if (p->parent_proc != curproc) {
    *errp = ECHILD;
    return -1;
  }

  // Process has already exited
  if (p->p_exited == 1)
    return pid;
  
  s = proc_wait(p);

  //The status_ptr pointer may also be NULL, in which case waitpid() ignores the child's return status
  if (statusp != NULL)
    *(int*)statusp = s;
  
  return pid;
}

pid_t sys_getpid(void) {
#if OPT_SHELL
  KASSERT(curproc != NULL);
  return curproc->p_pid;
#else
  return -1;
#endif
}

#if OPT_SHELL
static void
call_enter_forked_process(void *tfv, unsigned long dummy) {
  struct trapframe *tf = (struct trapframe *)tfv;
  (void)dummy;
  enter_forked_process(tf); 
 
  panic("enter_forked_process returned (should not happen)\n");
}

int sys_fork(struct trapframe *ctf, pid_t *retval) {
  struct trapframe *tf_child;
  struct proc *newp;
  int result;

  KASSERT(curproc != NULL);

  newp = proc_create_runprogram(curproc->p_name);
  if (newp == NULL) {
    return ENOMEM;
  }

  /* done here as we need to duplicate the address space 
     of thbe current process */
  as_copy(curproc->p_addrspace, &(newp->p_addrspace));
  if(newp->p_addrspace == NULL){
    proc_destroy(newp); 
    return ENOMEM; 
  }

  proc_file_table_copy(curproc, newp);

  /* we need a copy of the parent's trapframe */
  tf_child = kmalloc(sizeof(struct trapframe));
  if(tf_child == NULL){
    proc_destroy(newp);
    return ENOMEM; 
  }
  memcpy(tf_child, ctf, sizeof(struct trapframe));

  /* TO BE DONE: linking parent/child, so that child terminated 
     on parent exit */
  // Parent/child linking
  newp->parent_proc = curproc; 

  result = thread_fork(
		 curthread->t_name, newp,
		 call_enter_forked_process, 
		 (void *)tf_child, (unsigned long)0/*unused*/);

  if (result){
    proc_destroy(newp);
    kfree(tf_child);
    return result;
  } 

  *retval = newp->p_pid;
  return 0;
}

#endif
