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
#include <kern/fcntl.h>
#include <vfs.h>
#include <kern/wait.h>

static char karg[ARG_MAX]; // tmp vector to store the single argument before copying it into kargbuf
static unsigned char kargbuf[ARG_MAX]; // tmp vector to store the arguments before copying them into the stack

/*
 * system calls for process management
 */
void
sys__exit(int status)
{
  struct proc *p = curproc;
  spinlock_acquire(&p->p_lock);
  //p->p_status = (status & 0xff) << 2; /* just lower 8 bits returned (2 bit shift: see include/kern/wait.h) */
  p->p_status = _MKWAIT_EXIT(status); /* just lower 8 bits returned (2 bit shift: see include/kern/wait.h) */
  p->p_exited = 1;
  spinlock_release(&p->p_lock);
  proc_remthread(curthread);
  proc_signal_end(p);
  thread_exit();

  panic("thread_exit returned (should not happen)\n");
  (void) status; // TODO: status handling
}

int sys_waitpid(pid_t pid, int* statusp, int options, int *errp, bool is_kernel) {
  struct proc *p = proc_search_pid(pid);
  int s;
  
  // Check if the pid argument named a nonexistent process
  *errp = 0;
  if (p == NULL) {
	  *errp = ESRCH;
	  return -1;
  }
  
  // The options argument should be 0. It's not required to implement any options
  if (options != 0 && options != WNOHANG) {
    *errp = EINVAL;
    return -1;
  }

  // Check if the status argument was an invalid pointer  
  if(!is_kernel && statusp != NULL && !is_valid_pointer((userptr_t)statusp, proc_getas())){
    *errp = EFAULT;
    return -1;
  }

  if((int)statusp%(sizeof(int*))!=0){
    *errp = EFAULT;
    return -1;
  }

  spinlock_acquire(&p->p_lock);
  // if the process that called the waitpid is not the parent
  if (!is_kernel && p->parent_proc != curproc) {
    spinlock_release(&p->p_lock);
    *errp = ECHILD;
    return -1;
  }

  // Process has already exited
  if (p->p_exited == 1){
    s = p->p_status;
    spinlock_release(&p->p_lock);
    proc_destroy(p);
  } else {
    spinlock_release(&p->p_lock); 
    if(options == WNOHANG){ // to check
      return 0;
    } else {
      s = proc_wait(p);
    }
  }

  //The status_ptr pointer may also be NULL, in which case waitpid() ignores the child's return status
  if (statusp != NULL){
    if(is_kernel){
      *(int*)statusp = s;
    } else {
      copyout(&s, (userptr_t)statusp, sizeof(int));
    }
  }
    
  return pid;
}

pid_t sys_getpid(void) {
  KASSERT(curproc != NULL);
  return curproc->p_pid;
}

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
  char *name;

  KASSERT(curproc != NULL);

  spinlock_acquire(&curproc->p_lock);
  name = curproc->p_name;
  spinlock_release(&curproc->p_lock);
  newp = proc_create_runprogram(name);
  if(newp == NULL){
    if(is_proc_table_full())
		  return ENPROC;
    else
      return ENOMEM;
  }

  /* done here as we need to duplicate the address space 
     of thbe current process */
  as_copy(proc_getas(), &(newp->p_addrspace));
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

/* It receive a string and the alignment and returns the len as the first greatest multiple of align.
It also fills the remaining space with '\0' until it reaches a lenght of len+diff */
static int
align_arg(char arg[ARG_MAX], int align){
  int len = strlen(arg) + 1 , diff;

  if(len % align == 0)
    return len;

  diff = align - (len % align);
  
  for(int i = len; i < len+diff; i++)
    arg[i] = '\0';

  return len + diff;
}

/* It works like align_arg but it doesn't modify the string*/ 
static int 
get_aligned_len(char arg[ARG_MAX], int align){
  int len = strlen(arg) + 1;

  if(len % align == 0)
    return len;
  
  return len + (align - (len % align));
}

/* Copy the arguments from stack to kargbuf and return argc into nargs 
and total length into buflen. The arguments are aligned on 32 bits */
static int
copy_args(userptr_t uargs, int *nargs, int *buflen){
  int i = 0, err, n_last = 0, argc = 0, len = 0, arg_str_len_tot = 0;
  char *ptr;
  unsigned int *p_begin = NULL;
  unsigned char *p_end = NULL;
  uint32_t offset, last_offset;

  // Copy the argument and compute it's length
  while((err = copyin((userptr_t)uargs + i*4, &ptr, sizeof(ptr))) == 0){
    if(ptr == NULL)
      break;
    err = copyinstr((userptr_t)ptr, karg, sizeof(karg), NULL);
    if(err)
      return err;
    i++;
    argc += 1;
    len += get_aligned_len(karg, 4) + sizeof(char*);
    
    // Check if the total size of the argument strings exceeds ARG_MAX
    arg_str_len_tot += (strlen(ptr) + 1);
    if (arg_str_len_tot > ARG_MAX)
      return E2BIG;
  }

  if(err)
    return err;

  // Add space for NULL pointer at the end of vector of pointer
  len += sizeof(char*);

  i = 0;
  n_last = 0;
  last_offset = (argc+1) * sizeof(char*);
  p_begin = (unsigned int *) kargbuf;
  p_end = kargbuf + last_offset;
  // Copy the arguments in kargbuf and create the vector of indexes
  while((err = copyin((userptr_t)uargs + i*4, &ptr, sizeof(ptr))) == 0){
    if(ptr == NULL)
      break;
    err = copyinstr((userptr_t)ptr, karg, sizeof(karg), NULL);
    if(err)
      return err;
      
    offset = last_offset + n_last;
    n_last = align_arg(karg, 4);
    *p_begin = offset;

    memcpy(p_end, karg, n_last);

    p_end += n_last;
    p_begin += 1;
    last_offset = offset;
    i++;
  }

  if(err)
    return err;

  // NULL pointer at the end of vector of indexes
  *p_begin = 0;

  *nargs = argc;
  *buflen = len;

  return 0;
}

/* It sobstitute the indexes with the pointers that the arguments
 will have into the stack */
static int 
adjust_kargbuf(int n_params, vaddr_t stack_ptr){
  int i, index;
  uint32_t new_offset = 0, old_offset = 0;

  for(i = 0; i < n_params; i++){
    index = i * sizeof(char*);
    old_offset = *((unsigned int *)(kargbuf+index));
    new_offset = stack_ptr + old_offset;
    memcpy(kargbuf + index, &new_offset, sizeof(char*));
  }
  return 0;
}

int
sys_execv(userptr_t program, userptr_t args, int *errp)
{
	struct addrspace *new_as, *old_as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
  // vaddr_t argv_ptr;
	int result, argc, buflen;
  //char prg_path[PATH_MAX];
  char* prg_path, *prg_name;

  KASSERT(curthread != NULL);
  KASSERT(curproc != NULL);
  KASSERT(curproc->p_numthreads == 1);

  // Check parameters validity
  if(!is_valid_pointer(program, proc_getas())){
    *errp = EFAULT;
    return -1;
  }

  if((args == NULL) || (!is_valid_pointer(args, proc_getas()))){
    *errp = EFAULT;
    return -1;
  }
	
  // Check if maximum path name length is exceeded
  int len = strlen((char*)program) + 1;
  if (len > PATH_MAX) {
    *errp = ENAMETOOLONG;
    return -1;
  }

  prg_path = kmalloc(len * sizeof(char));
  if(prg_path == NULL){
      *errp = ENOMEM;
      return -1;
  }

  result = copyinstr(program, prg_path, len, NULL);
  if(result){
    *errp = result;
    return -1;
  }

  prg_name = kstrdup(prg_path);
  if(prg_name == NULL){
    *errp = ENOMEM;
    return -1;
  }

  // Update process name
  spinlock_acquire(&curproc->p_lock);
  kfree(curproc->p_name);
  curproc->p_name =prg_name;
  spinlock_release(&curproc->p_lock);

  prg_name = kstrdup(prg_path);
  if(prg_name == NULL){
    *errp = ENOMEM;
    return -1;
  }

  // Update thread name
  kfree(curthread->t_name);
  curthread->t_name = prg_name;

	/* Open the file. */
	result = vfs_open(prg_path, O_RDONLY, 0, &v);
	if (result) {
    kfree(prg_path);
    *errp = result;
		return -1;
	}

  // Copy arguments from user stack to kargbuf
  result = copy_args(args, &argc, &buflen);
  if(result){
    kfree(prg_path);
    vfs_close(v);
    *errp = result;
    return -1;
  }
	/* We should be a new process. */
	// KASSERT(proc_getas() == NULL);

	/* Create a new address space. */
	new_as = as_create();
	if (new_as == NULL) {
    kfree(prg_path);
		vfs_close(v);
    *errp = ENOMEM;
		return -1;
	}

  /* Switch to it and activate it. */
  as_deactivate(); // do nothing
	old_as = proc_setas(new_as);
	as_activate();

	/*
  if (std_open(STDIN_FILENO) != STDIN_FILENO){
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
		return EIO;
	}
	if (std_open(STDOUT_FILENO) != STDOUT_FILENO){
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
		return EIO;
	}
	if (std_open(STDERR_FILENO) != STDERR_FILENO){
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
		return EIO;
	}
  */

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
    kfree(prg_path);
    as_deactivate(); // do nothing
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
    *errp = result;
		return -1;
	}

  /* Define the user stack in the address space */
	result = as_define_stack(new_as, &stackptr);
	if (result) {
    kfree(prg_path);
    as_deactivate(); // do nothing
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
		/* p_addrspace will go away when curproc is destroyed */
    *errp = result;
		return -1;
	}

  // Update stack pointer and update vector of pointers in kargbuf
  stackptr -= buflen;
  result = adjust_kargbuf(argc, stackptr);
  if(result){
    kfree(prg_path);
    as_deactivate(); // do nothing
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
    *errp = result;
		return -1;
  }

  // Copy arguments from kargbuf to stack
  result = copyout(kargbuf, (userptr_t)stackptr, buflen);
  if(result){
    kfree(prg_path);
    as_deactivate(); // do nothing
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
    vfs_close(v);
    *errp = result;
		return -1;
  }

	/* Done with the file now. */
	vfs_close(v);
  as_destroy(old_as);
  kfree(prg_path);

	/* Warp to user mode. */
	enter_new_process(argc /*argc*/, argc!=0?((userptr_t) stackptr):NULL /*userspace addr of argv*/,
			    NULL /*userspace addr of environment*/,
			    stackptr, entrypoint);

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
  *errp = EINVAL;
	return -1;
}
