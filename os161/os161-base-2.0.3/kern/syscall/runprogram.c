/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009
 *	The President and Fellows of Harvard College.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE UNIVERSITY AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE UNIVERSITY OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Sample/test code for running a user program.  You can use this for
 * reference when implementing the execv() system call. Remember though
 * that execv() needs to do more than runprogram() does.
 */

#include <types.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <lib.h>
#include <proc.h>
#include <current.h>
#include <addrspace.h>
#include <vm.h>
#include <vfs.h>
#include <syscall.h>
#include <test.h>
#include <kern/unistd.h>
#include <copyinout.h>

/*
static int
get_argv(int argc, char **args, vaddr_t *stackptr, vaddr_t *argvptr){
  int result;
  vaddr_t stackp = *stackptr, argvp;

  stackp -= (vaddr_t) (argc+1)*sizeof(char*);
  argvp = stackp;

  for(int i = 0; i < argc; i++){
    size_t copied = 0;
    size_t arg_len = strlen(args[i])+1;
    stackp -= arg_len;

    result = copyoutstr(args[i], (userptr_t) stackp, arg_len, &copied);
    if(result){
      return result;
    }

    result = copyout((void*)stackp, (userptr_t)argvp + i*sizeof(char*),sizeof(char*));
    if(result){
      return result;
    }
  }

  *stackptr = stackp;
  *argvptr = argvp;
  return 0;
}*/

/*
 * Load program "progname" and start running it in usermode.
 * Does not return except on error.
 *
 * Calls vfs_open on progname and thus may destroy it.
 */
int
#if OPT_SHELL
runprogram(char *progname, int argc, char **argv)
#else
runprogram(char *progname)
#endif
{
	struct addrspace *as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;

	/* Open the file. */
	result = vfs_open(progname, O_RDONLY, 0, &v);
	if (result) {
		return result;
	}

	/* We should be a new process. */
	KASSERT(proc_getas() == NULL);

	/* Create a new address space. */
	as = as_create();
	if (as == NULL) {
		vfs_close(v);
		return ENOMEM;
	}

	/* Switch to it and activate it. */
	proc_setas(as);
	as_activate();

	#if OPT_SHELL

	if (std_open(STDIN_FILENO) != STDIN_FILENO){
		return EIO;
	}
	if (std_open(STDOUT_FILENO) != STDOUT_FILENO){
		return EIO;
	}
	if (std_open(STDERR_FILENO) != STDERR_FILENO){
		return EIO;
	}

	#endif

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(as, &stackptr);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		return result;
	}

	#if OPT_SHELL
	vaddr_t argvptr;

	/*
	result = get_argv(argc, argv, &stackptr, &argvptr);
	if(result){
		return result;
	}*/

	stackptr -= (vaddr_t) ((argc+1)*sizeof(char*));
	argvptr = stackptr;

	for(int i = 0; i < argc; i++){
		size_t copied = 0;
		size_t arg_len = strlen(argv[i]) + 1;
		stackptr -= arg_len;
		result = copyoutstr(argv[i], (userptr_t) stackptr, arg_len, &copied);
		if(result){
			return result;
		}
		result = copyout(&stackptr, (userptr_t)argvptr + i*sizeof(char*), sizeof(char*));
		if(result){
			return result;
		}
	}

	/* Warp to user mode. */
	enter_new_process(argc, (userptr_t) argvptr,
			  NULL /*userspace addr of environment*/,
			  (vaddr_t) stackptr, entrypoint);

	#else

	/* Warp to user mode. */
	enter_new_process(0 /*argc*/, NULL /*userspace addr of argv*/,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);

	#endif

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
}

