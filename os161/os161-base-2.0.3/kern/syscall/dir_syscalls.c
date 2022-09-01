#include <syscall.h>
#include <vfs.h>
#include <uio.h>
#include <vnode.h>
//#include <iovec.h>
#include <proc.h>
#include <kern/errno.h>
#include <current.h>
#include <types.h>
#include <copyinout.h>
#include <kern/fcntl.h>
#include "../arch/mips/include/vm.h"
#include <addrspace.h>

static int
is_valid_pointer(userptr_t addr, struct addrspace *as){
  unsigned int pointer = (unsigned int) addr;
  if (pointer >= MIPS_KSEG0)
    return 0;
  if(!(((pointer >= as->as_vbase1) && (pointer < as->as_vbase1 + PAGE_SIZE*as->as_npages1))||
  ((pointer >= as->as_vbase2) && (pointer < as->as_vbase2 + PAGE_SIZE*as->as_npages2))||
  (pointer>=MIPS_KSEG0 - PAGE_SIZE*DUMBVM_STACKPAGES)))
    return 0;
  return 1;
}

//#define PATH_LEN 128
// sys_chdir
int 
sys_chdir(userptr_t path, int *errp){
    char kern_buf[PATH_MAX];
    int err;
    struct vnode *dir;
    
    if(path == NULL || !is_valid_pointer(path, proc_getas())){
        *errp = EFAULT;
        return -1;
    }

    if(path != NULL && strlen((char*)path) > PATH_MAX){
        *errp = ENAMETOOLONG;
        return -1;
    }

    err = copyinstr(path, kern_buf, sizeof(kern_buf), NULL);
    if (err){
        *errp = err;
        return -1;
    }

    err = vfs_open( kern_buf, O_RDONLY, 0644, &dir );
	if( err ){
        *errp = err;
        return -1;
    }

    err = vfs_setcurdir( dir );

	vfs_close( dir );

	if( err ){
        *errp = err;
        return -1;
    }
    
    return 0;
}

// sys___getcwd
int 
sys___getcwd(userptr_t buf_ptr, size_t buflen, int *errp){
    int err;
    struct uio buf;
    struct iovec vec;
    if(buf_ptr == NULL){
        // *errp = EINVAL;
        *errp = EFAULT;
        return -1;
    }
    if(buflen == 0){
        *errp = EINVAL;
        return -1;
    }
    uio_kinit(
        &vec,
        &buf,
        buf_ptr,
        buflen,
        0,
        UIO_READ
    );
    buf.uio_space = proc_getas();
    buf.uio_segflg = UIO_USERSPACE;
    err = vfs_getcwd(&buf);
    if(err){
        *errp = err;
        return -1;
    }
    return buflen - buf.uio_resid;
}
