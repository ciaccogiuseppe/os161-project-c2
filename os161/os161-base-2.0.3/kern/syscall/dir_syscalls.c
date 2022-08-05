#include <syscall.h>
#include <vfs.h>
#include <uio.h>
#include <vnode.h>
//#include <iovec.h>
#include <proc.h>
#include <kern/errno.h>
#include <current.h>
#include <types.h>
#if OPT_SHELL
// sys_chdir
int 
sys_chdir(userptr_t path, int *errp){
    (void)path;
    (void)*errp;
    
    return 0;
}

// sys___getcwd
int 
sys___getcwd(userptr_t buf_ptr, size_t buflen, int *errp){
    int err;
    struct uio buf;
    struct iovec vec;
    uio_kinit(
        &vec,
        &buf,
        buf_ptr,
        buflen,
        0,
        UIO_READ
    );
    buf.uio_space = curproc->p_addrspace;
    buf.uio_segflg = UIO_USERSPACE;
    err = vfs_getcwd(&buf);
    if(err){
        *errp = err;
        return -1;
    }
    //return
    
    return buflen - buf.uio_resid;
}

#endif