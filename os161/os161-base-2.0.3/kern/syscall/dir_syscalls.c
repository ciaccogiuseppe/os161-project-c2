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

#define PATH_LEN 128
// sys_chdir
int 
sys_chdir(userptr_t path, int *errp){
    char kern_buf[PATH_LEN];
    int err;
    struct vnode *dir;

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
    return buflen - buf.uio_resid;
}
