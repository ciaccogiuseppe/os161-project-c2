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

//#define PATH_LEN 128
// sys_chdir
int 
sys_chdir(userptr_t path, int *errp){
    //char kern_buf[PATH_MAX];
    char* kern_buf;
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
    
    int len = strlen((char*)path) + 1;

    kern_buf = kmalloc(len * sizeof(char));
    if(kern_buf == NULL){
        *errp = ENOMEM;
        return -1;
    }

    err = copyinstr(path, kern_buf, len, NULL);
    if (err){
        kfree(kern_buf);
        *errp = err;
        return -1;
    }

    err = vfs_open( kern_buf, O_RDONLY, 0644, &dir );
	if( err ){
        kfree(kern_buf);
        *errp = err;
        return -1;
    }

    err = vfs_setcurdir( dir );

	vfs_close( dir );

	if( err ){
        kfree(kern_buf);
        *errp = err;
        return -1;
    }
    kfree(kern_buf);
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
