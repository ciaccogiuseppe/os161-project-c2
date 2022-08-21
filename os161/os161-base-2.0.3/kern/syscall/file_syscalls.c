/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys_read and sys_write.
 * just works (partially) on stdin/stdout
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <syscall.h>
#include <synch.h>
#include <current.h>
#include <kern/fcntl.h>
#include <lib.h>
#include <copyinout.h>
#include <vnode.h>
#include <vfs.h>
#include <limits.h>
#include <uio.h>
#include <proc.h>
#include "../arch/mips/include/vm.h"
#include <addrspace.h>
#include <kern/seek.h>
#include <kern/stat.h>

/* max num of system wide open files */
#define SYSTEM_OPEN_MAX (10*OPEN_MAX)

#define USE_KERNEL_BUFFER 0



struct openfile systemFileTable[SYSTEM_OPEN_MAX];

void openfileIncrRefCount(struct openfile *of) {
  if (of!=NULL)
    of->countRef++;
}

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

#if USE_KERNEL_BUFFER

static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *errp) {
  struct iovec iov;
  struct uio ku;
  int result, nread;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd > OPEN_MAX) {
    *errp = EBADF;
    return -1;
  }
  of = curproc->fileTable[fd];
  if (of==NULL) {
    *errp = EBADF;
    return -1;
  }
  if ((of->openflags & 3) == O_WRONLY){
    *errp = EBADF;
    return -1;
  }
  vn = of->vn;
  if (vn==NULL) {
    *errp = EBADF;
    return -1;
  }

  if(!is_valid_pointer(buf_ptr, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  kbuf = kmalloc(size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_READ);
  result = VOP_READ(vn, &ku);
  if (result) {
    *errp = result;
    return -1;
  }
  of->offset = ku.uio_offset;
  nread = size - ku.uio_resid;
  copyout(kbuf,buf_ptr,nread);
  kfree(kbuf);
  return (nread);
}

static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *errp) {
  struct iovec iov;
  struct uio ku;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd > OPEN_MAX) {
    *errp = EBADF;
    return -1;
  }
  of = curproc->fileTable[fd];
  if (of==NULL) {
    *errp = EBADF;
    return -1;
  }
  if ((of->openflags & 3) == O_RDONLY){
    *errp = EBADF;
    return -1;
  }
  vn = of->vn;
  if (vn==NULL) {
    *errp = EBADF;
    return -1;
  }

  if(!is_valid_pointer(buf_ptr, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  kbuf = kmalloc(size);
  copyin(buf_ptr,kbuf,size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_WRITE);
  result = VOP_WRITE(vn, &ku);
  if (result) {
    *errp = result;
    return -1;
  }
  kfree(kbuf);
  of->offset = ku.uio_offset;
  nwrite = size - ku.uio_resid;
  return (nwrite);
}

#else

static int
file_read(int fd, userptr_t buf_ptr, size_t size, int *errp) {
  struct iovec iov;
  struct uio u;
  int result;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX){
    *errp = EBADF;
    return -1;
  } 
  of = curproc->fileTable[fd];
  if (of==NULL){
    *errp = EBADF;
    return -1;
  }
  if ((of->openflags & 3) == O_WRONLY){
    *errp = EBADF;
    return -1;
  }
  vn = of->vn;
  if (vn==NULL){
    *errp = EBADF;
    return -1;
  }

  if(!is_valid_pointer(buf_ptr, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_READ;
  u.uio_space = curproc->p_addrspace;

  result = VOP_READ(vn, &u);
  if (result) {
    *errp = result;
    return -1;
  }

  of->offset = u.uio_offset;
  return (size - u.uio_resid);
}

static int
file_write(int fd, userptr_t buf_ptr, size_t size, int *errp) {
  struct iovec iov;
  struct uio u;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX){
    *errp = EBADF;
    return -1;
  }
  of = curproc->fileTable[fd];
  
  if (of==NULL){
    *errp = EBADF;
    return -1;
  }
  if ((of->openflags & 3)== O_RDONLY){
    *errp = EBADF;
    return -1;
  }
  vn = of->vn;
  if (vn==NULL){
    *errp = EBADF;
    return -1;
  }

  if(!is_valid_pointer(buf_ptr, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }


  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_WRITE;
  u.uio_space = curproc->p_addrspace;

  result = VOP_WRITE(vn, &u);
  if (result) {
    *errp = result;
    return -1;
  }
  of->offset = u.uio_offset;
  nwrite = size - u.uio_resid;
  return (nwrite);
}

#endif

/*
 * file system calls for open/close
 */
int
sys_open(userptr_t path, int openflags, mode_t mode, int *errp)
{
  int fd, i;
  struct vnode *v;
  struct openfile *of=NULL;; 	
  int result;
  char kbuf[PATH_MAX];

  if(path == NULL){
    *errp = EFAULT;
    return -1;
  }

  if(!is_valid_pointer(path, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  result = copyinstr(path, kbuf, sizeof(kbuf), NULL);
  if(result){
    *errp = result;
    return -1;
  }

  result = vfs_open(kbuf, openflags, mode, &v);
  if (result) {
    *errp = result;
    return -1;
  }
  /* search system open file table */
  for (i=0; i<SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn==NULL) {
      of = &systemFileTable[i];
      of->vn = v;
      of->offset = 0; // TODO: handle offset with append
      of->countRef = 1;
      of->openflags = openflags;
      break;
    }
  }
  if (of==NULL) { 
    // no free slot in system open file table
    *errp = ENFILE;
  }
  else {
    for (fd=STDERR_FILENO+1; fd<OPEN_MAX; fd++) {
      if (curproc->fileTable[fd] == NULL) {
	      curproc->fileTable[fd] = of;
	      return fd;
      }
    }
    // no free slot in process open file table
    *errp = EMFILE;
  }

  vfs_close(v);
  return -1;
}

/*
 * file system calls for open/close
 */
int sys_close(int fd, int *errp) {
  struct openfile *of = NULL; 
  struct vnode *vn;

  *errp = 0;
  // In order to pass testbin/badcall tests, fd==OPEN_MAX should return an error
  if (fd < 0 || fd >= OPEN_MAX) {
    *errp = EBADF;
    return -1;
  }

  KASSERT(curproc!=NULL);
  of = curproc->fileTable[fd];
  if (of == NULL) {
    *errp = EBADF;
    return -1;
  }

  curproc->fileTable[fd] = NULL;

  if (--of->countRef > 0)
    return 0; // just decrement ref cnt
  
  vn = of->vn;
  of->vn = NULL;
  if (vn == NULL) {
    *errp = EIO;
    return -1;
  }

  vfs_close(vn);	
  return 0;
}



/*
 * simple file system calls for write/read
 */
int
sys_write(int fd, userptr_t buf_ptr, size_t size, int *errp)
{
  //int i;
  //char *p = (char *)buf_ptr;

  *errp=0;
  return file_write(fd, buf_ptr, size, errp);
  /*
  if ((fd!=STDOUT_FILENO && fd!=STDERR_FILENO)||
    (fd==STDOUT_FILENO && (curproc->fileTable[STDOUT_FILENO])!=NULL)||
    (fd==STDERR_FILENO && (curproc->fileTable[STDERR_FILENO])!=NULL)) {
    
  }

  for (i=0; i<(int)size; i++) {
    putch(p[i]);
  }

  return (int)size;*/
}

int
sys_read(int fd, userptr_t buf_ptr, size_t size, int *errp)
{
  //int i;
  //char *p = (char *)buf_ptr;

  *errp=0;
  return file_read(fd, buf_ptr, size, errp);
  /*
  if (fd!=STDIN_FILENO || (fd==STDIN_FILENO && (curproc->fileTable[STDIN_FILENO])!=NULL)) {
    return file_read(fd, buf_ptr, size, errp);
  }

  for (i=0; i<(int)size; i++) {
    p[i] = getch();
    if (p[i] < 0) 
      return i;
  }

  return (int)size;*/
}

off_t 
sys_lseek(int fd, off_t pos, int whence, int *errp){
  struct openfile *of;
  off_t new_offset = 0;
  struct stat st;
  int result;

  /*if(fd >=0 && fd <= STDERR_FILENO){
    *errp = ESPIPE;
    return -1;
  }*/

  if(fd < 0 || fd >= OPEN_MAX){
    *errp = EBADF;
    return -1;
  }

  if(whence!=SEEK_SET && whence!=SEEK_CUR && whence!=SEEK_END){
    *errp = EINVAL;
    return -1;
  }

  of = curproc->fileTable[fd];

  if(of==NULL){
    *errp = EBADF;
    return -1;
  }

  result = VOP_ISSEEKABLE(of->vn);
  if(!result){
    *errp = ESPIPE;
    return -1;
  }

  switch(whence){
    case SEEK_SET:
      if(pos < 0){
        *errp = EINVAL;
        return -1;
      }
      new_offset = pos;
      break;
    case SEEK_CUR:
      if((of->offset + pos) < 0){
        *errp = EINVAL;
        return -1;
      }
      new_offset = of->offset + pos;
      break;
    case SEEK_END:
      result = VOP_STAT(of->vn, &st);
      if(result){
        *errp = result;
        return -1;
      }
      if((st.st_size + pos)<0){
        *errp = EINVAL;
        return -1;
      }
      new_offset = st.st_size + pos;
      break;
    default:
      *errp = EINVAL;
      return -1;
  }
  
  of->offset = new_offset;
  return new_offset;
}

int 
sys_dup2(int oldfd, int newfd, int *errp){
  struct openfile *old_of, *new_of;
  int result;

  if(oldfd < 0 || newfd < 0 || oldfd >= OPEN_MAX || newfd >= OPEN_MAX){
    *errp = EBADF;
    return -1;
  }

  if(oldfd == newfd)
    return newfd;
  
  old_of = curproc->fileTable[oldfd];
  new_of = curproc->fileTable[newfd];

  if(old_of == NULL){
    *errp = EBADF;
    return -1;
  }

  if(new_of != NULL){
    result = sys_close(newfd, errp);
    if(result==-1)
      return -1;
  }
  
  curproc->fileTable[newfd] = old_of;
  openfileIncrRefCount(old_of);
  VOP_INCREF(old_of->vn);

  return newfd;
}


int
std_open(int fileno){
  int fd, openflags, i;
  mode_t mode;
  struct vnode *v;
  struct openfile *of=NULL;; 	
  int result;
  const char* inpath = "con:";
  char path[5];
  
  strcpy(path, inpath);
  switch(fileno){
    case STDIN_FILENO:
      openflags = O_RDONLY;
      mode = 0;
      fd = STDIN_FILENO;
      break;
    case STDOUT_FILENO:
      openflags = O_WRONLY;
      mode = 0;
      fd = STDOUT_FILENO;
      break;
    case STDERR_FILENO:
      openflags = O_WRONLY;
      mode = 0;
      fd = STDERR_FILENO;
      break;
    default:
      return -1;
      break;
  }


  result = vfs_open(path, openflags, mode, &v);
  if (result) {
    return -1;
  }
  /* search system open file table */
  for (i=0; i<SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn==NULL) {
      of = &systemFileTable[i];
      of->vn = v;
      of->offset = 0; // TODO: handle offset with append
      of->countRef = 1;
      of->openflags = openflags;
      break;
    }
  }
  if (of==NULL) { 
    return -1;
  }


  curproc->fileTable[fd] = of;
  vfs_close(v);
  return fd;

}

int
sys_fstat(int fd, struct stat *statbuf, int *errp){
  int result;
  struct openfile *of;

  if(fd < 0 || fd >= OPEN_MAX){
    *errp = EBADF;
    return -1;
  }

  if(!is_valid_pointer((userptr_t)statbuf, curproc->p_addrspace)){
    *errp = EFAULT;
    return -1;
  }

  of = curproc->fileTable[fd];

  if(of==NULL){
    *errp = EBADF;
    return -1;
  }

  result = VOP_STAT(of->vn, statbuf);
  if(result){
    *errp = result;
    return -1;
  }

  return 0;
} 

int
sys_getdirentry(int fd, char *buf, size_t buflen, int* errp)
{
    int result;
    struct uio u;
    struct openfile *of;
    struct iovec iov;

    if (fd < 0 || fd >= OPEN_MAX){
      *errp = EBADF;
      return -1;
    } 
    of = curproc->fileTable[fd];
    if (of==NULL){
      *errp = EBADF;
      return -1;
    }

    if ((of->openflags & 3) == O_WRONLY){
      *errp = EBADF;
      return -1;
    }

    if(!is_valid_pointer((userptr_t)buf, curproc->p_addrspace)){
      *errp = EFAULT;
      return -1;
    }

    iov.iov_ubase = (userptr_t)buf;
    iov.iov_len = buflen;

    u.uio_iov = &iov;
    u.uio_iovcnt = 1;
    u.uio_resid = buflen;          // amount to read from the file
    u.uio_offset = of->offset;
    u.uio_segflg =UIO_USERISPACE;
    u.uio_rw = UIO_READ;
    u.uio_space = curproc->p_addrspace;

    result = VOP_GETDIRENTRY(of->vn, &u);
    if(result){
      *errp = result;
      return -1;
    }

    //return 0;
    of->offset = u.uio_offset;
    return (buflen - u.uio_resid);


    
}
