# COMMITS INFO

## COMMIT 2022/08/04 - 23:20 [GC]
Error handling in system calls:
- `read()`
- `write()`

Syscall write() passes all badcall tests
Syscall read() passes badcall tests except for the ones requiring lseek()

## COMMIT 35bce95
Added files in .vscode folder

## COMMIT 228dcc5, 00beaff 
Added lab implementations and SHELL option (impl of the last lab):
- `kern/arch/mips/syscall/syscall.c` (lab 2, 4, 5)
- `kern/arch/mips/vm/dumbvm.c` (lab 2)
- `kern/include/proc.h` (lab 4, 5)
- `kern/include/synch.h` (lab 3)
- `kern/include/syscall.h` (lab 2, 4, 5)
- `kern/proc/proc.c` (lab 4, 5)
- `kern/syscall/file_syscalls.c` (lab 2, 5 - opt)
- `kern/syscall/proc_syscalls.c` (lab 2, 4, 5 - opt)
- `kern/thread/synch.c` (lab 3)
- `kern/thread/thread.c` (lab 5)




