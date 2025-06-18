#ifndef ALAYA_LINUX_H
#define ALAYA_LINUX_H

#include "common.h"

// This module contains some linux-specific syscalls etc. Some of these are supported in libUseful
// but they are independantly included here to allow for situations where they weren't compiled into
// a system-wide libuseful but we still want to use them in alaya.

//prevent su/sudo/suid privilege escalation
int LinuxSetNoSU();

//obscure call needed in some unshare situations
int LinuxSetDumpable();

//memory-hardening syscall
int LinuxSetNoWriteExec(int Inherit);


#endif
