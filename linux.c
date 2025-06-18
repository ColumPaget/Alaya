#include "linux.h"
#include "settings.h"

// This module contains some linux-specific syscalls etc. Some of these are supported in libUseful
// but they are independantly included here to allow for situations where they weren't compiled into
// a system-wide libuseful but we still want to use them in alaya.

// Linux is not the only OS to have a prctl syscall, but it does different things on those other OSes.
// Thus everything must be guarded with #ifdef __linux__


#ifdef __linux__
#ifdef USE_PRCTL
#include <sys/prctl.h>
#endif
#endif

//PR_SET_NO_NEW_PRIVS prevents privilege escalation, at least by straightforward methods like use of
//suid programs.
int LinuxSetNoSU()
{
#ifdef __linux__
#ifdef USE_NOSU
#ifdef USE_PRCTL
#ifdef PR_SET_NO_NEW_PRIVS
    prctl((int) PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
    if (prctl((int) PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) == 1)
    {
        if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath, "%s", "'NO_NEW_PRIVS' set. Process cannot escalate to root.");
        return(TRUE);
    }
    LogToFile(Settings.LogPath,"%s", "WARN: Failed to set 'NO_NEW_PRIVS'. Process can still su/sudo.");
#endif
#endif
#endif
#endif

    return(FALSE);
}


//PR_SET_DUMPABLE is mostly about allowing coredumps, but it has a lot
//of side effects.
//you must call this on linux in some situations after switching users,
//otherwise many files in /proc will continue to be owned by root
//which will cause trouble with unshare
int LinuxSetDumpable()
{
#ifdef __linux__
#ifdef USE_PRCTL
#ifdef PR_SET_DUMPABLE
    prctl((int) PR_SET_DUMPABLE, 1L, 0L, 0L, 0L);
    if (prctl((int) PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) == 1) return(TRUE);
#endif
#endif
#endif

    return(FALSE);
}

//PR_SET_MDWE tells the kernel to disallow future memory mappings to be both
//writable and executable. Furthermore existing memory mappings that are not
//executable cannot become executable. This should make things harder to
//load malicious code into a process.
//Things seem fuzzy as to whether malloc returns memory with PROT_EXEC enabled
//assuming it doesn't this prctl call should prevent a lot of exploits of
//memory errors by now allowing allocated memory to be executable.
int LinuxSetNoWriteExec(int Inherit)
{
    int Flags=0;

    return(FALSE);

#ifdef __linux__
#ifdef USE_MDWE
#ifdef USE_PRCTL
#ifdef PR_SET_MDWE
    Flags |= PR_MDWE_REFUSE_EXEC_GAIN;
    if (! Inherit) Flags |= PR_MDWE_NO_INHERIT;
    //New memory mapping protections can't be writable and executable.
    //Non-executable mappings can't become executable.
    prctl(PR_SET_MDWE, Flags, 0L, 0L, 0L);
    if (prctl(PR_GET_MDWE, 0L, 0L, 0L, 0L) == Flags)
    {
        return(TRUE);
    }
#endif
#endif
#endif
#endif

    return(FALSE);
}
