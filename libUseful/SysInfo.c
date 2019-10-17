#include "SysInfo.h"
#include "Socket.h" // for MAX_HOST_NAME

#include <sys/utsname.h>

#ifdef linux
#include <sys/sysinfo.h>
#endif


//This is a convinience function for use by modern languages like
//lua that have an 'os' object that returns information
const char *OSSysInfoString(int Info)
{
    static struct utsname UtsInfo;
    struct passwd *pw;
    const char *ptr;
		static char *buf=NULL;

    uname(&UtsInfo);

    switch (Info)
    {
    case OSINFO_TYPE:
        return(UtsInfo.sysname);
        break;

    case OSINFO_ARCH:
        return(UtsInfo.machine);
        break;

    case OSINFO_RELEASE:
        return(UtsInfo.release);
        break;

    case OSINFO_HOSTNAME:
				buf=SetStrLen(buf, HOST_NAME_MAX);
				gethostname(buf, HOST_NAME_MAX);
        return(buf);
        break;

    case OSINFO_DOMAINNAME:
				buf=SetStrLen(buf, HOST_NAME_MAX);
				getdomainname(buf, HOST_NAME_MAX);
        return(buf);
        break;

    case OSINFO_HOMEDIR:
        pw=getpwuid(getuid());
        if (pw) return(pw->pw_dir);
        break;

    case OSINFO_TMPDIR:
        ptr=getenv("TMPDIR");
        if (! ptr) ptr=getenv("TEMP");
        if (! ptr) ptr="/tmp";
        if (ptr) return(ptr);
        break;


        /*
        case OSINFO_USERINFO:
          pw=getpwuid(getuid());
          if (pw)
          {
            MuJSNewObject(TYPE_OBJECT);
            MuJSNumberProperty("uid",pw->pw_uid);
            MuJSNumberProperty("gid",pw->pw_gid);
            MuJSStringProperty("username",pw->pw_name);
            MuJSStringProperty("shell",pw->pw_shell);
            MuJSStringProperty("homedir",pw->pw_dir);
          }
        break;
        }
        */

    }


    return("");
}


//This is a convienice function for use by modern languages like
//lua that have an 'os' object that returns information
unsigned long OSSysInfoLong(int Info)
{
#ifdef linux
    struct sysinfo SysInfo;

    sysinfo(&SysInfo);
    switch (Info)
    {
    case OSINFO_UPTIME:
        return((unsigned long) SysInfo.uptime);
        break;
    case OSINFO_TOTALMEM:
        return((unsigned long) SysInfo.totalram);
        break;
    case OSINFO_FREEMEM:
        return((unsigned long) SysInfo.freeram);
        break;
    case OSINFO_BUFFERMEM:
        return((unsigned long) SysInfo.bufferram);
        break;
    case OSINFO_PROCS:
        return((unsigned long) SysInfo.procs);
        break;
//case OSINFO_LOAD: MuJSArray(TYPE_ULONG, 3, (void *) SysInfo.loads); break;

    }

#endif
    return(0);
}
