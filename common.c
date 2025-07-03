#include "common.h"
#include "server.h"
#include "grp.h"

//for 'get default user'
#include "Authenticate.h"

TSettings Settings;
char *Version="5.1";

void SetTimezoneEnv()
{
    time_t Now;

    time(&Now);
    localtime(&Now);

    if (StrValid(tzname[1]))
    {
        setenv("TZ",tzname[1],TRUE);
    }
    else if (StrValid(tzname[0]))
    {
        setenv("TZ",tzname[0],TRUE);
    }
}




void HandleError(int Flags, const char *FmtStr, ...)
{
    va_list args;
    char *Tempstr=NULL;

    va_start(args,FmtStr);
    Tempstr=VFormatStr(Tempstr,FmtStr,args);
    va_end(args);

    if (Flags & ERR_LOG) LogToFile(Settings.LogPath, "%s", Tempstr);
    if (Flags & ERR_PRINT) printf("%s\n",Tempstr);

    Destroy(Tempstr);
    if (Flags & ERR_EXIT) exit(1);
}


TPathItem *PathItemCreate(int Type, const char *URL, const char *Path)
{
    TPathItem *PI=NULL;

    PI=(TPathItem *) calloc(1, sizeof(TPathItem));
    PI->Type=Type;
    PI->Path=CopyStr(PI->Path,Path);
    PI->Name=CopyStr(PI->Name,GetBasename((char *) Path));
    PI->URL=CopyStr(PI->URL,URL);
    PI->ContentType=CopyStr(PI->ContentType, "");
    return(PI);
}

void PathItemDestroy(void *pi_ptr)
{
    TPathItem *PI;

    if (! pi_ptr) return;
    PI=(TPathItem *) pi_ptr;
    Destroy(PI->Path);
    Destroy(PI->URL);
    Destroy(PI->Name);
    Destroy(PI->ContentType);

    free(PI);
}





char *ParentDirectory(char *RetBuff, const char *Path)
{
    char *RetStr=NULL, *ptr;
    int len;

    RetStr=CopyStr(RetBuff,Path);
    len=StrLen(RetStr);

//Don't strip slash if directory is root dir
    if (len > 1)
    {
        StripDirectorySlash(RetStr);

        //Now strip off one dir name (the result of '..')
        StrRTruncChar(RetStr,'/');
        if (! StrValid(RetStr)) RetStr=CopyStr(RetStr,"/");
    }
    RetStr=SlashTerminateDirectoryPath(RetStr);

    return(RetStr);
}



int IsLocalHost(HTTPSession *Session, char *Host)
{
    const char *ptr;
    int len;

    if (! StrValid(Host)) return(TRUE);
    if (strcmp(Host,"localhost")==0) return(TRUE);
    if (strcmp(Host,"127.0.0.1")==0) return(TRUE);

    len=StrLen(Session->Host);
    if (len)
    {
        ptr=strchr(Session->Host, ':');
        if (ptr) len=ptr-Session->Host;
    }

    if (strncasecmp(Session->Host,Host,len)==0) return(TRUE);

    return(FALSE);
}





char *FindScriptHandlerForScript(char *RetStr, const char *ScriptPath)
{
    char *Handler=NULL, *ptr;
    ListNode *Curr;

    ptr=strrchr(ScriptPath,'.');

    Handler=CopyStr(RetStr,"");
    if (ptr)
    {
        Curr=ListGetNext(Settings.ScriptHandlers);
        while (Curr)
        {
            if (
                (strcmp(Curr->Tag,ptr)==0) ||
                (strcmp(Curr->Tag,ptr+1)==0)
            )
            {
                Handler=CopyStr(Handler,(char *) Curr->Item);
                break;
            }
            Curr=ListGetNext(Curr);
        }
    }

    return(Handler);
}




void DropCapabilities(int Level)
{
#ifdef USE_LINUX_CAPABILITIES

//use portable 'libcap' interface if it's available
#ifdef HAVE_LIBCAP
#include <sys/capability.h>

#define CAPSET_SIZE 10
    int CapSet[CAPSET_SIZE];
    int NumCapsSet=0;
    cap_t cap;


//if we are a session then drop everything. Switch user should have happened,
//but if it failed we drop everything. Yes, a root attacker can probably
//reclaim caps, but it at least makes them do some work

    if (Level < CAPS_LEVEL_SESSION)
    {
        CapSet[NumCapsSet]= CAP_CHOWN;
        NumCapsSet++;

        CapSet[NumCapsSet]= CAP_SETUID;
        NumCapsSet++;

        CapSet[NumCapsSet]= CAP_SETGID;
        NumCapsSet++;
    }

    if (Level < CAPS_LEVEL_CHROOTED)
    {
        CapSet[NumCapsSet] = CAP_SYS_CHROOT;
        NumCapsSet++;

        CapSet[NumCapsSet] = CAP_FOWNER;
        NumCapsSet++;

        CapSet[NumCapsSet] = CAP_DAC_OVERRIDE;
        NumCapsSet++;
    }

    if (Level==CAPS_LEVEL_STARTUP)
    {
        CapSet[NumCapsSet] = CAP_NET_BIND_SERVICE;
        NumCapsSet++;
    }

    cap=cap_init();
    if (cap_set_flag(cap, CAP_EFFECTIVE, NumCapsSet, CapSet, CAP_SET) == -1)  ;
    if (cap_set_flag(cap, CAP_PERMITTED, NumCapsSet, CapSet, CAP_SET) == -1)  ;
    if (cap_set_flag(cap, CAP_INHERITABLE, NumCapsSet, CapSet, CAP_SET) == -1)  ;

    cap_set_proc(cap);
    cap_free(cap);

#else

//if libcap is not available try linux-only interface

#include <linux/capability.h>

    struct __user_cap_header_struct cap_hdr;
    cap_user_data_t cap_values;
    unsigned long CapVersions[]= { _LINUX_CAPABILITY_VERSION_3, _LINUX_CAPABILITY_VERSION_2, _LINUX_CAPABILITY_VERSION_1, 0};
    int val=0, i, result;

//the CAP_ values are not bitmask flags, but instead indexes, so we have
//to use shift to get the appropriate flag value
    if (Level < CAPS_LEVEL_SESSION)
    {
        val |=(1 << CAP_CHOWN);
        val |=(1 << CAP_SETUID);
        val |=(1 << CAP_SETGID);
    }

    if (Level < CAPS_LEVEL_CHROOTED)
    {
        val |= (1 << CAP_SYS_CHROOT);
        val |= (1 << CAP_FOWNER);
        val |= (1 << CAP_DAC_OVERRIDE);
    }


    if (Level==CAPS_LEVEL_STARTUP) val |= (1 << CAP_NET_BIND_SERVICE);


    for (i=0; CapVersions[i] > 0; i++)
    {
        cap_hdr.version=CapVersions[i];
        cap_hdr.pid=0;

        //Horrible cludgy interface. V1 uses 32bit, V2 uses 64 bit, and somehow spreads this over
        //two __user_cap_data_struct items
        if (CapVersions[i]==_LINUX_CAPABILITY_VERSION_1) cap_values=calloc(1,sizeof(struct __user_cap_data_struct));
        else cap_values=calloc(2,sizeof(struct __user_cap_data_struct));

        cap_values->effective=val;
        cap_values->permitted=val;
        cap_values->inheritable=val;
        result=capset(&cap_hdr, cap_values);
        free(cap_values);
        if (result == 0) break;
    }

#endif
#endif
}
