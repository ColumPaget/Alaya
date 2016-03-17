#include "common.h"
#include "server.h"
#include "grp.h"

//for 'get default user'
#include "Authenticate.h"

TSettings Settings;
char *Version="1.7";

void SetTimezoneEnv()
{
time_t Now;

time(&Now);
localtime(&Now);

if (StrLen(tzname[1]))
{
   setenv("TZ",tzname[1],TRUE);
}
else if (StrLen(tzname[0]))
{
   setenv("TZ",tzname[0],TRUE);
}
}



HTTPSession *HTTPSessionCreate()
{
HTTPSession *Session;

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

//Must set all these to "" otherwise nulls can cause trouble later
Session->Protocol=CopyStr(Session->Protocol,"HTTP/1.1");
Session->ServerName=CopyStr(Session->ServerName,"");
Session->UserAgent=CopyStr(Session->UserAgent,"");
Session->UserName=CopyStr(Session->UserName,"");
Session->RealUser=CopyStr(Session->RealUser,"");
Session->ContentType=CopyStr(Session->ContentType,"");
Session->Host=CopyStr(Session->Host,"");
Session->Path=CopyStr(Session->Path,"");
Session->Arguments=CopyStr(Session->Arguments,"");
Session->ClientHost=CopyStr(Session->ClientHost,"");
Session->ClientIP=CopyStr(Session->ClientIP,"");
Session->ClientMAC=CopyStr(Session->ClientMAC,"");
Session->ClientReferrer=CopyStr(Session->ClientReferrer,"");
Session->StartDir=CopyStr(Session->StartDir,"");
Session->Depth=1;
Session->CacheTime=Settings.DocumentCacheTime;
Session->Headers=ListCreate();
Session->Flags |= SESSION_UPLOAD;

return(Session);
}



HTTPSession *HTTPSessionClone(HTTPSession *Src)
{
HTTPSession *Session;

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

//Must set all these to "" otherwise nulls can cause trouble later
Session->Protocol=CopyStr(Session->Protocol, Src->Protocol);
Session->Method=CopyStr(Session->Method, Src->Method);
Session->URL=CopyStr(Session->URL, Src->URL);
Session->ServerName=CopyStr(Session->ServerName, Src->ServerName);
Session->UserAgent=CopyStr(Session->UserAgent, Src->UserAgent);

Session->UserName=CopyStr(Session->UserName, Src->UserName);
Session->RealUser=CopyStr(Session->RealUser, Src->RealUser);
Session->Group=CopyStr(Session->Group, Src->Group);

Session->ContentType=CopyStr(Session->ContentType, Src->ContentType);
Session->ContentBoundary=CopyStr(Session->ContentBoundary, Src->ContentBoundary);
Session->Host=CopyStr(Session->Host, Src->Host);
Session->Path=CopyStr(Session->Path, Src->Path);
Session->Arguments=CopyStr(Session->Arguments, Src->Arguments);
Session->ClientHost=CopyStr(Session->ClientHost, Src->ClientHost);
Session->ClientIP=CopyStr(Session->ClientIP, Src->ClientIP);
Session->ClientMAC=CopyStr(Session->ClientMAC, Src->ClientMAC);
Session->ClientReferrer=CopyStr(Session->ClientReferrer, Src->ClientReferrer);
Session->StartDir=CopyStr(Session->StartDir, Src->StartDir);
Session->Cookies=CopyStr(Session->Cookies, Src->Cookies);
Session->Cipher=CopyStr(Session->Cipher, Src->Cipher);
Session->Depth=Src->Depth;
Session->ContentSize=Src->ContentSize;
Session->CacheTime=Src->CacheTime;
Session->Flags=Src->Flags;
Session->AuthFlags=Src->AuthFlags;
Session->Headers=ListCreate();
CopyVars(Session->Headers, Src->Headers);

return(Session);
}


//This copies certain fields from a request session object
//to a new response session object, but only those ones that
//are appropriate to a response!
HTTPSession *HTTPSessionResponse(HTTPSession *Src)
{
HTTPSession *Session;

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

//Must set all these to "" otherwise nulls can cause trouble later
Session->Protocol=CopyStr(Session->Protocol, Src->Protocol);
Session->Method=CopyStr(Session->Method, Src->Method);
Session->URL=CopyStr(Session->URL, Src->URL);
Session->ServerName=CopyStr(Session->ServerName, Src->ServerName);
Session->UserAgent=CopyStr(Session->UserAgent, Src->UserAgent);

Session->UserName=CopyStr(Session->UserName, Src->UserName);
Session->RealUser=CopyStr(Session->RealUser, Src->RealUser);
Session->Group=CopyStr(Session->Group, Src->Group);

Session->ContentType=CopyStr(Session->ContentType, Src->ContentType);
Session->Host=CopyStr(Session->Host, Src->Host);
Session->Path=CopyStr(Session->Path, Src->Path);
Session->Arguments=CopyStr(Session->Arguments, Src->Arguments);
Session->ClientHost=CopyStr(Session->ClientHost, Src->ClientHost);
Session->ClientIP=CopyStr(Session->ClientIP, Src->ClientIP);
Session->ClientMAC=CopyStr(Session->ClientMAC, Src->ClientMAC);
Session->StartDir=CopyStr(Session->StartDir, Src->StartDir);
Session->Depth=Src->Depth;
Session->CacheTime=Src->CacheTime;

//only copy certain flags!
Session->Flags=Src->Flags & (SESSION_KEEP_ALIVE | SESSION_REUSE | SESSION_AUTHENTICATED | SESSION_SSL | SESSION_ICECAST | SESSION_UPLOAD) ;
Session->AuthFlags=Src->AuthFlags;
Session->Headers=ListCreate();

return(Session);
}



void HTTPSessionDestroy(void *p_Trans)
{
HTTPSession *Trans;

if (! p_Trans) return;
Trans=(HTTPSession *) p_Trans;

DestroyString(Trans->Protocol);
DestroyString(Trans->Method);
DestroyString(Trans->ResponseCode);
DestroyString(Trans->OriginalURL);
DestroyString(Trans->URL);
DestroyString(Trans->Path);
DestroyString(Trans->Cipher);
DestroyString(Trans->Arguments);
DestroyString(Trans->Destination);
DestroyString(Trans->ContentType);
DestroyString(Trans->ContentBoundary);
DestroyString(Trans->UserName);
DestroyString(Trans->Password);
DestroyString(Trans->RealUser);
DestroyString(Trans->HomeDir);
DestroyString(Trans->AuthType);
DestroyString(Trans->Host);
DestroyString(Trans->ClientIP);
DestroyString(Trans->ClientMAC);
DestroyString(Trans->ClientHost);
DestroyString(Trans->ClientReferrer);
DestroyString(Trans->UserAgent);
DestroyString(Trans->ServerName);
DestroyString(Trans->SearchPath);
DestroyString(Trans->UserSettings);
DestroyString(Trans->StartDir);

ListDestroy(Trans->Headers,DestroyString);
free(Trans);
}


void HTTPSessionClear(void *p_Trans)
{
HTTPSession *Trans;

if (! p_Trans) return;
Trans=(HTTPSession *) p_Trans;

//Clear everything but SESSION_REUSE, SESSION_AUTHENTICATED and HTTP_SSL, which are persistent
Trans->Flags &= (SESSION_REUSE | SESSION_AUTHENTICATED | SESSION_UPLOAD | HTTP_SSL);

Trans->Method=CopyStr(Trans->Method,"");
Trans->ResponseCode=CopyStr(Trans->ResponseCode,"");
Trans->URL=CopyStr(Trans->URL,"");
Trans->Path=CopyStr(Trans->Path,"");
Trans->Arguments=CopyStr(Trans->Arguments,"");
Trans->Destination=CopyStr(Trans->Destination,"");
Trans->ContentType=CopyStr(Trans->ContentType,"");
Trans->ContentBoundary=CopyStr(Trans->ContentBoundary,"");
Trans->UserName=CopyStr(Trans->UserName,"");
Trans->Password=CopyStr(Trans->Password,"");
Trans->AuthType=CopyStr(Trans->AuthType,"");
Trans->Host=CopyStr(Trans->Host,"");
Trans->ClientReferrer=CopyStr(Trans->ClientReferrer,"");
Trans->UserAgent=CopyStr(Trans->UserAgent,"");
Trans->SearchPath=CopyStr(Trans->SearchPath,"");

//Do not clear these values, as 'SessionClear' is only called on persistent
//'HTTP Keep-Alive' sessions
//Trans->Protocol=CopyStr(Trans->Protocol,"");
//Trans->Cipher=CopyStr(Trans->Cipher,"");
//Trans->ClientIP=CopyStr(Trans->ClientIP,"");
//Trans->ClientHost=CopyStr(Trans->ClientHost,"");
//Trans->StartDir=CopyStr(Trans->StartDir,"");
//Trans->HomeDir=CopyStr(Trans->HomeDir,"");
//Trans->RealUser=CopyStr(Trans->RealUser,"");
//Trans->UserSettings=CopyStr(Trans->UserSettings,"");
//Trans->ServerName=CopyStr(Trans->ServerName,"");


ListClear(Trans->Headers,DestroyString);
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

DestroyString(Tempstr);
if (Flags & ERR_EXIT) exit(1);
}


TPathItem *PathItemCreate(int Type, const char *URL, const char *Path)
{
TPathItem *PI=NULL;

PI=(TPathItem *) calloc(1,sizeof(TPathItem));
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

PI=(TPathItem *) pi_ptr;
DestroyString(PI->Path);
DestroyString(PI->URL);
DestroyString(PI->Name);
DestroyString(PI->ContentType);
free(PI);
}




char *FormatURL(char *Buff, HTTPSession *Session, const char *ItemPath)
{
char *Tempstr=NULL, *Quoted=NULL;
const char *ptr=NULL, *sd_ptr;
int len;

if (StrLen(Session->Host))
{
if (Settings.Flags & FLAG_SSL) Tempstr=MCopyStr(Buff,"https://",Session->Host,"/",NULL);
else Tempstr=MCopyStr(Buff,"http://",Session->Host,"/",NULL);
}
else Tempstr=CopyStr(Tempstr,"/");

ptr=ItemPath;
while (*ptr == '/') ptr++;

if (StrLen(Session->StartDir)) sd_ptr=Session->StartDir;
else sd_ptr="";

while (*sd_ptr == '/') sd_ptr++;

len=StrLen(sd_ptr);

if (strncmp(ptr, sd_ptr,len)==0) ptr+=len;
Quoted=HTTPQuoteChars(Quoted,ptr," ()[]{}\t?&%!,+\':;#");

Tempstr=CatStr(Tempstr,Quoted);

DestroyString(Quoted);
return(Tempstr);
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
  ptr=strrchr(RetStr,'/');
  if (ptr) *ptr='\0';
  if (StrLen(RetStr)==0) RetStr=CopyStr(RetStr,"/");
}
RetStr=SlashTerminateDirectoryPath(RetStr);

return(RetStr);
}


char *SessionGetArgument(char *RetBuff, HTTPSession *Session, const char *ReqName)
{
char *Name=NULL, *Value=NULL, *RetStr=NULL, *ptr;

ptr=GetNameValuePair(Session->Arguments, "&", "=", &Name, &Value);
while (ptr)
{
	if (strcasecmp(ReqName,Name)==0) 
	{
		RetStr=HTTPUnQuote(RetBuff,Value);
		break;
	}
ptr=GetNameValuePair(ptr, "&", "=", &Name, &Value);
}

DestroyString(Name);
DestroyString(Value);

return(RetStr);
}


int IsLocalHost(HTTPSession *Session, char *Host)
{
char *ptr;
int len;

if (StrLen(Host)==0) return(TRUE);
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




int CopyLocalItem(char *From, char *To)
{
glob_t Glob;
struct stat FStat;
char *Tempstr=NULL, *ptr;
int i,  RetVal=EFAULT;
STREAM *In=NULL, *Out=NULL;

stat(From,&FStat);
if (S_ISDIR(FStat.st_mode))
{
	mkdir(To,FStat.st_mode);
	Tempstr=MCopyStr(Tempstr, From, "/*", NULL);
	glob(Tempstr, 0, 0, &Glob);
	for (i=0; i < Glob.gl_pathc; i++)
	{
		ptr=strrchr(Glob.gl_pathv[i],'/');
		if (! ptr) ptr=Glob.gl_pathv[i];
		Tempstr=MCopyStr(Tempstr, To, ptr, NULL);
		CopyLocalItem(Glob.gl_pathv[i],Tempstr);
	}
	RetVal=0;
	globfree(&Glob);
}
else
{
	In=STREAMOpenFile(From,SF_RDONLY);
	if (In)
	{
		Out=STREAMOpenFile(To, SF_CREAT| SF_WRONLY | SF_TRUNC);
		if (Out) RetVal=STREAMSendFile(In, Out, 0, SENDFILE_KERNEL | SENDFILE_LOOP);
	}
}

//as In and Out are NULL if not opened, it's safe to close them 
//here as STREAMClose will ignore a NULL argument
STREAMClose(In);
STREAMClose(Out);
DestroyString(Tempstr);

return(RetVal);
}


int CopyURL(HTTPSession *Session, char *From, char *To)
{
char *Tempstr=NULL, *Host=NULL, *PortStr=NULL, *FromPath=NULL, *ToPath=NULL, *User=NULL, *Password=NULL;
int RetVal=EFAULT;
STREAM *In=NULL, *Out=NULL;

ParseURL(To, &Tempstr, &Host, &Tempstr, NULL, NULL, &ToPath, NULL);

if ((access(ToPath,F_OK)==0) && (! (Session->Flags & SESSION_OVERWRITE))) RetVal=EEXIST;

//If the TO Host is local
if (IsLocalHost(Session,Host))
{
  ParseURL(From, &Tempstr, &Host, &PortStr, &User, &Password, &FromPath, NULL);

	if (! IsLocalHost(Session,Host)) 
	{
			In=HTTPGet(From,User,Password);
			if (In) Out=STREAMOpenFile(ToPath,SF_CREAT|SF_WRONLY|SF_TRUNC);
			if (Out) RetVal=STREAMSendFile(In, Out, 0, SENDFILE_KERNEL | SENDFILE_LOOP);
			STREAMClose(In);
			STREAMClose(Out);
	}
	else RetVal=CopyLocalItem(FromPath, ToPath);
}

DestroyString(User);
DestroyString(Password);
DestroyString(Tempstr);
DestroyString(Host);
DestroyString(PortStr);
DestroyString(FromPath);
DestroyString(ToPath);

return(RetVal);
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

#else 

//if libcap is not available try linux-only interface

#include <linux/capability.h>

struct __user_cap_header_struct cap_hdr;
cap_user_data_t cap_values;
unsigned long CapVersions[]={ _LINUX_CAPABILITY_VERSION_3, _LINUX_CAPABILITY_VERSION_2, _LINUX_CAPABILITY_VERSION_1, 0};
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
