#include "common.h"
#include "server.h"
#include "grp.h"

//for 'get default user'
#include "Authenticate.h"

TSettings Settings;
char *Version="1.2.0";


TPathItem *PathItemCreate(int Type, char *URL, char *Path)
{
TPathItem *PI=NULL;

PI=(TPathItem *) calloc(1,sizeof(TPathItem));
PI->Type=Type;
PI->Path=CopyStr(PI->Path,Path);
PI->Name=CopyStr(PI->Name,GetBasename(Path));
PI->URL=CopyStr(PI->URL,URL);
return(PI);
}

void PathItemDestroy(void *pi_ptr)
{
TPathItem *PI;

PI=(TPathItem *) pi_ptr;
DestroyString(PI->Path);
DestroyString(PI->URL);
DestroyString(PI->Name);
free(PI);
}


void ParsePathItem(char *Data)
{
char *Type=NULL, *URL=NULL, *Path=NULL, *Tempstr=NULL, *ptr;
TPathItem *PI;
int val;
char *PathTypes[]={"Files","Cgi","Stream","Logout","Proxy",NULL};

ptr=GetToken(Data,",",&Type,0);

val=MatchTokenFromList(Type,PathTypes,0);
if (val > -1)
{
	ptr=GetToken(ptr,",",&Tempstr,0);

	StripLeadingWhitespace(Tempstr);
	if (*Tempstr !='/') URL=MCopyStr(URL,"/",Tempstr,NULL);
	else URL=CopyStr(URL,Tempstr);
	
	PI=PathItemCreate(val, URL, ptr);
	if (PI->Type==PATHTYPE_LOGOUT) Settings.Flags |= FLAG_LOGOUT_AVAILABLE;
	ListAddNamedItem(Settings.VPaths,PI->URL,PI);
}
else LogToFile(Settings.LogPath,"ERROR: Unknown Path type '%s' in Config File",Type);


DestroyString(Tempstr);
DestroyString(Type);
DestroyString(Path);
DestroyString(URL);
}

void ParseDirListType(char *Data)
{
char *Token=NULL, *ptr;

Settings.DirListFlags=DIR_REJECT;

ptr=GetToken(Data,",",&Token,0);
while (ptr)
{
	StripLeadingWhitespace(Token);
	StripTrailingWhitespace(Token);
	if (strcasecmp(Token,"None")==0) Settings.DirListFlags=DIR_REJECT;
	if (strcasecmp(Token,"Basic")==0) Settings.DirListFlags=DIR_SHOWFILES;
	if (strcasecmp(Token,"Fancy")==0) Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY;
	if (strcasecmp(Token,"Interactive")==0) Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY | DIR_INTERACTIVE;
	if (strcasecmp(Token,"Full")==0) Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY | DIR_INTERACTIVE | DIR_MEDIA_EXT | DIR_SHOW_VPATHS | DIR_TARBALLS;

	if (strcasecmp(Token,"Media")==0) Settings.DirListFlags |= DIR_MEDIA_EXT;
	if (strcasecmp(Token,"IndexPages")==0) Settings.DirListFlags |= DIR_INDEX_FILES;
	if (strcasecmp(Token,"ShowVPaths")==0) Settings.DirListFlags |= DIR_SHOW_VPATHS;
	if (strcasecmp(Token,"TarDownloads")==0) Settings.DirListFlags |= DIR_TARBALLS;
ptr=GetToken(ptr,",",&Token,0);
}

DestroyString(Token);
}


void ParseConfigItem(char *ConfigLine)
{
char *ConfTokens[]={"Chroot","Chshare","Chhome","AllowUsers","DenyUsers","Port","LogFile","AuthPath","BindAddress","LogPasswords","HttpMethods","AuthMethods","DefaultUser","DefaultGroup","SSLKey","SSLCert","Path","LogVerbose","AuthRealm","Compression","StreamDir","DirListType","DisplayNameLen","MaxLogSize","ScriptHandler","ScriptHashFile","LookupClientName","HostConnections","SanitizeAllowTags","CustomHeader","UserAgentSettings",NULL};
typedef enum {CT_CHROOT, CT_CHSHARE, CT_CHHOME, CT_ALLOWUSERS,CT_DENYUSERS,CT_PORT, CT_LOGFILE,CT_AUTHFILE,CT_BINDADDRESS,CT_LOGPASSWORDS,CT_HTTPMETHODS, CT_AUTHMETHODS,CT_DEFAULTUSER,CT_DEFAULTGROUP,CT_SSLKEY,CT_SSLCERT,CT_PATH, CT_LOG_VERBOSE,CT_AUTH_REALM, CT_COMPRESSION, CT_STREAMDIR, CT_DIRTYPE, CT_DISPLAYNAMELEN, CT_MAXLOGSIZE, CT_SCRIPTHANDLER, CT_SCRIPTHASHFILE, CT_LOOKUPCLIENT, CT_HOSTCONNECTIONS, CT_SANITIZEALLOW, CT_CUSTOMHEADER, CT_USERAGENTSETTINGS};

char *Token=NULL, *ptr;
struct group *grent;
int result;


ptr=GetToken(ConfigLine,"=|:",&Token,GETTOKEN_MULTI_SEPARATORS);
StripLeadingWhitespace(Token);
StripTrailingWhitespace(Token);
result=MatchTokenFromList(Token,ConfTokens,0);

if (ptr)
{
 StripLeadingWhitespace(ptr);
 StripTrailingWhitespace(ptr);
}

switch(result)
{
	case CT_PORT:
		Settings.Port=atoi(ptr);
	break;

	case CT_CHROOT:
		Settings.Flags &= ~FLAG_CHHOME;
		Settings.Flags |= FLAG_CHROOT;
		Settings.DefaultDir=CopyStr(Settings.DefaultDir,ptr);
	break;

	case CT_CHHOME:
		Settings.Flags &= ~FLAG_CHROOT;
		Settings.Flags|=FLAG_CHHOME;
	break;

	case CT_ALLOWUSERS:
		Settings.AllowUsers=CopyStr(Settings.AllowUsers,ptr);
	break;

	case CT_DENYUSERS:
		Settings.DenyUsers=CopyStr(Settings.DenyUsers,ptr);
	break;

	case CT_AUTHFILE:
		Settings.AuthPath=CopyStr(Settings.AuthPath,ptr);
	break;

	case CT_BINDADDRESS:
		Settings.BindAddress=CopyStr(Settings.BindAddress,ptr);
	break;

	case CT_LOGPASSWORDS:
		//	Settings.Flags |= FLAG_LOGPASSWORDS;
	break;

	case CT_DISPLAYNAMELEN:
		Settings.DisplayNameLen=atoi(ptr);
	break;

	case CT_AUTHMETHODS:
		Settings.AuthMethods=CopyStr(Settings.AuthMethods,ptr);
	break;

	case CT_HTTPMETHODS:
		Settings.HttpMethods=CopyStr(Settings.HttpMethods,ptr);
	break;

	case CT_DEFAULTUSER:
		Settings.DefaultUser=CopyStr(Settings.DefaultUser,ptr);
		Settings.CgiUser=CopyStr(Settings.CgiUser,ptr);
	break;

	case CT_DEFAULTGROUP:
		Settings.DefaultGroup=CopyStr(Settings.DefaultGroup,ptr);
    grent=getgrnam(ptr);
    if (grent) Settings.DefaultGroupID=grent->gr_gid;
	break;

	case CT_SSLKEY:
		if (! Settings.SSLKeys) Settings.SSLKeys=ListCreate();
		Token=FormatStr(Token,"SSL_KEY_FILE:%d",ListSize(Settings.SSLKeys));
		ListAddNamedItem(Settings.SSLKeys,Token,CopyStr(NULL,ptr));
		Settings.Flags |=FLAG_SSL;
	break;

	case CT_SSLCERT:
		if (! Settings.SSLKeys) Settings.SSLKeys=ListCreate();
		Token=FormatStr(Token,"SSL_CERT_FILE:%d",ListSize(Settings.SSLKeys));
		ListAddNamedItem(Settings.SSLKeys,Token,CopyStr(NULL,ptr));
		Settings.Flags |=FLAG_SSL;
	break;
	

	case CT_AUTH_REALM:
		Settings.AuthRealm=CopyStr(Settings.AuthRealm,ptr);
	break;

	case CT_COMPRESSION:
		if (strcasecmp(ptr,"no")==0) Settings.Flags &= ~(FLAG_COMPRESS | FLAG_PARTIAL_COMPRESS);
		else if (strcasecmp(ptr,"partial")==0) 
		{
			Settings.Flags &= ~FLAG_COMPRESS;
			Settings.Flags |= FLAG_PARTIAL_COMPRESS;
		}
		else
		{
			Settings.Flags &= ~FLAG_PARTIAL_COMPRESS;
			Settings.Flags |= FLAG_COMPRESS;
		}
	break;


	case CT_PATH:
		ParsePathItem(ptr);
	break;

	case CT_DIRTYPE:
		ParseDirListType(ptr);
	break;

	case CT_LOGFILE:
		Settings.LogPath=CopyStr(Settings.LogPath,ptr);
	break;

	case CT_LOG_VERBOSE:
		Settings.Flags |= FLAG_LOG_VERBOSE;
	break;

	case CT_MAXLOGSIZE:
		Settings.MaxLogSize = atoi(ptr);
	break;

  case CT_SCRIPTHANDLER:
    ptr=GetToken(ptr,"=",&Token,0);
    if (! Settings.ScriptHandlers) Settings.ScriptHandlers=ListCreate();
    SetVar(Settings.ScriptHandlers,Token,ptr);
  break;

	case CT_SCRIPTHASHFILE:
		Settings.ScriptHashFile=CopyStr(Settings.ScriptHashFile,ptr);
		Settings.Flags |= FLAG_CHECK_SCRIPTS;
	break;

	case CT_SANITIZEALLOW:
		if (! Settings.SanitizeArgumentsAllowedTags) Settings.SanitizeArgumentsAllowedTags=ListCreate();
		ptr=GetToken(ptr,",",&Token,0);
		while (ptr)
		{
			SetVar(Settings.SanitizeArgumentsAllowedTags,Token,"Y");
			ptr=GetToken(ptr,",",&Token,0);
		}
	break;

	case CT_CUSTOMHEADER:
		if (! Settings.CustomHeaders) Settings.CustomHeaders=ListCreate();
		ptr=GetToken(ptr,":",&Token,0);
		ListAddNamedItem(Settings.CustomHeaders,Token,CopyStr(NULL,ptr));
	break;

	case CT_LOOKUPCLIENT:
		Settings.Flags |= FLAG_LOOKUP_CLIENT;
	break;

	case CT_USERAGENTSETTINGS:
		if (! Settings.UserAgents) Settings.UserAgents=ListCreate();
		ptr=GetToken(ptr,",",&Token,0);
		ListAddNamedItem(Settings.UserAgents,Token,CopyStr(NULL,ptr));
	break;

}

DestroyString(Token);
}


void PostProcessSettings(TSettings *Settings)
{
char *Tempstr=NULL, *Token=NULL, *ptr;

if (StrLen(Settings->DefaultUser)==0) Settings->DefaultUser=CopyStr(Settings->DefaultUser,GetDefaultUser());
if (StrLen(Settings->CgiUser)==0) Settings->CgiUser=CopyStr(Settings->CgiUser,Settings->DefaultUser);

LogToFile(Settings->LogPath, "Default User: %s %s\n",Settings->DefaultUser,Settings->CgiUser);

Tempstr=CopyStr(Tempstr,"");
ptr=GetToken(Settings->HttpMethods,",",&Token,0);
while (ptr)
{
if (strcmp(Token,"BASE")==0) Tempstr=CatStr(Tempstr,"GET,POST,HEAD,OPTIONS,");
else if (strcmp(Token,"DAV")==0) Tempstr=CatStr(Tempstr,"GET,POST,HEAD,OPTIONS,DELETE,MKCOL,MOVE,COPY,PUT,PROPFIND,PROPPATCH,");
else if (strcmp(Token,"PROXY")==0) Tempstr=CatStr(Tempstr,"CONNECT,RGET,RPOST");
else Tempstr=MCatStr(Tempstr,Token,",",NULL);

ptr=GetToken(ptr,",",&Token,0);
}

Settings->HttpMethods=CopyStr(Settings->HttpMethods,Tempstr);

AuthenticateExamineMethods(Settings->AuthMethods);

if (Settings->Port < 1)
{
  if (Settings->Flags & FLAG_SSL) Settings->Port=443;
  else Settings->Port=80;
}


DestroyString(Tempstr);
DestroyString(Token);
}


void ParseConfigItemList(const char *ConfigItemList)
{
char *Tempstr=NULL, *ptr;

    if (StrLen(ConfigItemList))
    {
      ptr=GetToken(ConfigItemList,"\\S",&Tempstr,0);
      while (ptr)
      {
        ParseConfigItem(Tempstr);
        ptr=GetToken(ptr,"\\S",&Tempstr,0);
      }
    }

PostProcessSettings(&Settings);

DestroyString(Tempstr);
}



char *FormatURL(char *Buff, HTTPSession *Session, char *ItemPath)
{
char *Tempstr=NULL, *Quoted=NULL, *ptr=NULL, *sd_ptr;
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
Quoted=HTTPQuoteChars(Quoted,ptr," ()[]{}\t?&!,+\':;#");

Tempstr=CatStr(Tempstr,Quoted);

DestroyString(Quoted);
return(Tempstr);
}



char *MakeAccessToken(char *Buffer, char *Salt, char *Method, char *RequestingHost, char *RequestURL)
{
char *Tempstr=NULL, *RetStr=NULL;



Tempstr=MCopyStr(Tempstr,Salt,":",Method,":",RequestingHost,":",RequestURL,NULL);

RetStr=CopyStr(Buffer,"");

HashBytes(&RetStr,"sha1",Tempstr,StrLen(Tempstr),ENCODE_HEX);

DestroyString(Tempstr);

return(RetStr);
}




char *ParentDirectory(char *RetBuff, char *Path)
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


char *SessionGetArgument(char *RetBuff, HTTPSession *Session, char *ReqName)
{
char *Name=NULL, *Value=NULL, *RetStr=NULL, *ptr;

ptr=GetNameValuePair(Session->Arguments, "&", "=", &Name, &Value);
while (ptr)
{
	if (strcasecmp(ReqName,Name)==0) 
	{
		RetStr=CopyStr(RetBuff,Value);
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
int i, RetVal=EFAULT;
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
	In=STREAMOpenFile(From,O_RDONLY);
	if (In)
	{
		Out=STREAMOpenFile(To, O_CREAT| O_WRONLY | O_TRUNC);
		if (Out) RetVal=STREAMSendFile(In, Out, 0);
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
char *Tempstr=NULL, *Host=NULL, *PortStr=NULL, *FromPath=NULL, *ToPath=NULL, *User=NULL, *Password=NULL, *ptr;
int RetVal=EFAULT, result, i;
STREAM *In=NULL, *Out=NULL;

ParseURL(To, &Tempstr, &Host, &Tempstr, NULL, NULL, &ToPath, NULL);

if ((access(ToPath,F_OK)==0) && (! (Session->Flags & HTTP_OVERWRITE))) RetVal=EEXIST;

//If the TO Host is local
if (IsLocalHost(Session,Host))
{
  ParseURL(From, &Tempstr, &Host, &PortStr, &User, &Password, &FromPath, NULL);

	if (! IsLocalHost(Session,Host)) 
	{
			In=HTTPGet(From,User,Password);
			if (In) Out=STREAMOpenFile(ToPath,O_CREAT|O_WRONLY|O_TRUNC);
			if (Out) RetVal=STREAMSendFile(In, Out, 0);
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




void DropCapabilities(int Level)
{
#ifdef USE_LINUX_CAPABILITIES

//use portable 'libcap' interface if it's available
#ifdef HAVE_LIBCAP
#include <sys/capability.h>

#define CAPSET_SIZE 10
int CapSet[CAPSET_SIZE];
int NumCapsSet=0, i;
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

if (Level < CAPS_LEVEL_CHROOTED) val |= (1 << CAP_SYS_CHROOT);

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
