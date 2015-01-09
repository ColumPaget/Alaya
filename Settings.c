#include "Settings.h"
#include "Authenticate.h" //(For GetDefaultUser)
#include <sys/utsname.h>
#include <grp.h>


int YesNoTrueFalse(char *String)
{
	if (! StrLen(String)) return(TRUE);
	if (strcasecmp(String,"true")==0) return(TRUE);
	if (strcasecmp(String,"yes")==0) return(TRUE);
	if (strcasecmp(String,"y")==0) return(TRUE);

	return(FALSE);
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


if (Settings->Flags & FLAG_SSL)
{
	ptr=LibUsefulGetValue("SSL-Permitted-Ciphers");
	if (! StrLen(ptr))
	{
		LibUsefulSetValue("SSL-Permitted-Ciphers", "DH+AESGCM:DH+AES256:DH+CAMELLIA256:ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+AES:EDH-RSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:CAMELLIA256:AES128-SHA256:CAMELLIA128:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:DES-CBC3-SHA:!ADH:!AECDH:!aNULL:!eNULL:!LOW:!EXPORT:!MD5");
	}

	ptr=LibUsefulGetValue("SSL_VERIFY_CERTFILE");
	if (! StrLen(ptr)) ptr=LibUsefulGetValue("SSL_VERIFY_CERTDIR");

	if ((Settings->AuthFlags & FLAG_AUTH_CERT_REQUIRED) && (! StrLen(ptr)))
	{
		HandleError(ERR_PRINT|ERR_LOG|ERR_EXIT, "ERROR: Client SSL Certificate required, but no certificate verify file/directory given.\nPlease Supply one with the -verify-path command-line-argument, or the SSLVerifyPath config file entry.");
	}

	ptr=LibUsefulGetValue("SSL-DHParams-File");
	if (! StrLen(ptr))
	{
		HandleError(ERR_PRINT|ERR_LOG, "WARNING: No DH parameters file given for SSL. Perfect Forward Secrecy can only be achieved with Eliptic Curve (ECDH) methods. ECDH depends on fixed values recomended by the U.S. National Institute of Standards and technology (NIST) and thus may not be trustworthy.\n\nCreate a DHParams file with 'openssl dhparam -2 -out dhparams.pem 4096' and give the path to it using the -dhparams command-line-argument or the DHParams config file entry, if you want DiffieHelman key exchange for Perfect Forward Secrecy.");

	}
}

DestroyString(Tempstr);
DestroyString(Token);
}





void ParsePathItem(char *Data)
{
char *PathTypes[]={"Files","Cgi","Stream","Logout","Proxy","MimeIcons",NULL};
char *Type=NULL, *URL=NULL, *Path=NULL, *Tempstr=NULL, *ptr;
TPathItem *PI;
int val;

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
	if (strcasecmp(Token,"MimeIcons")==0) Settings.DirListFlags |= DIR_MIMEICONS;

ptr=GetToken(ptr,",",&Token,0);
}
DestroyString(Token);
}



void ParseEventConfig(char *ConfigLine)
{
char *EventTypeStrings[]={"Method","Path","User","ClientIP","BadURL","Header","ResponseCode",NULL};
char *Token=NULL, *ptr;
ListNode *Node;
int Type;

if (! Settings.Events) Settings.Events=ListCreate();

ptr=GetToken(ConfigLine,":",&Token,0);
Type=MatchTokenFromList(Token,EventTypeStrings,0);
ptr=GetToken(ptr,":",&Token,0);

Node=ListAddNamedItem(Settings.Events,Token,CopyStr(NULL,ptr));
Node->ItemType=Type;

DestroyString(Token);
}


void ParseConfigItem(char *ConfigLine)
{
char *ConfTokens[]={"Chroot","Chshare","Chhome","AllowUsers","DenyUsers","Port","LogFile","AuthPath","BindAddress","LogPasswords","HttpMethods","AuthMethods","DefaultUser","DefaultGroup","SSLKey","SSLCert","SSLCiphers","SSLDHParams","Path","LogVerbose","AuthRealm","Compression","StreamDir","DirListType","DisplayNameLen","MaxLogSize","ScriptHandler","ScriptHashFile","LookupClientName","HostConnections","SanitizeAllowTags","CustomHeader","UserAgentSettings","SSLClientCertificate","SSLVerifyPath","Event","FileCacheTime","HttpKeepAlive","AccessTokenKey","Timezone","MaxMemory","MaxStack",NULL};
typedef enum {CT_CHROOT, CT_CHSHARE, CT_CHHOME, CT_ALLOWUSERS,CT_DENYUSERS,CT_PORT, CT_LOGFILE,CT_AUTHFILE,CT_BINDADDRESS,CT_LOGPASSWORDS,CT_HTTPMETHODS, CT_AUTHMETHODS,CT_DEFAULTUSER, CT_DEFAULTGROUP, CT_SSLKEY, CT_SSLCERT, CT_SSLCIPHERS, CT_SSLDHPARAMS, CT_PATH, CT_LOG_VERBOSE, CT_AUTH_REALM, CT_COMPRESSION, CT_STREAMDIR, CT_DIRTYPE, CT_DISPLAYNAMELEN, CT_MAXLOGSIZE, CT_SCRIPTHANDLER, CT_SCRIPTHASHFILE, CT_LOOKUPCLIENT, CT_HOSTCONNECTIONS, CT_SANITIZEALLOW, CT_CUSTOMHEADER, CT_USERAGENTSETTINGS, CT_CLIENT_CERTIFICATION, CT_SSLVERIFY_PATH, CT_EVENT, CT_FILE_CACHE_TIME, CT_HTTP_KEEP_ALIVE, CT_ACCESS_TOKEN_KEY, CT_TIMEZONE, CT_MAX_MEM, CT_MAX_STACK};

char *Token=NULL, *ptr;
struct group *grent;
struct stat Stat;
int result;


ptr=GetToken(ConfigLine,"=|:",&Token,GETTOKEN_MULTI_SEPARATORS);

StripLeadingWhitespace(Token);
StripTrailingWhitespace(Token);
result=MatchTokenFromList(Token,ConfTokens,0);

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
	
	case CT_SSLCIPHERS:
		LibUsefulSetValue("SSL-Permitted-Ciphers",ptr);
	break;

	case CT_SSLDHPARAMS:
		LibUsefulSetValue("SSL-DHParams-File",ptr);
	break;	

	case CT_AUTH_REALM:
		Settings.AuthRealm=CopyStr(Settings.AuthRealm,ptr);
	break;

	case CT_COMPRESSION:
		if (strcasecmp(ptr,"partial")==0) 
		{
			Settings.Flags &= ~FLAG_COMPRESS;
			Settings.Flags |= FLAG_PARTIAL_COMPRESS;
		}
		else if (! YesNoTrueFalse(ptr)) Settings.Flags &= ~(FLAG_COMPRESS | FLAG_PARTIAL_COMPRESS);
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
		if (YesNoTrueFalse(ptr)) Settings.Flags |= FLAG_LOG_VERBOSE;
		else Settings.Flags &= ~FLAG_LOG_VERBOSE;
	break;

	case CT_MAXLOGSIZE:
		Settings.MaxLogSize = (int) ParseHumanReadableDataQty(ptr, 0);
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
		if (YesNoTrueFalse(ptr)) Settings.Flags |= FLAG_LOOKUP_CLIENT;
		else Settings.Flags &= ~FLAG_LOOKUP_CLIENT;
	break;

	case CT_USERAGENTSETTINGS:
		if (! Settings.UserAgents) Settings.UserAgents=ListCreate();
		ptr=GetToken(ptr,",",&Token,0);
		ListAddNamedItem(Settings.UserAgents,Token,CopyStr(NULL,ptr));
	break;

	case CT_SSLVERIFY_PATH:
		if (stat(ptr,&Stat)==0)
		{
		if (S_ISDIR(Stat.st_mode)) LibUsefulSetValue("SSL_VERIFY_CERTDIR",ptr);
		else if (S_ISREG(Stat.st_mode)) LibUsefulSetValue("SSL_VERIFY_CERTFILE",ptr);
		}
		else HandleError(ERR_PRINT|ERR_LOG|ERR_EXIT, "ERROR: Can't access SSL certificate verify data at '%s'",ptr);
	break;

	case CT_CLIENT_CERTIFICATION:
		if (strcasecmp(ptr,"ask")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_ASK;
		if (strcasecmp(ptr,"required")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_REQUIRED;
		if (strcasecmp(ptr,"sufficient")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_SUFFICIENT;
		if (strcasecmp(ptr,"required+sufficient")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_REQUIRED | FLAG_AUTH_CERT_SUFFICIENT;
	break;

	case CT_EVENT:
		ParseEventConfig(ptr);
	break;

	case CT_FILE_CACHE_TIME:
		Settings.DocumentCacheTime=strtol(ptr,NULL,10);
	break;

	case CT_HTTP_KEEP_ALIVE:
		if (YesNoTrueFalse(ptr)) Settings.Flags |= FLAG_KEEP_ALIVES;
		else Settings.Flags &= ~FLAG_KEEP_ALIVES;
	break;

	case CT_ACCESS_TOKEN_KEY:
		Settings.AccessTokenKey=CopyStr(Settings.AccessTokenKey,ptr);
	break;

	case CT_TIMEZONE:
		Settings.Timezone=CopyStr(Settings.Timezone,ptr);
	break;

	case CT_MAX_MEM:
		Settings.AddressSpace=CopyStr(Settings.AddressSpace,ptr);
	break;

	case CT_MAX_STACK:
		Settings.StackSize=CopyStr(Settings.StackSize,ptr);
	break;
}

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



void HandleUserSetup(char *Operation, int argc, char *argv[])
{
 int i, result;
 char *UserName=NULL, *Password=NULL, *PassType=NULL, *HomeDir=NULL, *RealUser=NULL, *Args=NULL;

	if (strcmp(Operation,"del")==0) PassType=CopyStr(PassType,"delete");
	else PassType=CopyStr(PassType,"sha256");
	HomeDir=CopyStr(HomeDir,"/tmp");
	RealUser=CopyStr(RealUser,GetDefaultUser());
	Password=CopyStr(Password,"");
	Args=CopyStr(Args,"");

 for (i=3; i < argc; i++)
 {
	if (strcmp(argv[i],"-e")==0)
	{
		i++;
		if (strcmp(Operation,"del") !=0) PassType=CopyStr(PassType,argv[i]);
	}
	else if (strcmp(argv[i],"-h")==0)
	{
		i++;
		HomeDir=CopyStr(HomeDir,argv[i]);
	}
	else if (strcmp(argv[i],"-u")==0)
	{
		i++;
		RealUser=CopyStr(RealUser,argv[i]);
	}
	else if (strcmp(argv[i],"-a")==0)
	{
		i++;
		Settings.AuthPath=CopyStr(Settings.AuthPath,argv[i]);
	}
	else if (StrLen(UserName)==0) UserName=CopyStr(UserName,argv[i]);
	else if (StrLen(Password)==0) Password=CopyStr(Password,argv[i]);
	else Args=MCatStr(Args,argv[i]," ",NULL);
 }

	if (strcmp(Operation,"list")==0) ListNativeFile(Settings.AuthPath);
	else if (! StrLen(UserName)) printf("ERROR: NO USERNAME GIVEN\n");
	else if ((strcmp(Operation,"add")==0) && (! StrLen(Password))) printf("ERROR: NO PASSWORD GIVEN\n");
	else 
	{
		result=UpdateNativeFile(Settings.AuthPath, UserName, PassType, Password, HomeDir,RealUser, Args);
		if (result==ERR_FILE) printf("ERROR: Cannot open file '%s'\n",Settings.AuthPath);
	}

 DestroyString(UserName);
 DestroyString(Password);
 DestroyString(PassType);
 DestroyString(RealUser);
 DestroyString(HomeDir);
 DestroyString(Args);

	//Always exit when this is done, don't launch webserver
 exit(0);
}

	

void PrintUsage()
{
fprintf(stdout,"\nAlaya Webdav Server: version %s\n",Version);
fprintf(stdout,"Author: Colum Paget\n");
fprintf(stdout,"Email: colums.projects@gmail.com\n");
fprintf(stdout,"Blog: http://idratherhack.blogspot.com \n");
fprintf(stdout,"Credits: Thanks to Gregor Heuer, Helmut Schmid, and Maurice R Volaski for bug reports.\n");
fprintf(stdout,"\n");

fprintf(stdout,"Usage: alaya [-v] [-d] [-O] [-h] [-p <port>] [-A <auth methods>] [-a <auth file>] [-l <path>]  [-r <path>] [-key <path>] [-cert <path>] [-client-cert <level>] [-verify-path <path>] [-ciphers <cipher list>] [-cgi <path>] [-ep <path>] [-u <default user>] [-g <default group>] [-m <http methods>] [-realm <auth realm>] [-compress <yes|no|partial>] [-cache <seconds>] [-tz <timezone>]\n\n");
fprintf(stdout,"	-v:		Verbose logging.\n");
fprintf(stdout,"	-v -v:		Even more verbose logging.\n");
fprintf(stdout,"	-a:		Specify the authentication file for 'built in' authentication.\n");
fprintf(stdout,"	-A:		Authentication methods. Comma separated list of pam,passwd,shadow,native,accesstoken. For 'Alaya native only' just use 'native' on its own\n");
fprintf(stdout,"	-d:		No daemon, don't background process.\n");
fprintf(stdout,"	-f:		Path to config file, defaults to /etc/alaya.conf, but alaya can be configured by command-line args only.\n");
fprintf(stdout,"	-O:		Open, don't require authentication.\n");
fprintf(stdout,"	-h:		'ChHome mode', switch to users home dir and chroot.\n");
fprintf(stdout,"	-i:		Set interface listen on, allows running separate servers on the same port on different interfaces/network cards.\n");
fprintf(stdout,"	-l:		Path to log file, default is to use 'syslog' instead.\n");
fprintf(stdout,"	-m:		HTTP Methods (GET, PUT, DELETE, PROPFIND) that are allowed.\nComma Separated. Set to 'GET' for very basic webserver, 'GET,PROPFIND' for readonly DAV.\n'BASE' will set GET,POST,HEAD. 'DAV' will set everything needed for WebDAV. 'RGET' will allow proxy-server gets. 'PROXY' will enable CONNECT and RGET. 'DAV,PROXY' enables everything.\n");
fprintf(stdout,"	-p:		Set port to listen on.\n");
fprintf(stdout,"	-tz:		Set server's timezone.\n");
fprintf(stdout,"	-r:		'ChRoot mode', chroot into directory and offer services from it\n");
fprintf(stdout,"	-key:		Keyfile for SSL (HTTPS)\n");
fprintf(stdout,"	-cert:		Certificate for SSL (HTTPS). This can be a certificate chain bundled in .pem format.\n");
fprintf(stdout,"	-ciphers:		List of SSL ciphers to use.\n");
fprintf(stdout,"	-dhparams:	Path to a file containing Diffie Helmann parameters for Perfect Forward Secrecy.\n");
fprintf(stdout,"	-client-cert:		Settings for SSL client certificate authentication. Three levels are available: 'required' means a client MUST supply a certificate, but that it may still be required to log in through normal authentication. 'sufficient' means that a client CAN supply a certificate, and that the certificate is all the authentication that's needed. 'required+sufficient' means that a client MUST provide a certificate, and that this certificate is sufficient for authentication. 'ask' is used at the global level, when 'required' or 'sufficient' is present in the authentication file for a specific user.\n");
fprintf(stdout,"	-verify-path:		Path to a file, or a directory, containing Authority certificates for verifying client certificates.\n");
fprintf(stdout,"	-cgi:		Directory containing cgi programs. These programs will be accessible even though they are outside of a 'chroot'\n");
fprintf(stdout,"	-hashfile:	File containing cryptographic hashes of cgi-scripts. This file contains the output of the md5sum, shasum, sha256sum or sha512sum utilities.\n");
fprintf(stdout,"	-ep:		'External path' containing files that will be accessible even outside a chroot.\n");
fprintf(stdout,"	-u:		User to run cgi-programmes and default 'real user' for any 'native users' that don't have one specified.\n");
fprintf(stdout,"	-g:		Group to run server in (this will be the default group for users)\n");
fprintf(stdout,"	-allowed:		Comma separated list of users allowed to login (default without this switch is 'all users can login'\n");
fprintf(stdout,"	-denied:		Comma separated list of users DENIED login\n");
fprintf(stdout,"	-realm:		Realm for HTTP Authentication\n");
fprintf(stdout,"	-compress:		Compress documents and responses. This can have three values, 'yes', 'no' or 'partial'. 'Partial' means alaya will compress directory listings and other internally genrated pages, but not file downloads.\n");
fprintf(stdout,"	-cache:		Takes an argument in seconds which is the max-age recommended for browser caching. Setting this to zero will turn off caching in the browser. Default is 10 secs.\n");
fprintf(stdout,"\n\nUser Setup for Alaya Authentication\n");
fprintf(stdout,"	Alaya can use PAM, /etc/shadow or /etc/passwd to authenticate, but has its own password file that offers extra features, or is useful to create users who can only use Alaya. Users in the Alaya password file are mapped to a 'real' user on the system (usually 'guest' or 'nobody'). The Alaya password file can be setup through the alaya commandline.\n\n");
fprintf(stdout," Add User: alaya -user add [-a <auth path>] [-e <password encryption type>]  [-h <user home directory>] <Username> <Password> <Setting> <Setting> <Setting>\n\n");
fprintf(stdout,"	-a:		Specify the authentication file for 'built in' authentication.\n");
fprintf(stdout,"	-h:		Specify home directory of new user.\n");
fprintf(stdout,"	-u:		Specify 'real user' that this user maps to.\n");
fprintf(stdout,"	-e:		Specify password encryption type (sha1, sha512, sha256, md5, plain or null).\n");
fprintf(stdout,"				Config file type settings (like 'ChHome' or 'ChRoot=/var/shared' or 'HttpMethods=GET,PUT,PROPFIND' or 'CgiPath=/usr/share/cgi' can be added so that these settings are specific to a user\n\n");

fprintf(stdout," Delete User: alaya -user del [-a <auth path>] <Username>\n\n");
fprintf(stdout," List Users : alaya -user list\n\n");

}



void ParseSettings(int argc, char *argv[], TSettings *Settings)
{
int i;
char *Token=NULL;


if (argc < 2) return;

if (strcmp(argv[1],"-user")==0)
{

	if (strcmp(argv[2],"list")==0) HandleUserSetup("list",argc, argv);
	else if (strcmp(argv[2],"add")==0) HandleUserSetup("add",argc, argv);
	else if (strcmp(argv[2],"del")==0) HandleUserSetup("del",argc, argv);
	else printf("-user must be followed by one of \"add\", \"del\" or \"list\"\n");


		exit(1);
}


for (i=1; i < argc; i++)
{
	if (strcmp(argv[i],"-nodemon")==0) Settings->Flags |= FLAG_NODEMON;
	else if (strcmp(argv[i],"-d")==0) Settings->Flags |= FLAG_NODEMON;
	else if (strcmp(argv[i],"-i")==0) Settings->BindAddress=CopyStr(Settings->BindAddress,argv[++i]);
	else if (strcmp(argv[i],"-a")==0) Settings->AuthPath=CopyStr(Settings->AuthPath,argv[++i]);
	else if (strcmp(argv[i],"-A")==0) Settings->AuthMethods=CopyStr(Settings->AuthMethods,argv[++i]);
	else if (strcmp(argv[i],"-v")==0) 
	{
		if (Settings->Flags & FLAG_LOG_VERBOSE) Settings->Flags |= FLAG_LOG_MORE_VERBOSE;
		Settings->Flags |= FLAG_LOG_VERBOSE;
	}
	else if (strcmp(argv[i],"-f")==0) Settings->ConfigPath=CopyStr(Settings->ConfigPath,argv[++i]);
	else if (strcmp(argv[i],"-l")==0) Settings->LogPath=CopyStr(Settings->LogPath,argv[++i]);
	else if (strcmp(argv[i],"-m")==0) Settings->HttpMethods=CopyStr(Settings->HttpMethods,argv[++i]);
	else if (strcmp(argv[i],"-p")==0) Settings->Port=atoi(argv[++i]);
	else if (strcmp(argv[i],"-O")==0) Settings->AuthFlags &= ~FLAG_AUTH_REQUIRED;
	else if (strcmp(argv[i],"-compress")==0) 
	{
		Token=MCopyStr(Token,"Compression=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-u")==0) 
	{
		Token=MCopyStr(Token,"DefaultUser=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-g")==0) 
	{
		Token=MCopyStr(Token,"DefaultGroup=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-r")==0) 
	{
		Token=MCopyStr(Token,"ChRoot=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-chroot")==0) 
	{
		Token=MCopyStr(Token,"ChRoot=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-h")==0) ParseConfigItem("ChHome");
	else if (strcmp(argv[i],"-chhome")==0) ParseConfigItem("ChHome");
	else if (strcmp(argv[i],"-key")==0) 
	{
		Token=MCopyStr(Token,"SSLKey=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-cert")==0) 
	{
		Token=MCopyStr(Token,"SSLCert=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-dhparams")==0) 
	{
		Token=MCopyStr(Token,"SSLDHParams=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-ciphers")==0) 
	{
		Token=MCopyStr(Token,"SSLCiphers=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-cgi")==0) 
	{
		Token=MCopyStr(Token,"Path=cgi,/cgi-bin/,",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-ep")==0) 
	{
		Token=MCopyStr(Token,"Path=files,,",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-denied")==0) 
	{
		Token=MCopyStr(Token,"DenyUsers=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-allowed")==0) 
	{
		Token=MCopyStr(Token,"AllowUsers=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-realm")==0) 
	{
		Token=MCopyStr(Token,"AuthRealm=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-client-cert")==0) 
	{
		Token=MCopyStr(Token,"SSLClientCertificate=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-verify-path")==0) 
	{
		Token=MCopyStr(Token,"SSLVerifyPath=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-dirtype")==0) 
	{
		Token=MCopyStr(Token,"DirListType=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-hashfile")==0) 
	{
		Token=MCopyStr(Token,"ScriptHashFile=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-cache")==0) Settings->DocumentCacheTime=strtol(argv[++i],NULL,10);
	else if (strcmp(argv[i],"-tz")==0) 
	{
		Token=MCopyStr(Token,"Timezone=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (
						(strcmp(argv[i],"-version")==0) ||
						(strcmp(argv[i],"--version")==0) 
					)
	{
		fprintf(stdout,"version: %s\n",Version); 
		fprintf(stdout,"\nBuilt: %s %s\n",__DATE__,__TIME__);
		fprintf(stdout,"libUseful: Version %s BuildTime: %s\n",LibUsefulGetValue("LibUsefulVersion"), LibUsefulGetValue("LibUsefulBuildTime"));
		if (SSLAvailable()) fprintf(stdout,"SSL Library: %s\n",LibUsefulGetValue("SSL-Library"));
		else fprintf(stdout,"%s\n","SSL Library: None, not compiled with --enable-ssl");

		exit(1);
	}
	else if (strcmp(argv[i],"-clientnames")==0) Settings->Flags |= FLAG_LOOKUP_CLIENT;
	else if (
						(strcmp(argv[i], "-?")==0) ||
						(strcmp(argv[i], "-help")==0) ||
						(strcmp(argv[i], "--help")==0)
					) 
	{
		PrintUsage();
		exit(0);
	}
	else 
	{
		printf("UNKNOWN ARGUMENT: [%s]\n",argv[i]);
		exit(1);
	}
}


}




void InitSettings()
{
time_t Now;
struct utsname UnameData;

//Initialise timezone information, this is so that
//we don't get erratic times in log files from forked
//chrooted processes
time(&Now);
localtime(&Now);
srand(Now+getpid());
SetTimezoneEnv();


uname(&UnameData);
memset(&Settings,0,sizeof(TSettings));
Settings.MaxLogSize=999999;
Settings.LogPath=CopyStr(Settings.LogPath,"SYSLOG");
Settings.ConfigPath=CopyStr(Settings.ConfigPath,"/etc/alaya.conf");
Settings.DefaultDir=CopyStr(Settings.DefaultDir,"./");
Settings.BindAddress=CopyStr(Settings.BindAddress,"");
Settings.AuthFlags=FLAG_AUTH_REQUIRED;
Settings.AuthPath=CopyStr(Settings.AuthPath,"/etc/alaya.auth");
Settings.AuthMethods=CopyStr(Settings.AuthMethods,"native,accesstoken");
Settings.AuthRealm=CopyStr(Settings.AuthRealm,UnameData.nodename);
Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY;
Settings.IndexFiles=CopyStr(Settings.IndexFiles,"index.html,dir.html");
Settings.M3UFileTypes=CopyStr(Settings.M3UFileTypes,".mp3,.ogg,.mp4,.flv,.webm,.m4v,.m4a,.aac");
Settings.ForbiddenURLStrings=CopyStr(Settings.ForbiddenURLStrings,"..,%00,%2e%2e");
Settings.VPaths=ListCreate();
Settings.HostConnections=ListCreate();
Settings.ScriptHandlers=ListCreate();
Settings.LoginEntries=ListCreate();
Settings.DocumentCacheTime=10;
Settings.AddressSpace=CopyStr(Settings.AddressSpace, "50M");
Settings.StackSize=CopyStr(Settings.StackSize, "500k");

GenerateRandomBytes(&Settings.AccessTokenKey,32,ENCODE_BASE64);
//this will be set to 80 or 443 in 'PostProcessSettings'
Settings.Port=0;

}



void ReadConfigFile(TSettings *Settings)
{
STREAM *S;
char *Tempstr=NULL;


S=STREAMOpenFile(Settings->ConfigPath,O_RDONLY);
if (S)
{
Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
	StripLeadingWhitespace(Tempstr);
	StripTrailingWhitespace(Tempstr);
	if (StrLen(Tempstr)) ParseConfigItem(Tempstr);
	Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);
}

DestroyString(Tempstr);
}

