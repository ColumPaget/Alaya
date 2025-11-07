#include "Authenticate.h" //(For GetDefaultUser)
#include "VPath.h" //For VPathParse
#include <sys/utsname.h>
#include <grp.h>




void PostProcessSettings(TSettings *Settings)
{
    char *Tempstr=NULL, *Token=NULL;
    const char *ptr;

    if (StrLen(Settings->DefaultUser)==0) Settings->DefaultUser=CopyStr(Settings->DefaultUser,GetDefaultUser());

//this seems odd, but it will generate a blank bind address in ServiceSocketsInit in main.c.
//if Settings->BindAddress is completely empty nothing will be bound, but if it has one blank option
//then the default 'bind all tcp addresses' action will be carried out
    if (StrLen(Settings->BindAddress)==0) Settings->BindAddress=CopyStr(Settings->BindAddress, ",");

    Tempstr=CopyStr(Tempstr,"");
    ptr=GetToken(Settings->HttpMethods,",",&Token,0);
    while (ptr)
    {
        if (strcmp(Token,"BASE")==0) Tempstr=CatStr(Tempstr,"GET,POST,HEAD,OPTIONS,");
        else if (strcmp(Token,"DAV")==0) Tempstr=CatStr(Tempstr,"GET,POST,HEAD,OPTIONS,DELETE,MKCOL,MOVE,COPY,PUT,PROPFIND,PROPPATCH,");
        else if (strcmp(Token,"PROXY")==0) Tempstr=CatStr(Tempstr,"CONNECT,RGET,RPOST,SOCKS");
        else Tempstr=MCatStr(Tempstr,Token,",",NULL);

        ptr=GetToken(ptr,",",&Token,0);
    }

    Settings->HttpMethods=CopyStr(Settings->HttpMethods,Tempstr);

    AuthenticateExamineMethods(Settings->AuthMethods, TRUE);

    if (Settings->Port < 1)
    {
        if (Settings->Flags & FLAG_SSL) Settings->Port=443;
        else Settings->Port=80;
    }

    Destroy(Tempstr);
    Destroy(Token);
}





static void ParseDirListType(const char *Data)
{
    char *Token=NULL;
    const char *ptr;

    Settings.DirListFlags=0;

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
    Destroy(Token);
}



static void ParseEventConfig(const char *ConfigLine)
{
    const char *EventTypeStrings[]= {"Method","Path","User","ClientIP","BadURL","Header","ResponseCode","Upload","Auth",NULL};
    char *Token=NULL;
    const char *ptr;
    ListNode *Node;
    int Type;

    if (! Settings.Events) Settings.Events=ListCreate();

    ptr=GetToken(ConfigLine,":",&Token,0);
    Type=MatchTokenFromList(Token,EventTypeStrings,0);
    ptr=GetToken(ptr,":",&Token,0);

    Node=ListAddNamedItem(Settings.Events,Token,CopyStr(NULL,ptr));
    Node->ItemType=Type;

    Destroy(Token);
}


//Parse a list of packing formats and their associated commands so we can offer the user
//'download as zip' in the directory webpage
static char *ParsePackFormats(char *RetStr, const char *Config)
{
    char *Name=NULL, *Value=NULL;
    char *Path=NULL;
    const char *ptr;
    char *tptr;

    RetStr=CopyStr(RetStr, "");
    ptr=GetNameValuePair(Config,  ", ", ":", &Name, &Value);
    while (ptr)
    {
        if (StrLen(Name) && StrLen(Value))
        {
            if (strcasecmp(Value, "internal")==0) RetStr=MCatStr(RetStr, Name, ":", Value, ", ", NULL);
            else
            {
                tptr=strchr(Value, ' ');
                if (tptr)
                {
                    StrTrunc(Value,  tptr-Value);
                    tptr++;
                }
                //we don't want this to be null if strchr returns a null,  otherwise it will
                //shorten our sting when we use MCatStr below.
                else tptr="";

                Path=FindFileInPath(Path, Value, getenv("PATH"));
                if (StrLen(Path)) RetStr=MCatStr(RetStr, Name, ":", Path, " ",  tptr,  ", ", NULL);
            }
        }
        ptr=GetNameValuePair(ptr, ", ", ":", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Path);

    return(RetStr);
}


static void SettingsParseProxyConf(int Allow, const char *Config)
{
    char *URL=NULL, *Token=NULL;
    const char *ptr;

    ptr=GetToken(Config, "\\S", &URL, 0);
    while (ptr != NULL)
    {
        if (! Settings.ProxyConfig) Settings.ProxyConfig=ListCreate();
        ListAddTypedItem(Settings.ProxyConfig, Allow, URL, CopyStr(NULL, ptr));
        ptr=GetToken(ptr, "\\S", &URL, 0);
    }

    Destroy(Token);
    Destroy(URL);
}

void ParseConfigItem(const char *ConfigLine)
{
    const char *ConfTokens[]= {"include","Chroot","Chhome","AllowUsers","DenyUsers","Port","LogFile","PidFilePath","AuthPath","BindAddress","LogPasswords","HttpMethods","AuthMethods","DefaultUser","DefaultGroup","Path","FileType","LogVerbose","AuthRealm","Compression","DirListType","DisplayNameLen","MaxLogSize","ScriptHandler","ScriptHashFile","WebsocketHandler","LookupClientName","SanitizeAllowTags","CustomHeader","UserAgentSettings",
                               "SSLKey","SSLCert","SSLCiphers","SSLDHParams","SSLClientCertificate","SSLVerifyPath", "SSLVersion",
                               "Event","FileCacheTime","HttpKeepAlive","AccessTokenKey","UrlTokenKey","Timezone","MaxMemory","MaxStack","ActivityTimeout","PackFormats","Admin","AllowProxy", "DenyProxy", "UseNamespaces", "ReusePort", "TCPFastOpen","ListenQueue","PFS","PerfectForwardSecrecy","AllowSU", "URLShortener","URLShort","ServerTTL","AllowIPs",
                               NULL
                              };
    typedef enum {CT_INCLUDE,CT_CHROOT, CT_CHHOME, CT_ALLOWUSERS,CT_DENYUSERS,CT_PORT, CT_LOGFILE, CT_PIDFILE, CT_AUTHFILE,CT_BINDADDRESS,CT_LOGPASSWORDS,CT_HTTPMETHODS, CT_AUTHMETHODS,CT_DEFAULTUSER, CT_DEFAULTGROUP, CT_PATH, CT_FILETYPE, CT_LOG_VERBOSE, CT_AUTH_REALM, CT_COMPRESSION, CT_DIRTYPE, CT_DISPLAYNAMELEN, CT_MAXLOGSIZE, CT_SCRIPTHANDLER, CT_SCRIPTHASHFILE, CT_WEBSOCKETHANDLER, CT_LOOKUPCLIENT, CT_SANITIZEALLOW, CT_CUSTOMHEADER, CT_USERAGENTSETTINGS, CT_SSLKEY, CT_SSLCERT, CT_SSLCIPHERS, CT_SSLDHPARAMS, CT_CLIENT_CERTIFICATION, CT_SSLVERIFY_PATH, CT_SSL_VERSION, CT_EVENT, CT_FILE_CACHE_TIME, CT_SESSION_KEEPALIVE, CT_ACCESS_TOKEN_KEY, CT_URL_TOKEN_KEY, CT_TIMEZONE, CT_MAX_MEM, CT_MAX_STACK, CT_ACTIVITY_TIMEOUT, CT_ARCHIVE_FORMATS, CT_ADMIN, CT_ALLOWPROXY, CT_DENYPROXY, CT_USE_NAMESPACES, CT_REUSE_PORT, CT_FAST_OPEN, CT_LISTEN_QUEUE, CT_SSL_PFS, CT_SSL_PERFECT_FORWARD_SECRECY, CT_ALLOW_SU, CT_URL_SHORT, CT_URL_SHORT2, CT_TCP_TTL, CT_ALLOW_IPS} TConfigTokens;

    char *Token=NULL;
    const char *ptr;
    struct group *grent;
    struct stat Stat;
    TConfigTokens TokType;


    ptr=GetToken(ConfigLine,"=|:",&Token,GETTOKEN_MULTI_SEPARATORS);

    StripLeadingWhitespace(Token);
    StripTrailingWhitespace(Token);
    TokType=MatchTokenFromList(Token,ConfTokens,0);

    switch(TokType)
    {
    case CT_INCLUDE:
        ReadConfigFile(ptr);
        break;

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

    case CT_ALLOW_IPS:
        Settings.AllowIPs=CopyStr(Settings.AllowIPs,ptr);
        break;

    case CT_AUTHFILE:
        Settings.AuthPath=CopyStr(Settings.AuthPath,ptr);
        break;

    case CT_BINDADDRESS:
        Settings.BindAddress=CopyStr(Settings.BindAddress,ptr);
        break;

    case CT_LOGPASSWORDS:
        //Settings.Flags |= FLAG_LOGPASSWORDS;
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
        break;

    case CT_DEFAULTGROUP:
        Settings.DefaultGroup=CopyStr(Settings.DefaultGroup,ptr);
        grent=getgrnam(ptr);
        if (grent) Settings.DefaultGroupID=grent->gr_gid;
        break;

    case CT_SSLKEY:
        if (! Settings.SSLKeys) Settings.SSLKeys=ListCreate();
        ListAddNamedItem(Settings.SSLKeys,"SSL:KeyFile",CopyStr(NULL,ptr));
        Settings.Flags |=FLAG_SSL;
        break;

    case CT_SSLCERT:
        if (! Settings.SSLKeys) Settings.SSLKeys=ListCreate();
        ListAddNamedItem(Settings.SSLKeys,"SSL:CertFile",CopyStr(NULL,ptr));
        Settings.Flags |=FLAG_SSL;
        break;

    case CT_SSL_PFS:
    case CT_SSL_PERFECT_FORWARD_SECRECY:
        if (strtobool(ptr)) Settings.Flags |= FLAG_SSL_PFS | FLAG_PFS_GENERATE;
        break;

    case CT_SSLCIPHERS:
        LibUsefulSetValue("SSL:PermittedCiphers",ptr);
        break;

    case CT_SSLDHPARAMS:
        LibUsefulSetValue("SSL:DHParamsFile",ptr);
        Settings.Flags |= FLAG_SSL_PFS;
        break;

    case CT_SSL_VERSION:
        LibUsefulSetValue("SSL:Level",ptr);
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
        else if (! strtobool(ptr)) Settings.Flags &= ~(FLAG_COMPRESS | FLAG_PARTIAL_COMPRESS);
        else
        {
            Settings.Flags &= ~FLAG_PARTIAL_COMPRESS;
            Settings.Flags |= FLAG_COMPRESS;
        }
        break;

    case CT_PATH:
        ptr=GetToken(ptr,",",&Token,0);
        VPathParse(Settings.VPaths, Token, ptr);
        break;

    case CT_FILETYPE:
        VPathParse(Settings.VPaths, Token, ptr);
        break;

    case CT_DIRTYPE:
        ParseDirListType(ptr);
        break;

    case CT_LOGFILE:
        Settings.LogPath=CopyStr(Settings.LogPath,ptr);
        break;

    case CT_PIDFILE:
        Settings.PidFilePath=CopyStr(Settings.PidFilePath,ptr);
        break;

    case CT_LOG_VERBOSE:
        if (strtobool(ptr)) Settings.Flags |= FLAG_LOG_VERBOSE;
        else Settings.Flags &= ~FLAG_LOG_VERBOSE;
        break;

    case CT_MAXLOGSIZE:
        Settings.MaxLogSize = (int) FromMetric(ptr, 0);
        break;

    case CT_SCRIPTHANDLER:
        ptr=GetToken(ptr,"=",&Token,0);
        if (! Settings.ScriptHandlers) Settings.ScriptHandlers=ListCreate();
        SetTypedVar(Settings.ScriptHandlers,Token,ptr,PATHTYPE_CGI);
        break;

    case CT_SCRIPTHASHFILE:
        Settings.ScriptHashFile=CopyStr(Settings.ScriptHashFile,ptr);
        Settings.Flags |= FLAG_CHECK_SCRIPTS;
        break;

    case CT_WEBSOCKETHANDLER:
        if (! Settings.ScriptHandlers) Settings.ScriptHandlers=ListCreate();
        ptr=GetToken(ptr,"=",&Token,0);
        SetTypedVar(Settings.ScriptHandlers,Token,ptr,PATHTYPE_WEBSOCKET);
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
        if (strtobool(ptr)) Settings.Flags |= FLAG_LOOKUP_CLIENT;
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
            if (S_ISDIR(Stat.st_mode)) LibUsefulSetValue("SSL:VerifyCertdir",ptr);
            else if (S_ISREG(Stat.st_mode)) LibUsefulSetValue("SSL:VerifyCertfile",ptr);
        }
        else HandleError(ERR_PRINT|ERR_LOG|ERR_EXIT, "ERROR: Can't access SSL certificate verify data at '%s'",ptr);
        break;

    case CT_CLIENT_CERTIFICATION:
        if (strcasecmp(ptr,"ask")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_ASK;
        if (strcasecmp(ptr,"required")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_REQUIRED;
        if (strcasecmp(ptr,"sufficient")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_SUFFICIENT;
        if (strcasecmp(ptr,"optional")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_SUFFICIENT;
        if (strcasecmp(ptr,"required+sufficient")==0) Settings.AuthFlags |= FLAG_AUTH_CERT_REQUIRED | FLAG_AUTH_CERT_SUFFICIENT;
        break;

    case CT_EVENT:
        ParseEventConfig(ptr);
        break;

    case CT_FILE_CACHE_TIME:
        Settings.DocumentCacheTime=strtol(ptr,NULL,10);
        break;

    case CT_SESSION_KEEPALIVE:
        if (strtobool(ptr)) Settings.Flags |= FLAG_KEEPALIVES;
        else Settings.Flags &= ~FLAG_KEEPALIVES;
        break;

    case CT_ACCESS_TOKEN_KEY:
        Settings.AccessTokenKey=CopyStr(Settings.AccessTokenKey,ptr);
        break;

    case CT_URL_TOKEN_KEY:
        Settings.URLTokenKey=CopyStr(Settings.URLTokenKey,ptr);
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

    case CT_ACTIVITY_TIMEOUT:
        Settings.ActivityTimeout=atoi(ptr);
        break;

    case CT_LISTEN_QUEUE:
        Settings.ListenQueueLen=atoi(ptr);
        break;

    case CT_ARCHIVE_FORMATS:
        Settings.PackFormats=ParsePackFormats(Settings.PackFormats, ptr);
        break;

    case CT_ADMIN:
        Settings.AuthFlags |= FLAG_AUTH_ADMIN;
        break;

    case CT_ALLOWPROXY:
        SettingsParseProxyConf(TRUE, ptr);
        break;

    case CT_DENYPROXY:
        SettingsParseProxyConf(FALSE, ptr);
        break;

    case CT_USE_NAMESPACES:
        if (strtobool(ptr)) Settings.Flags |= FLAG_USE_UNSHARE;
        else Settings.Flags &= ~FLAG_USE_UNSHARE;
        break;

    case CT_REUSE_PORT:
        if (strtobool(ptr)) Settings.Flags |= FLAG_USE_REUSEPORT;
        else Settings.Flags &= ~FLAG_USE_REUSEPORT;
        break;

    case CT_FAST_OPEN:
        if (strcasecmp(ptr, "https")==0) Settings.Flags |= FLAG_USE_HTTPS_FASTOPEN;
        else if (strtobool(ptr)) Settings.Flags |= FLAG_USE_FASTOPEN;
        else Settings.Flags &= ~(FLAG_USE_FASTOPEN | FLAG_USE_HTTPS_FASTOPEN);
        break;

    case CT_ALLOW_SU:
        Settings.Flags |= FLAG_ALLOW_SU;
        break;

    case CT_URL_SHORT:
    case CT_URL_SHORT2:
        Settings.URLShortner=CopyStr(Settings.URLShortner, ptr);
        break;


    case CT_TCP_TTL:
        Settings.TTL=atoi(ptr);
        if (Settings.TTL > 255) Settings.TTL=255;
        if (Settings.TTL < 0) Settings.TTL=0;
        break;
    }

    Destroy(Token);
}



void ParseConfigItemList(const char *ConfigItemList)
{
    char *Tempstr=NULL;
    const char *ptr;

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

    Destroy(Tempstr);
}



void PostProcessUserSetup(const char *Operation, const char *PassType,  const char *UserName, const char *Password, const char *HomeDir, const char *RealUser, const char *Args)
{
char *Path=NULL;
const char *ptr;
int result;


    if (strcmp(Operation,"list")==0) AuthNativeListUsers(Settings.AuthPath);
    else if (! StrLen(UserName)) printf("ERROR: NO USERNAME GIVEN\n");
    else if (strchr(UserName, ':')) printf("ERROR: The ':' character is not allowed in usernames as it is used for various purposes. Sorry.\n");
    else if ((strcmp(Operation,"add")==0) && (! StrLen(Password))) printf("ERROR: NO PASSWORD GIVEN\n");
    else
    {
        ptr=GetToken(Settings.AuthPath, ":", &Path, 0);
        while (ptr)
        {
            result=AuthNativeChange(Path, UserName, PassType, Password, HomeDir, RealUser, Args);
            if (result==ERR_FILE) printf("ERROR: Cannot open file '%s'\n", Path);
            else break;
            ptr=GetToken(ptr, ":", &Path, 0);
        }
    }

Destroy(Path);
}


void HandleUserSetup(const char *Operation, CMDLINE *CMD)
{
    int i, result;
    char *UserName=NULL, *Password=NULL, *PassType=NULL, *HomeDir=NULL, *RealUser=NULL, *Args=NULL, *Path=NULL;
    const char *ptr, *p_arg;

    if (strcmp(Operation,"del")==0) PassType=CopyStr(PassType,"delete");
    else PassType=CopyStr(PassType,"sha256");
    HomeDir=CopyStr(HomeDir,"/tmp");
    RealUser=CopyStr(RealUser,GetDefaultUser());
    Password=CopyStr(Password,"");
    Args=CopyStr(Args,"");

    p_arg=CommandLineNext(CMD);
    while (p_arg)
    {
        if (strcmp(p_arg,"-e")==0)
        {   
            p_arg=CommandLineNext(CMD);
            if (strcmp(Operation,"del") !=0) PassType=CopyStr(PassType,p_arg);
        }
        else if (strcmp(p_arg,"-h")==0)
        {
            p_arg=CommandLineNext(CMD);
            HomeDir=CopyStr(HomeDir,p_arg);
        }
        else if (strcmp(p_arg,"-u")==0)
        {
            p_arg=CommandLineNext(CMD);
            RealUser=CopyStr(RealUser,p_arg);
        }
        else if (strcmp(p_arg,"-a")==0)
        {
            p_arg=CommandLineNext(CMD);
            Settings.AuthPath=CopyStr(Settings.AuthPath,p_arg);
        }
        else if (StrLen(UserName)==0) UserName=CopyStr(UserName,p_arg);
        else if (StrLen(Password)==0) Password=CopyStr(Password,p_arg);
        else Args=MCatStr(Args,p_arg," ",NULL);
    p_arg=CommandLineNext(CMD);
    }


    PostProcessUserSetup(Operation, PassType, UserName, Password, HomeDir, RealUser, Args);


    Destroy(UserName);
    Destroy(Password);
    Destroy(PassType);
    Destroy(RealUser);
    Destroy(HomeDir);
    Destroy(Path);
    Destroy(Args);

    //Always exit when this is done, don't launch webserver
    exit(0);
}



void PrintUsage()
{
    fprintf(stdout,"\nAlaya Webdav Server: version %s\n",Version);
    fprintf(stdout,"Author: Colum Paget\n");
    fprintf(stdout,"Email: colums.projects@gmail.com\n");
    fprintf(stdout,"Credits: Thanks to Gregor Heuer, Helmut Schmid, and Maurice R Volaski for bug reports.\n");
    fprintf(stdout,"\n");

    fprintf(stdout,"Usage: alaya [-v] [-d] [-O] [-h] [-p <port>] [-i <iface>] [-f <config file>] [-t <seconds>] [-A <auth methods>] [-a <auth file>] [-l <log file>] [-P <pid file>] [-r <path>] [-sslv <version>] [-key <path>] [-cert <path>] [-client-cert <level>] [-verify-path <path>] [-ciphers <cipher list>] [-pfs] [-cgi <path>] [-ep <path>] [-u <default user>] [-g <default group>] [-m <http methods>] [-realm <auth realm>] [-allowed <users>] -denied <users>] [-allow-ip <iplist>] [-nodir] [-dir <type>] [-compress <yes|no|partial>] [-ttl <ttl>] [-cache <seconds>] [-tz <timezone>] [-accesstokenkey <string>] [-urltokenkey <string>] [-clientnames] [-ttl <pkt ttl>] \n\n");





    fprintf(stdout,"  %-15s %s", "-v","Verbose logging.\n");
    fprintf(stdout,"  %-15s %s", "-v -v", "Even more verbose logging.\n");
    fprintf(stdout,"  %-15s %s", "-a", "Specify the authentication file for 'built in' authentication.\n");
    fprintf(stdout,"  %-15s %s", "-A", "Authentication methods. Comma separated list of pam,passwd,shadow,native,accesstoken,urltoken. For 'Alaya native only' just use 'native' on its own\n");
    fprintf(stdout,"  %-15s %s", "-d", "No daemon, don't background process.\n");
    fprintf(stdout,"  %-15s %s", "-nodemon", "No daemon, don't background process.\n");
    fprintf(stdout,"  %-15s %s","-f", "Path to config file, defaults to /etc/alaya.conf, but alaya can be configured by command-line args only.\n");
    fprintf(stdout,"  %-15s %s","-p", "Set port to listen on.\n");
    fprintf(stdout,"  %-15s %s","-O", "Open server, don't require authentication.\n");
    fprintf(stdout,"  %-15s %s","-m", "HTTP Methods (GET, PUT, DELETE, PROPFIND) that are allowed.\nComma Separated. Set to 'GET' for very basic webserver, 'GET,PROPFIND' for readonly DAV.\n'BASE' will set GET,POST,HEAD. 'DAV' will set everything needed for WebDAV. 'RGET' will allow proxy-server gets. 'PROXY' will enable CONNECT and RGET. 'DAV,PROXY' enables everything.\n");
    fprintf(stdout,"  %-15s %s","-t", "'activity timeout', connection inactivity timeout in seconds.\n");
    fprintf(stdout,"  %-15s %s","-r", "'ChRoot mode', chroot into directory and offer services from it.\n");
    fprintf(stdout,"  %-15s %s","-chroot", "'ChRoot mode', chroot into directory and offer services from it.\n");
    fprintf(stdout,"  %-15s %s","-h", "'ChHome mode', switch to users home dir and chroot.\n");
    fprintf(stdout,"  %-15s %s","-chhome", "'ChHome mode', switch to users home dir and chroot.\n");
    fprintf(stdout,"  %-15s %s","-i", "Set interface/address listen on. Argument is IP address of interface. Allows running separate servers on the same port on different interfaces/network cards.\n");
    fprintf(stdout,"  %-15s %s","-l", "Path to log file, default is to use 'syslog' instead.\n");
    fprintf(stdout,"  %-15s %s","-P", "Set path to pidfile.\n");
    fprintf(stdout,"  %-15s %s","-tz", "Set server's timezone.\n");
    fprintf(stdout,"  %-15s %s","-nodir", "Do not allow directory listings.\n");
    fprintf(stdout,"  %-15s %s","-dir", "Directory listing type. One of: 'none', 'basic', 'fancy', 'interactive', or 'full'.\n");
    fprintf(stdout,"  %-15s %s","-dirtype", "Directory listing type. One of: 'none', 'basic', 'fancy', 'interactive', or 'full'.\n");
    fprintf(stdout,"  %-15s %s","-U", "fancy, interactive dir listings with media, tarballs and other features..\n");
    fprintf(stdout,"  %-15s %s","-sslv", "Minimum  SSL version for HTTPS.  One of 'ssl', 'tls', 'tls1.2', 'tls1.2'\n");
    fprintf(stdout,"  %-15s %s","-key", "Keyfile for SSL (HTTPS)\n");
    fprintf(stdout,"  %-15s %s","-cert", "Certificate for SSL (HTTPS). This can be a certificate chain bundled in .pem format.\n");
    fprintf(stdout,"  %-15s %s","-ciphers", "List of SSL ciphers to use.\n");
    fprintf(stdout,"  %-15s %s","-dhparams", "Path to a file containing Diffie Helmann parameters for Perfect Forward Secrecy.\n");
    fprintf(stdout,"  %-15s %s","-dhgenerate", "Generate Diffie Helmann parameters for Perfect Forward Secrecy at startup (will take a long time). Will not generate if a dhparams file ahs been supplied with -dhparams\n");
    fprintf(stdout,"  %-15s %s","-pfs", "Use Perfect Forward Secrecy. Will not generate Diffie Helmann parameters unless -dhgenerate is supplied too\n");
    fprintf(stdout,"  %-15s %s","-client-cert", "Settings for SSL client certificate authentication. Three levels are available: 'required' means a client MUST supply a certificate, but that it may still be required to log in through normal authentication. 'sufficient' means that a client CAN supply a certificate, and that the certificate is all the authentication that's needed. 'required+sufficient' means that a client MUST provide a certificate, and that this certificate is sufficient for authentication. 'ask' is used at the global level, when 'required' or 'sufficient' is present in the authentication file for a specific user.\n");
    fprintf(stdout,"  %-15s %s","-verify-path", "Path to a file, or a directory, containing Authority certificates for verifying client certificates.\n");
    fprintf(stdout,"  %-15s %s","-cgi", "Directory containing cgi programs. These programs will be accessible even though they are outside of a 'chroot'\n");
    fprintf(stdout,"  %-15s %s","-hashfile", "File containing cryptographic hashes of cgi-scripts. This file contains the output of the md5sum, shasum, sha256sum or sha512sum utilities.\n");
    fprintf(stdout,"  %-15s %s","-ep", "'External path' containing files that will be accessible even outside a chroot.\n");
    fprintf(stdout,"  %-15s %s","-u", "User to run cgi-programmes and default 'real user' for any 'native users' that don't have one specified.\n");
    fprintf(stdout,"  %-15s %s","-g", "Group to run server in (this will be the default group for users)\n");
    fprintf(stdout,"  %-15s %s","-allowed", "Comma separated list of users allowed to login (default without this switch is 'all users can login'\n");
    fprintf(stdout,"  %-15s %s","-denied", "Comma separated list of users DENIED login\n");
    fprintf(stdout,"  %-15s %s","-realm", "Realm for HTTP Authentication\n");
    fprintf(stdout,"  %-15s %s","-compress", "Compress documents and responses. This can have three values, 'yes', 'no' or 'partial'. 'Partial' means alaya will compress directory listings and other internally genrated pages, but not file downloads.\n");
    fprintf(stdout,"  %-15s %s","-cache", "Takes an argument in seconds which is the max-age recommended for browser caching. Setting this to zero will turn off caching in the browser. Default is 10 secs.\n");
    fprintf(stdout,"  %-15s %s","-accesstokenkey", "Secret key to use with access-tokens.\n");
    fprintf(stdout,"  %-15s %s","-urltokenkey", "Secret key to use with url-tokens.\n");
    fprintf(stdout,"  %-15s %s","-su", "On linux systems disable the 'no su' feature, so that suid cgi programs can switch user. NOT RECOMENDED.\n");
    fprintf(stdout,"  %-15s %s","-ttl <value>", "Set Time To Live value for response packets from this server.\n");
    fprintf(stdout,"  %-15s %s","-allow-ip <ip list>", "Comma-seperated list of shell-match patterns of allowed client IPs. If unset all IPs are allowed as clients. e.g. `alaya -allow-ips 10.[1-5].*.*,127.0.0.1`.\n");
    fprintf(stdout,"  %-15s %s","-allow-ips <ip list>", "Comma-seperated list of shell-match patterns of allowed client IPs. If unset all IPs are allowed as clients. e.g. `alaya -allow-ips 10.[1-5].*.*,127.0.0.1`.\n");
    fprintf(stdout,"\n\nUser Setup for Alaya Authentication\n");
    fprintf(stdout,"	Alaya can use PAM, /etc/shadow or /etc/passwd to authenticate, but has its own password file that offers extra features, or is useful to create users who can only use Alaya. Users in the Alaya password file are mapped to a 'real' user on the system (usually 'guest' or 'nobody'). The Alaya password file can be setup through the alaya commandline.\n");
    fprintf(stdout,"\nAdd User:\n   alaya -user add [-a <auth path>] [-e <password encryption type>]  [-h <user home directory>] <Username> <Password> <Setting> <Setting> <Setting>\n\n");
    fprintf(stdout,"   %-15s %s","-a", "Specify the authentication file for 'built in' authentication.\n");
    fprintf(stdout,"   %-15s %s","-h", "Specify home directory of new user.\n");
    fprintf(stdout,"   %-15s %s","-u", "Specify 'real user' that this user maps to.\n");
    fprintf(stdout,"   %-15s %s","-e", "Specify password encryption type (sha1, sha512, sha256, md5, plain or null).\n");
    fprintf(stdout,"\nConfig file type settings (like 'ChHome' or 'ChRoot=/var/shared' or 'HttpMethods=GET,PUT,PROPFIND' or 'CgiPath=/usr/share/cgi') can be added so that these settings are specific to a user\n\n");
    fprintf(stdout,"   alaya -user add bill billspassword ChHome HttpMethods=GET\n");

    fprintf(stdout,"\nDelete User:\n  alaya -user del [-a <auth path>] <Username>\n\n");
    fprintf(stdout,"List Users:\n  alaya -user list\n\n");

}



void SettingsParseCommandLine(int argc, char *argv[], TSettings *Settings)
{
    int i;
    char *Token=NULL;
    const char *p_arg;
    CMDLINE *CMD; 

    if (argc < 2) return;

    CMD=CommandLineParserCreate(argc, argv);
    p_arg=CommandLineNext(CMD);
    if (! p_arg) return;

    if (strcmp(p_arg,"-user")==0)
    {
         p_arg=CommandLineNext(CMD);

        if (strcmp(p_arg, "list")==0) HandleUserSetup("list", CMD);
        else if (strcmp(p_arg, "add")==0) HandleUserSetup("add", CMD);
        else if (strcmp(p_arg, "del")==0) HandleUserSetup("del", CMD);
        else printf("-user must be followed by one of \"add\", \"del\" or \"list\"\n");

        //if we are doing 'HandleUserSetup' then once it's done we don't need to continue
        exit(1);
    }


    while (p_arg)
    {
        if (strcmp(p_arg,"-v")==0)
        {
            if (Settings->Flags & FLAG_LOG_VERBOSE) Settings->Flags |= FLAG_LOG_MORE_VERBOSE;
            Settings->Flags |= FLAG_LOG_VERBOSE;
        }
        else if (strcmp(p_arg,"-d")==0) Settings->Flags |= FLAG_NODEMON;
        else if (strcmp(p_arg,"-nodemon")==0) Settings->Flags |= FLAG_NODEMON;
        else if (strcmp(p_arg,"-i")==0) Settings->BindAddress=MCatStr(Settings->BindAddress,CommandLineNext(CMD),",",NULL);
        else if (strcmp(p_arg,"-a")==0) Settings->AuthPath=CopyStr(Settings->AuthPath,CommandLineNext(CMD));
        else if (strcmp(p_arg,"-A")==0) Settings->AuthMethods=CopyStr(Settings->AuthMethods,CommandLineNext(CMD));
        else if (strcmp(p_arg,"-admin")==0) Settings->AdminUser=CopyStr(Settings->AdminUser, CommandLineNext(CMD));
        else if (strcmp(p_arg,"-su")==0) Settings->Flags |= FLAG_ALLOW_SU;
        else if (strcmp(p_arg,"-f")==0) Settings->ConfigPath=CopyStr(Settings->ConfigPath,CommandLineNext(CMD));
        else if (strcmp(p_arg,"-l")==0) Settings->LogPath=CopyStr(Settings->LogPath,CommandLineNext(CMD));
        else if (strcmp(p_arg,"-m")==0) Settings->HttpMethods=CopyStr(Settings->HttpMethods,CommandLineNext(CMD));
        else if (strcmp(p_arg,"-t")==0) Settings->ActivityTimeout=atoi(CommandLineNext(CMD));
        else if (strcmp(p_arg,"-p")==0) Settings->Port=atoi(CommandLineNext(CMD));
        else if (strcmp(p_arg,"-P")==0) Settings->PidFilePath=CopyStr(Settings->PidFilePath, CommandLineNext(CMD));
        else if (strcmp(p_arg,"-O")==0) Settings->AuthFlags &= ~FLAG_AUTH_REQUIRED;
        else if (strcmp(p_arg,"-U")==0) Settings->DirListFlags |= DIR_SHOWFILES | DIR_FANCY | DIR_INTERACTIVE | DIR_MEDIA_EXT | DIR_SHOW_VPATHS | DIR_TARBALLS;
        else if (strcmp(p_arg,"-nodir")==0) Settings->DirListFlags = DIR_REJECT;
        else if ( (strcmp(p_arg,"-dir")==0) || (strcmp(p_arg,"-dirtype")==0) )
        {
            Token=MCopyStr(Token,"DirListType=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-ttl")==0)
        {
            Token=MCopyStr(Token,"ServerTTL=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-compress")==0)
        {
            Token=MCopyStr(Token,"Compression=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-u")==0)
        {
            Token=MCopyStr(Token,"DefaultUser=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-g")==0)
        {
            Token=MCopyStr(Token,"DefaultGroup=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-r")==0)
        {
            Token=MCopyStr(Token,"ChRoot=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-chroot")==0)
        {
            Token=MCopyStr(Token,"ChRoot=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-h")==0) ParseConfigItem("ChHome");
        else if (strcmp(p_arg,"-chhome")==0) ParseConfigItem("ChHome");
        else if (strcmp(p_arg,"-sslv")==0)
        {
            Token=MCopyStr(Token,"SSLVersion=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-key")==0)
        {
            Token=MCopyStr(Token,"SSLKey=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-cert")==0)
        {
            Token=MCopyStr(Token,"SSLCert=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-dhparams")==0)
        {
            Token=MCopyStr(Token,"SSLDHParams=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-dhgenerate")==0) Settings->Flags |= FLAG_SSL_PFS | FLAG_PFS_GENERATE;
        else if (strcmp(p_arg,"-pfs")==0) Settings->Flags |= FLAG_SSL_PFS;
        else if (strcmp(p_arg,"-ciphers")==0)
        {
            Token=MCopyStr(Token,"SSLCiphers=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-cgi")==0)
        {
            Token=MCopyStr(Token,"Path=cgi,/cgi-bin/,",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-ep")==0)
        {
            Token=MCopyStr(Token,"Path=files,,",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-denied")==0)
        {
            Token=MCopyStr(Token,"DenyUsers=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-allowed")==0)
        {
            Token=MCopyStr(Token,"AllowUsers=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if ( (strcmp(p_arg,"-allow-ips")==0) || (strcmp(p_arg,"-allow-ip")==0) )
        {
            Token=MCopyStr(Token,"AllowIPs=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-realm")==0)
        {
            Token=MCopyStr(Token,"AuthRealm=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-client-cert")==0)
        {
            Token=MCopyStr(Token,"SSLClientCertificate=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-verify-path")==0)
        {
            Token=MCopyStr(Token,"SSLVerifyPath=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-hashfile")==0)
        {
            Token=MCopyStr(Token,"ScriptHashFile=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-accesstokenkey")==0)
        {
            Token=MCopyStr(Token,"AccessTokenKey=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-urltokenkey")==0)
        {
            Token=MCopyStr(Token,"URLTokenKey=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (strcmp(p_arg,"-cache")==0) Settings->DocumentCacheTime=strtol(CommandLineNext(CMD),NULL,10);
        else if (strcmp(p_arg,"-clientnames")==0) Settings->Flags |= FLAG_LOOKUP_CLIENT;
        else if (strcmp(p_arg,"-tz")==0)
        {
            Token=MCopyStr(Token,"Timezone=",CommandLineNext(CMD),NULL);
            ParseConfigItem(Token);
        }
        else if (
            (strcmp(p_arg,"-version")==0) ||
            (strcmp(p_arg,"--version")==0)
        )
        {
            fprintf(stdout,"version: %s\n",Version);
            fprintf(stdout,"\nBuilt: %s %s\n",__DATE__,__TIME__);

#ifdef USE_IP6
            fprintf(stdout, "   IPv6 support enabled\n");
#endif

#ifdef HAVE_LIBPAM
            fprintf(stdout, "   Pluggable Authentication Modules (PAM) enabled\n");
#endif

#ifdef USE_MDWE
            fprintf(stdout, "   MDWE memory hardening enabled\n");
#endif

#ifdef USE_NOSU
            fprintf(stdout, "   PR_NO_NEW_PRIVS 'nosu' deny privesc enabled\n");
#endif

#ifdef USE_LINUX_CAPABILITIES
            fprintf(stdout, "   Linux Capabilites enabled\n");
#endif

#ifdef USE_UNSHARE
            fprintf(stdout, "   process containment using unshare enabled (allows chroot as normal user)\n");
#endif

#ifdef USE_SOCKS
            fprintf(stdout, "   SOCKS proxy features enabled\n");
#endif

#ifdef USE_SENDFILE
            fprintf(stdout, "   use linux sendfile for zero-copy send of data in unencrypted HTTP mode\n");
#endif



            fprintf(stdout,"libUseful: Version %s BuildTime: %s\n",LibUsefulGetValue("LibUsefulVersion"), LibUsefulGetValue("LibUsefulBuildTime"));

            if (SSLAvailable()) fprintf(stdout,"SSL Library: %s\n",LibUsefulGetValue("SSL:Library"));
            else fprintf(stdout,"%s\n","SSL Library: None, not compiled with --enable-ssl");

            exit(1);
        }
        else if (
            (strcmp(p_arg, "-?")==0) ||
            (strcmp(p_arg, "-help")==0) ||
            (strcmp(p_arg, "--help")==0)
        )
        {
            PrintUsage();
            exit(0);
        }
        else
        {
            printf("UNKNOWN ARGUMENT: [%s]\n",p_arg);
            exit(1);
        }

         p_arg=CommandLineNext(CMD);
    }

    Destroy(Token);
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
    Settings.ListenQueueLen=10;
    Settings.MaxLogSize=9999999;
    Settings.MaxLogRotate=5;
    Settings.LogPath=CopyStr(Settings.LogPath, "SYSLOG");
    Settings.PidFilePath=CopyStr(Settings.PidFilePath, "/var/run/alaya.pid");
    Settings.ConfigPath=CopyStr(Settings.ConfigPath, "/etc/alaya.conf");
    Settings.DefaultDir=CopyStr(Settings.DefaultDir, "./");
    Settings.BindAddress=CopyStr(Settings.BindAddress, "");
    Settings.Flags |= FLAG_KEEPALIVES | FLAG_USE_REUSEPORT | FLAG_USE_UNSHARE | FLAG_USE_HTTPS_FASTOPEN;
    Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY;
    Settings.AuthFlags=FLAG_AUTH_REQUIRED | FLAG_AUTH_COOKIE;
    Settings.AuthPath=CopyStr(Settings.AuthPath,"/etc/alaya.auth:~/.alaya/alaya.auth");
    Settings.AuthMethods=CopyStr(Settings.AuthMethods,"accesstoken,cookie,native");
    Settings.AuthRealm=CopyStr(Settings.AuthRealm,UnameData.nodename);
    Settings.IndexFiles=CopyStr(Settings.IndexFiles,"index.html,dir.html");
    Settings.M3UFileTypes=CopyStr(Settings.M3UFileTypes,".mp3,.ogg,.mp4,.flv,.webm,.m4v,.m4a,.aac,.wma,.wmv");
    Settings.ForbiddenURLStrings=CopyStr(Settings.ForbiddenURLStrings,"..,%00,%2e%2e");
    Settings.HttpMethods=CopyStr(Settings.HttpMethods,"GET,POST,HEAD,OPTIONS,DELETE,MKCOL,MOVE,COPY,PUT,PROPFIND,PROPPATCH,");
    Settings.VPaths=ListCreate();
    Settings.HostConnections=ListCreate();
    Settings.ScriptHandlers=ListCreate();
    Settings.LoginEntries=ListCreate();
    Settings.DocumentCacheTime=10;
    Settings.AddressSpace=CopyStr(Settings.AddressSpace, "250M");
    Settings.StackSize=CopyStr(Settings.StackSize, "1M");
    Settings.ActivityTimeout=10000;
    Settings.TTL=-1;
    Settings.PackFormats=CopyStr(Settings.PackFormats,"tar:internal,zip:zip -");

    GenerateRandomBytes(&Settings.AccessTokenKey,32,ENCODE_BASE64);
//this will be set to 80 or 443 in 'PostProcessSettings'
    Settings.Port=0;

}



void ReadConfigFile(const char *Path)
{
    STREAM *S;
    char *Tempstr=NULL;


    S=STREAMOpen(Path, "r");
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

    Destroy(Tempstr);
}

