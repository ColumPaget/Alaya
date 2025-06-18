#include "http_session.h"

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
    Session->Flags |= SESSION_ALLOW_UPLOAD;

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
    Session->HomeDir=CopyStr(Session->HomeDir, Src->HomeDir);
    Session->RemoteAuthenticate=CopyStr(Session->RemoteAuthenticate, Src->RemoteAuthenticate);

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
    Session->RemoteAuthenticate=CopyStr(Session->RemoteAuthenticate, Src->RemoteAuthenticate);

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
    Session->Flags=Src->Flags & (SESSION_KEEPALIVE | SESSION_REUSE | SESSION_AUTHENTICATED | SESSION_SSL | SESSION_ICECAST | SESSION_ALLOW_UPLOAD) ;
    Session->AuthFlags=Src->AuthFlags;
    Session->Headers=ListCreate();

    return(Session);
}



void HTTPSessionDestroy(void *p_Session)
{
    HTTPSession *Session;

    if (! p_Session) return;
    Session=(HTTPSession *) p_Session;

    Destroy(Session->Protocol);
    Destroy(Session->Method);
    Destroy(Session->ResponseCode);
    Destroy(Session->OriginalURL);
    Destroy(Session->URL);
    Destroy(Session->Path);
    Destroy(Session->Cipher);
    Destroy(Session->Arguments);
    Destroy(Session->Destination);
    Destroy(Session->ContentType);
    Destroy(Session->ContentBoundary);
    Destroy(Session->UserName);
    Destroy(Session->Password);
    Destroy(Session->RealUser);
    Destroy(Session->AuthenticatedUser);
    Destroy(Session->HomeDir);
    Destroy(Session->Group);
    Destroy(Session->RemoteAuthenticate);
    Destroy(Session->Host);
    Destroy(Session->ClientIP);
    Destroy(Session->ClientMAC);
    Destroy(Session->ClientHost);
    Destroy(Session->ClientReferrer);
    Destroy(Session->UserAgent);
    Destroy(Session->ServerName);
    Destroy(Session->SearchPath);
    Destroy(Session->UserSettings);
    Destroy(Session->StartDir);
    Destroy(Session->Cookies);

    ListDestroy(Session->Headers,Destroy);
    free(Session);
}



//Clear down certain elements of a session so we can reuse it with keeplaive,
//but we keep it's Authentication and TLS/SSL context
void HTTPSessionClear(void *p_Session)
{
    HTTPSession *Session;

    if (! p_Session) return;
    Session=(HTTPSession *) p_Session;

//Clear everything but SESSION_REUSE, SESSION_AUTHENTICATED and HTTP_SSL, which are persistent
    Session->Flags &= (SESSION_REUSE | SESSION_AUTHENTICATED | SESSION_ALLOW_UPLOAD | HTTP_SSL);

    Session->Method=CopyStr(Session->Method,"");
    Session->ResponseCode=CopyStr(Session->ResponseCode,"");
    Session->URL=CopyStr(Session->URL,"");
    Session->Path=CopyStr(Session->Path,"");
    Session->Arguments=CopyStr(Session->Arguments,"");
    Session->Destination=CopyStr(Session->Destination,"");
    Session->ContentType=CopyStr(Session->ContentType,"");
    Session->ContentBoundary=CopyStr(Session->ContentBoundary,"");
    Session->UserName=CopyStr(Session->UserName,"");
    Session->Password=CopyStr(Session->Password,"");
    Session->Host=CopyStr(Session->Host,"");
    Session->ClientReferrer=CopyStr(Session->ClientReferrer,"");
    Session->UserAgent=CopyStr(Session->UserAgent,"");
    Session->SearchPath=CopyStr(Session->SearchPath,"");

//Do not clear these values, as 'SessionClear' is only called on persistent
//'HTTP Keep-Alive' sessions
//Session->Protocol=CopyStr(Session->Protocol,"");
//Session->Cipher=CopyStr(Session->Cipher,"");
//Session->ClientIP=CopyStr(Session->ClientIP,"");
//Session->ClientHost=CopyStr(Session->ClientHost,"");
//Session->StartDir=CopyStr(Session->StartDir,"");
//Session->HomeDir=CopyStr(Session->HomeDir,"");
//Session->RealUser=CopyStr(Session->RealUser,"");
//Session->UserSettings=CopyStr(Session->UserSettings,"");
//Session->ServerName=CopyStr(Session->ServerName,"");


    ListClear(Session->Headers,Destroy);
}

char *HTTPSessionGetArg(char *RetStr, HTTPSession *Session, const char *Arg)
{
    char *Name=NULL, *Value=NULL;
    const char *ptr;

    RetStr=CopyStr(RetStr, "");
    ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
    while (ptr)
    {
        if (strcasecmp(Name, Arg) ==0)
        {
            RetStr=HTTPUnQuote(RetStr, Value);
            break;
        }
        ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
    }

    Destroy(Name);
    Destroy(Value);

    return(RetStr);
}




char *HTTPSessionFormatURL(char *Buff, HTTPSession *Session, const char *ItemPath)
{
    char *Tempstr=NULL, *Quoted=NULL;
    const char *ptr=NULL, *sd_ptr;
    int len;

    if (StrValid(Session->Host))
    {
        if (Settings.Flags & FLAG_SSL) Tempstr=MCopyStr(Buff,"https://",Session->Host,"/",NULL);
        else Tempstr=MCopyStr(Buff,"http://",Session->Host,"/",NULL);
    }
    else Tempstr=CopyStr(Tempstr,"/");

    ptr=ItemPath;
    while (*ptr == '/') ptr++;

    if (StrValid(Session->StartDir)) sd_ptr=Session->StartDir;
    else sd_ptr="";

    while (*sd_ptr == '/') sd_ptr++;

    len=StrLen(sd_ptr);

    if (strncmp(ptr, sd_ptr,len)==0) ptr+=len;
    Quoted=HTTPQuoteChars(Quoted, ptr, " ()[]{}\t?&%!,+\':;#");

    Tempstr=CatStr(Tempstr,Quoted);

    Destroy(Quoted);
    return(Tempstr);
}




//currently only used by HTTPSessionCopyURL
static int CopyLocalItem(const char *From, const char *To)
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
        In=STREAMFileOpen(From,SF_RDONLY);
        if (In)
        {
            Out=STREAMFileOpen(To, SF_CREAT| SF_WRONLY | SF_TRUNC);
            if (Out) RetVal=STREAMSendFile(In, Out, 0, SENDFILE_KERNEL | SENDFILE_LOOP);
        }
    }

//as In and Out are NULL if not opened, it's safe to close them
//here as STREAMClose will ignore a NULL argument
    STREAMClose(In);
    STREAMClose(Out);
    Destroy(Tempstr);

    return(RetVal);
}




//currently only used by HTTPSessionCopyURL
static int IsLocalHost(HTTPSession *Session, const char *Host)
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






int HTTPSessionCopyURL(HTTPSession *Session, const char *From, const char *To)
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
            In=HTTPGet(From);
            if (In) Out=STREAMFileOpen(ToPath,SF_CREAT|SF_WRONLY|SF_TRUNC);
            if (Out) RetVal=STREAMSendFile(In, Out, 0, SENDFILE_KERNEL | SENDFILE_LOOP);
            STREAMClose(In);
            STREAMClose(Out);
        }
        else RetVal=CopyLocalItem(FromPath, ToPath);
    }

    Destroy(User);
    Destroy(Password);
    Destroy(Tempstr);
    Destroy(Host);
    Destroy(PortStr);
    Destroy(FromPath);
    Destroy(ToPath);

    return(RetVal);
}

