#include "auth_access_token.h"

static char *MakeAccessDigest(char *Buffer, const char *User, const char *Salt, const char *Key, const char *RequestingHost, const char *RequestURL)
{
    char *Tempstr=NULL, *RetStr=NULL;
    const char *ptr;

    RetStr=CopyStr(Buffer,"");

    Tempstr=MCopyStr(Tempstr, Salt, ":", User,":", Key, ":", RequestingHost, ":", RequestURL, NULL);

    HashBytes(&RetStr,"sha256",Tempstr,StrLen(Tempstr),ENCODE_RBASE64);

    ptr=strchr(RetStr, '=');
    if (ptr) StrTrunc(RetStr, ptr-RetStr);

    LogToFile(Settings.LogPath,"MKAD: [%s] salt=%s user=%s key=%s rh=%s ru=%s", RetStr, Salt, User, Key, RequestingHost, RequestURL);

    Destroy(Tempstr);

    return(RetStr);
}


void ParseAccessToken(HTTPSession *Session)
{
    char *Salt=NULL, *Token=NULL;
    char *Name=NULL, *Value=NULL;
    const char *ptr;

    ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
    while (ptr)
    {
        if (strcasecmp(Name,"AccessToken")==0) Token=CopyStr(Token,Value);
        if (strcasecmp(Name,"URLToken")==0) Token=CopyStr(Token,Value);
        ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
    }
    Session->Password=CopyStr(Session->Password,Token);

    Destroy(Salt);
    Destroy(Name);
    Destroy(Value);
    Destroy(Token);
}


char *MakeAccessToken(char *Buffer, const char *User, const char *Key, const char *Salt, const char *RequestingHost, const char *RequestURL)
{
    char *Digest=NULL, *RetStr=NULL;

    Digest=MakeAccessDigest(Digest, User, Salt, Key, RequestingHost, RequestURL);
    RetStr=MCopyStr(RetStr,User,":",Salt,":",Digest,NULL);

    Destroy(Digest);
    return(RetStr);
}


static int CheckAccessToken(HTTPSession *Session, const char *User, const char *Key, const char *Salt, const char *URL, const char *ClientIP, const char *CorrectToken)
{
    char *Token=NULL;
    int result=FALSE;

    if (strcmp(Session->Method, "PUT")==0) return(FALSE);
    if (strcmp(Session->Method, "POST")==0) return(FALSE);
    if (! StrValid(Key)) return(FALSE);

    Token=MakeAccessDigest(Token, User, Salt, Key, ClientIP, URL);

    if (StrValid(Token) && (strcmp(Token, CorrectToken)==0)) result=TRUE;

    Destroy(Token);
    return(result);
}


//AccessTokens apply to use cases where access to a specific file is granted
//to a specific IP. When alaya gives URLs to a client, say in a directory listing
//it included an 'AccessToken' variable that authenticates the IP the client
//is coming from to get those URLS. The main use case for this is media players
//that are launched from a web-browser and support HTTP but don't support authentication
int AuthAccessToken(HTTPSession *Session, const char *AccessToken)
{
    char *URL=NULL, *User=NULL, *Salt=NULL, *Token=NULL;
    const char *ptr, *ipptr;
    int result=FALSE;

//if (! (Session->Flags & FLAG_AUTH_ACCESS_TOKEN)) return(FALSE);
    if (! StrValid(Settings.AccessTokenKey)) return(FALSE);

    URL=HTTPSessionFormatURL(URL,Session,Session->Path);


//Password will be in format <salt>:<access token>
    ptr=GetToken(AccessToken,":",&User,0);
    if (! StrValid(Session->UserName)) Session->UserName=CopyStr(Session->UserName,User);

    ptr=GetToken(ptr,":",&Salt,0);
    ptr=GetToken(ptr,"\\S",&Token,0);


    if (StrValid(Salt) && StrValid(User) && StrValid(Token))
    {
        //ipptr is the client's IP address. Access tokens are given to a client at an
        //IP and only work for that client
        if (strncmp(Session->ClientIP,"::ffff:",7)==0) ipptr=Session->ClientIP+7;
        else ipptr=Session->ClientIP;


        if (CheckAccessToken(Session, User, Settings.AccessTokenKey, Salt, URL, ipptr, Token)) result=TRUE;
        else if (CheckAccessToken(Session, User, Settings.AccessTokenKey, Salt, "*", ipptr, Token)) result=TRUE;
        else if (CheckAccessToken(Session, User, Settings.AccessTokenKey, Salt, URL, "*", Token)) result=TRUE;
        else if (CheckAccessToken(Session, User, Settings.AccessTokenKey, Salt, "*", "*", Token)) result=TRUE;
    }

    Destroy(Salt);
    Destroy(URL);

    return(result);
}


//URL Tokens are a type of access token, but they differ from standard access tokens
//in that it's expected they can come from any IP, and they tend to be long lived.
//Whereas the underlying random key for access tokens is generated whenever alaya
//restarts, url tokens have a permanent key configured in alaya's config file.
//URL Tokens only permit access to one file. The use case is QR codes that can be
//scanned to display a document, but only grant access to that document, without
//giving away a full login.
int AuthURLToken(HTTPSession *Session, const char *AccessToken)
{
    char *URL=NULL, *User=NULL, *Salt=NULL, *Token=NULL;
    const char *ptr, *ipptr;
    int result=FALSE;

//if (! (Session->Flags & FLAG_AUTH_ACCESS_TOKEN)) return(FALSE);
    if (! StrValid(Settings.URLTokenKey)) return(FALSE);

    URL=HTTPSessionFormatURL(URL,Session,Session->Path);

//Password will be in format <salt>:<access token>
    ptr=GetToken(AccessToken,":",&User,0);
    if (! StrValid(Session->UserName)) Session->UserName=CopyStr(Session->UserName,User);

    ptr=GetToken(ptr,":",&Salt,0);
    ptr=GetToken(ptr,"\\S",&Token,0);


    if (StrValid(Salt) && StrValid(User) && StrValid(Token))
    {
        if (CheckAccessToken(Session, User, Settings.URLTokenKey,  Salt, Session->Path, "", Token)) result=TRUE;
        else if (CheckAccessToken(Session, User, Settings.URLTokenKey,  Salt, Session->Path, "", Token)) result=TRUE;
    }

    Destroy(Salt);
    Destroy(URL);

    return(result);
}



char *MakeAccessCookie(char *RetStr, HTTPSession *Session)
{
    char *Salt=NULL, *AccessToken=NULL;

    GenerateRandomBytes(&Salt,24,ENCODE_HEX);
    AccessToken=MakeAccessToken(AccessToken, Session->UserName, Salt, Settings.AccessTokenKey, Session->ClientIP, "*");
    RetStr=MCopyStr(RetStr, "AlayaAccessToken=",AccessToken," domain=",Session->Host, NULL);

    Destroy(AccessToken);
    Destroy(Salt);

    return(RetStr);
}


//Access Tokens stored as a cookie. These allow a client at a given IP
//Access to all URLs on a server
int AccessTokenAuthCookie(HTTPSession *Session)
{
    char *Name=NULL, *Value=NULL, *Token=NULL, *Tempstr=NULL;
    const char *ptr;
    int result=FALSE;

    Tempstr=CopyStr(Tempstr, Session->Cookies);
    Session->Cookies=CopyStr(Session->Cookies, "");
    ptr=GetNameValuePair(Tempstr, ";", "=", &Name, &Value);
    while (ptr)
    {

        if (strcasecmp(Name,"AlayaAccessToken")==0)
        {
            result=AuthAccessToken(Session, Value);

            if (result) Session->AuthFlags |= FLAG_AUTH_HASCOOKIE;
        }
        else Session->Cookies=MCatStr(Session->Cookies, Name, "=", Value, "; ", NULL);

        while (isspace(*ptr)) ptr++;
        ptr=GetNameValuePair(ptr, ";", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Token);
    Destroy(Tempstr);

    return(result);
}


