#include "AccessTokens.h"


void ParseAccessToken(HTTPSession *Session)
{
char *Salt=NULL, *Token=NULL;
char *Name=NULL, *Value=NULL, *ptr;

    ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
    while (ptr)
    {
      if (strcasecmp(Name,"AccessToken")==0) Token=CopyStr(Token,Value);
      ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
    }
    Session->Password=CopyStr(Session->Password,Token);

  DestroyString(Salt);
  DestroyString(Name);
  DestroyString(Value);
  DestroyString(Token);
}


char *MakeAccessDigest(char *Buffer, const char *User, const char *Salt, const char *RequestingHost, const char *RequestURL)
{
char *Tempstr=NULL, *RetStr=NULL;

RetStr=CopyStr(Buffer,"");

if (StrLen(Settings.AccessTokenKey))
{
  Tempstr=MCopyStr(Tempstr,Salt,":",User,":",Settings.AccessTokenKey,":",RequestingHost,":",RequestURL,NULL);
  HashBytes(&RetStr,"sha1",Tempstr,StrLen(Tempstr),ENCODE_HEX);

}
DestroyString(Tempstr);

return(RetStr);
}


char *MakeAccessToken(char *Buffer, const char *User, const char *Salt, const char *RequestingHost, const char *RequestURL)
{
char *Digest=NULL, *RetStr=NULL;

Digest=MakeAccessDigest(Digest, User, Salt, RequestingHost, RequestURL);
RetStr=MCopyStr(RetStr,User,":",Salt,":",Digest,NULL);

DestroyString(Digest);
return(RetStr);
}


int CheckAccessToken(HTTPSession *Session, const char *User, const char *Salt, const char *URL, const char *ClientIP, const char *CorrectToken)
{
char *Token=NULL;
int result=FALSE;

if (strcmp(Session->Method, "PUT")==0) return(FALSE);
if (strcmp(Session->Method, "POST")==0) return(FALSE);
Token=MakeAccessDigest(Token, User, Salt, ClientIP, URL);

if (StrLen(Token) && (strcmp(Token, CorrectToken)==0)) result=TRUE; 

DestroyString(Token);
return(result);
}


int AuthAccessToken(HTTPSession *Session, const char *AccessToken)
{
char *URL=NULL, *User=NULL, *Salt=NULL, *Token=NULL;
const char *ptr, *ipptr;
int result=FALSE;

//if (! (Session->Flags & FLAG_AUTH_ACCESS_TOKEN)) return(FALSE);
if (StrLen(Settings.AccessTokenKey)==0) return(FALSE);

URL=FormatURL(URL,Session,Session->Path);


//Password will be in format <salt>:<access token>
ptr=GetToken(AccessToken,":",&User,0);
if (StrLen(Session->UserName)==0) Session->UserName=CopyStr(Session->UserName,User);

ptr=GetToken(ptr,":",&Salt,0);
ptr=GetToken(ptr,"\\S",&Token,0);


if (StrLen(Salt) && StrLen(User) && StrLen(Token))
{
	if (strncmp(Session->ClientIP,"::ffff:",7)==0) ipptr=Session->ClientIP+7;
	else ipptr=Session->ClientIP;
	
	
	if (CheckAccessToken(Session, User, Salt, URL, ipptr, Token)) result=TRUE;
	else if (CheckAccessToken(Session, User, Salt, "*", ipptr, Token)) result=TRUE;
	else if (CheckAccessToken(Session, User, Salt, URL, "*", Token)) result=TRUE;
	else if (CheckAccessToken(Session, User, Salt, "*", "*", Token)) result=TRUE;
}

DestroyString(Salt);
DestroyString(URL);

return(result);
}


int AccessTokenAuthCookie(HTTPSession *Session)
{
char *ptr, *Name=NULL, *Value=NULL, *Token=NULL;
char *Tempstr=NULL;
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
else Session->Cookies=MCatStr(Session->Cookies, Name, "=", Value, ";", NULL);

while (isspace(*ptr)) ptr++;
ptr=GetNameValuePair(ptr, ";", "=", &Name, &Value);
}

DestroyString(Name);
DestroyString(Value);
DestroyString(Token);
DestroyString(Tempstr);

return(result);
}


char *MakeAccessCookie(char *RetStr, HTTPSession *Session)
{
char *Salt=NULL, *AccessToken=NULL;

GenerateRandomBytes(&Salt,24,ENCODE_HEX);
AccessToken=MakeAccessToken(AccessToken, Session->UserName, Salt, Session->ClientIP, "*");
RetStr=MCopyStr(RetStr, "AlayaAccessToken=",AccessToken," domain=",Session->Host, NULL);

DestroyString(AccessToken);
DestroyString(Salt);

return(RetStr);
}
