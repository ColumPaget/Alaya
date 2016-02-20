#include "AccessTokens.h"


char *MakeAccessToken(char *Buffer, const char *Salt, const char *User, const char *RequestingHost, const char *RequestURL)
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


int CheckAccessToken(HTTPSession *Session, const char *Salt, const char *URL, const char *ClientIP, const char *CorrectToken)
{
char *Token=NULL;
int result=FALSE;

if (strcmp(Session->Method, "PUT")==0) return(FALSE);
if (strcmp(Session->Method, "POST")==0) return(FALSE);
Token=MakeAccessToken(Token, Salt, Session->UserName, ClientIP, URL);



if (StrLen(Token) && (strcmp(Token, CorrectToken)==0)) result=TRUE; 

DestroyString(Token);
return(result);
}


int AuthAccessToken(HTTPSession *Session, const char *AccessToken)
{
char *URL=NULL, *Salt=NULL;
const char *ptr, *ipptr;
int result=FALSE;

//if (! (Session->Flags & FLAG_AUTH_ACCESS_TOKEN)) return(FALSE);
if (StrLen(Settings.AccessTokenKey)==0) return(FALSE);

URL=FormatURL(URL,Session,Session->Path);

//Password will be in format <salt>:<access token>
ptr=GetToken(AccessToken,":",&Salt,0);

if (StrLen(Salt) && (StrLen(ptr)))
{
if (strncmp(Session->ClientIP,"::ffff:",7)==0) ipptr=Session->ClientIP+7;
else ipptr=Session->ClientIP;


if (CheckAccessToken(Session, Salt, URL, ipptr, ptr)) result=TRUE;
else if (CheckAccessToken(Session, Salt, "*", ipptr, ptr)) result=TRUE;
else if (CheckAccessToken(Session, Salt, URL, "*", ptr)) result=TRUE;
else if (CheckAccessToken(Session, Salt, "*", "*", ptr)) result=TRUE;
}

DestroyString(Salt);
DestroyString(URL);

return(result);
}


int AccessTokenAuthCookie(HTTPSession *Session)
{
char *ptr, *tptr, *Name=NULL, *Value=NULL, *Token=NULL;
int result=FALSE;

ptr=GetNameValuePair(Session->Cookies, ";", "=", &Name, &Value);
while (ptr)
{
if (strcasecmp(Name,"AlayaAccessToken")==0)
{
	tptr=GetToken(Value,":",&Token, 0);
	if (StrLen(Token))
	{
		if (! StrLen(Session->UserName)) Session->UserName=CopyStr(Session->UserName, Token);
		if (strcmp(Session->UserName,Token) !=0) LogToFile(Settings.LogPath,"ERROR: AccessCookie UserName missmatch [%s] [%s]",Session->UserName,Token);
		else
		{
			result=AuthAccessToken(Session, tptr);
			if (result) Session->AuthFlags |= FLAG_AUTH_HASCOOKIE;
		}
	}
}
ptr=GetNameValuePair(ptr, ";", "=", &Name, &Value);
}

DestroyString(Name);
DestroyString(Value);
DestroyString(Token);

return(result);
}


char *MakeAccessCookie(char *RetStr, HTTPSession *Session)
{
char *Salt=NULL, *AccessToken=NULL;

GenerateRandomBytes(&Salt,24,ENCODE_HEX);
AccessToken=MakeAccessToken(AccessToken, Salt, Session->UserName, Session->ClientIP, "*");
RetStr=MCopyStr(RetStr, "AlayaAccessToken=",Session->UserName,":",Salt,":",AccessToken,NULL);

DestroyString(AccessToken);
DestroyString(Salt);

return(RetStr);
}
