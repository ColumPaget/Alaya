/*

This file contains functions related to alaya's native authentication system

*/


#include "auth_alaya_native.h"


void AuthNativeListUsers(const char *Path)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL;
const char *ptr;

S=STREAMOpen(Path, "r");
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		StripTrailingWhitespace(Tempstr);
		ptr=GetToken(Tempstr,":",&Token,0);

		printf("%s ",Token);

		ptr=GetToken(ptr,":",&Token,0); //passtype
		ptr=GetToken(ptr,":",&Token,0); //password
		ptr=GetToken(ptr,":",&Token,0); //realuser
		printf("RealUser=%s ",Token);
		ptr=GetToken(ptr,":",&Token,0); //homedir
		printf("Dir=%s %s\n",Token,ptr);

		Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}

Destroy(Tempstr);
Destroy(Token);
}



int AuthNativeChange(const char *Path, const char *Name, const char *PassType, const char *Pass, const char *HomeDir, const char *RealUser, const char *Args)
{
STREAM *S;
ListNode *Entries;
char *Tempstr=NULL, *Token=NULL, *Salt=NULL;
ListNode *Curr;
int RetVal=ERR_FILE;
uid_t uid;

Entries=ListCreate();
S=STREAMOpen(Path, "r");

if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		GetToken(Tempstr,":",&Token,0);

		if (strcmp(Token,Name) !=0) ListAddItem(Entries,CopyStr(NULL,Tempstr));	
	
		Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}


S=STREAMOpen(Path, "w");
if (S)
{
	//First copy all other entries
	Curr=ListGetNext(Entries);
	while (Curr)
	{
		STREAMWriteLine((char *) Curr->Item,S);
		Curr=ListGetNext(Curr);
	}
	STREAMFlush(S);


	if (strcmp(PassType,"delete")==0)
	{
		//Don't bother to write new entry, effectively deleting user
	}
	else
	{
		//WriteNew Entry
		if (strcmp(PassType,"plain")==0)
		{
			Token=CopyStr(Token,Pass);
			Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Token,":",RealUser,":",HomeDir,":",Args,"\n",NULL);
		}
		else if (strcmp(PassType,"htdigest-md5")==0)
		{
			//Calc 'HA1'
			Tempstr=MCopyStr(Tempstr,Name,":",Settings.AuthRealm,":",Pass,NULL);
			HashBytes(&Token,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);
			Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Token,":",RealUser,":",HomeDir,":",Args,"\n",NULL);
		}
		else
		{
			GenerateRandomBytes(&Salt,24, ENCODE_BASE64);
			Tempstr=MCopyStr(Tempstr,Name,":",Pass,":",Salt,NULL);
			HashBytes(&Token, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
			Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Salt,"$",Token,":",RealUser,":",HomeDir,":",Args,"\n",NULL);
		}
	
		STREAMWriteLine(Tempstr,S);

		uid=LookupUID(RealUser);
		if (uid > 0)
		{
		mkdir(HomeDir,0770);
		chown(HomeDir, uid, -1);
		}
	}

	STREAMClose(S);
	RetVal=ERR_OKAY;
}
else RetVal=ERR_FILE;


Destroy(Tempstr);
Destroy(Token);
Destroy(Salt);

ListDestroy(Entries, Destroy);

return(RetVal);
}
	


static int NativeFileCheckPassword(char *Name, const char *PassType, const char *AuthStr, const char *ProvidedPass)
{
char *Salt=NULL, *Password=NULL, *Digest=NULL, *Tempstr=NULL;
const char *ptr;
int result=FALSE;

if (! PassType) return(FALSE);
if (! AuthStr) return(FALSE);
if (! ProvidedPass) return(FALSE);

if (strcmp(PassType,"null")==0) return(TRUE);
if (
			(strcmp(PassType,"plain")==0) &&
			(strcmp(AuthStr,ProvidedPass)==0) 
	)
return(TRUE);


ptr=strchr(AuthStr,'$');
if (ptr)
{
	ptr=GetToken(AuthStr, "$", &Salt, 0);
	Password=CopyStr(Password,ptr);
}
else 
{
	Salt=CopyStr(Salt,"");
	Password=CopyStr(Password,AuthStr);
}


if (StrValid(PassType) && StrValid(ProvidedPass))
{
	if (strcmp(PassType,"htdigest-md5")==0)
	{
		Tempstr=MCopyStr(Tempstr,Name,":",Settings.AuthRealm,":",ProvidedPass,NULL);
		HashBytes(&Digest,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);
	}
	else if (StrValid(Salt))
	{
			//Salted passwords as of version 1.1.1
			Tempstr=MCopyStr(Tempstr,Name,":",ProvidedPass,":",Salt,NULL);
			HashBytes(&Digest, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
	}
	//Old-style unsalted passwords
	else HashBytes(&Digest,PassType,ProvidedPass,StrLen(ProvidedPass),ENCODE_HEX);
		
	if (StrValid(Digest) && (strcmp(Password,Digest)==0)) result=TRUE;
}

Destroy(Tempstr);
Destroy(Password);
Destroy(Salt);
Destroy(Digest);

return(result);
}



/* HTTP Digest format uses the algorithm MD5(H1,H2) where:

 H1 is MD5(<username>:<auth realm>:password)
 H2 is MD5(<http method>:<extra details>:<request URI>)

 <extra details> contains a number of values sent by the server and echoed back by the client
*/
static int NativeFileCheckHTTPDigestAuth(HTTPSession *Session, const char *PasswordType, const char *Password, const char *ProvidedPass)
{
char *Tempstr=NULL, *Digest1=NULL, *Digest2=NULL;
char *Algo=NULL, *URI=NULL;
const char *p_AuthDetails;
int result=FALSE;


if (! ProvidedPass) return(FALSE);
if (! StrValid(PasswordType)) return(FALSE);
if (
			(strcmp(PasswordType, "plain") !=0) &&
			(strcmp(PasswordType, "htdigest-md5") !=0) 
	) return(FALSE);
	

	p_AuthDetails=GetToken(Session->AuthDetails,":",&URI,0);
	p_AuthDetails=GetToken(p_AuthDetails,":",&Algo,0);
	if (! StrValid(URI)) URI=CopyStr(URI,Session->Path);

	if (strcmp(PasswordType,"htdigest-md5")==0) Digest1=CopyStr(Digest1, Password);
	else
	{
		//Calc 'HA1'
		Tempstr=MCopyStr(Tempstr,Session->UserName,":",Settings.AuthRealm,":",Password,NULL);
		HashBytes(&Digest1,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);
	}


	//Calc 'HA2'

	Tempstr=MCopyStr(Tempstr,Session->Method,":",URI,NULL);
	HashBytes(&Digest2,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);

	Tempstr=MCopyStr(Tempstr,Digest1,":",p_AuthDetails,":",Digest2,NULL);
	Digest1=CopyStr(Digest1,"");
	HashBytes(&Digest1,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);
		
	if (strcasecmp(ProvidedPass,Digest1)==0) result=TRUE;


Destroy(Tempstr);
Destroy(Digest1);
Destroy(Digest2);
Destroy(Algo);
Destroy(URI);

return(result);
}



int AuthNativeFileCheck(const char *Path, HTTPSession *Session, int HTTPDigest, char **RealUser, char **HomeDir, char **UserSettings)
{
STREAM *S;
char *Tempstr=NULL;
char *Name=NULL, *Pass=NULL, *PasswordType=NULL, *Trash=NULL;
const char *ptr;
int RetVal=USER_UNKNOWN;


S=STREAMOpen(Path, "r");
if (! S) return(USER_UNKNOWN);

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{

  StripTrailingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,":",&Name,0);

  if (strcmp(Name,Session->UserName)==0)
  {
		ptr=GetToken(ptr,":",&PasswordType,0);
		ptr=GetToken(ptr,":",&Pass,0);
		if (RealUser) ptr=GetToken(ptr,":",RealUser,0);
		else ptr=GetToken(ptr,":",&Trash,0);
		if (HomeDir) ptr=GetToken(ptr,":",HomeDir,0);
		else ptr=GetToken(ptr,":",&Trash,0);
		if (UserSettings) ptr=GetToken(ptr,":",UserSettings,0);
		else ptr=GetToken(ptr,":",&Trash,0);
	
		RetVal=FALSE;

		if (HTTPDigest) RetVal=NativeFileCheckHTTPDigestAuth(Session, PasswordType, Pass, Session->Password);
		else RetVal=NativeFileCheckPassword(Name, PasswordType,Pass,Session->Password);

		if ((RetVal==TRUE) && (Settings.Flags & FLAG_LOG_VERBOSE)) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via native file: %s.",Session->UserName, Path);
		break;
  }

  Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);

Destroy(Name);
Destroy(Pass);
Destroy(Tempstr);
Destroy(PasswordType);

return(RetVal);
}


int AuthNativeCheck(HTTPSession *Session, int HTTPDigest, char **RealUser, char **HomeDir, char **UserSettings)
{
char *Path=NULL;
const char *ptr;
int RetVal=FALSE;

ptr=GetToken(Settings.AuthPath, ":", &Path, 0);
while (ptr)
{
	RetVal=AuthNativeFileCheck(Path, Session, HTTPDigest, RealUser, HomeDir, UserSettings);
	if (RetVal==TRUE) break;
	ptr=GetToken(ptr, ":", &Path, 0);
}

Destroy(Path);

return(RetVal);
}
