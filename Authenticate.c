#include "Authenticate.h"
#include <pwd.h>


#define ENC_MD5_HEX 0
#define ENC_MD5_BASE64 1

#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif


#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>
#endif

#define USER_UNKNOWN -1

char *AuthenticationsTried=NULL;

char *AuthMethods[]={"native","pam","passwd","shadow","digest","accesstoken","open","none","deny",NULL};

#define AUTH_NONE 0
#define AUTH_STD 1
#define AUTH_DIGEST 2
#define AUTH_DIGEST_STD 3
#define AUTH_OPEN 4
#define AUTH_OPEN_STD 5


int CheckSSLAuthentication(HTTPSession *Session, char *UserName)
{
char *ptr;

if (! Session->S) return(FALSE);
if (Settings.AuthFlags & FLAG_AUTH_CERT_SUFFICIENT)
{
  ptr=STREAMGetValue(Session->S,"SSL-Certificate-Verify");
  if (StrLen(ptr) && (strcmp(ptr,"OK")==0))
  {
  	ptr=STREAMGetValue(Session->S,"SSL-Certificate-CommonName");
		if (StrLen(ptr) && (strcmp(ptr,UserName)==0))
		{
			LogToFile(Settings.LogPath,"AUTH: SSL-Certificate Authentication sufficient for User '%s'",UserName);
			return(TRUE);
		}
  }
}

return(FALSE);
}


void AuthenticateExamineMethods(char *Methods)
{
char *ptr, *Token=NULL;
int MethodFound=AUTH_NONE;


LogToFile(Settings.LogPath,"CONSIDER AUTH METHODS: %s",Methods);

ptr=GetToken(Methods,",",&Token,0);
while (ptr)
{
	StripTrailingWhitespace(Token);
	StripLeadingWhitespace(Token);
	if (MatchTokenFromList(Token,AuthMethods,0) ==-1) LogToFile(Settings.LogPath,"WARNING: unknown authentication method '%s'",Token);
	else if (strcasecmp(Token,"digest")==0) 
	{
		if (MethodFound==AUTH_NONE) MethodFound=AUTH_DIGEST;
		else MethodFound=AUTH_DIGEST_STD;
		Settings.AuthFlags |= FLAG_AUTH_DIGEST;
	}
	else if (strcasecmp(Token,"open")==0) 
	{
		if (MethodFound==AUTH_NONE) MethodFound=AUTH_OPEN;
		else MethodFound=AUTH_OPEN_STD;
		Settings.AuthFlags &= ~FLAG_AUTH_REQUIRED;
	}
	else switch (MethodFound)
	{
		case AUTH_DIGEST:
		case AUTH_DIGEST_STD:
			MethodFound=AUTH_DIGEST_STD;
		break;

		case AUTH_OPEN:
		case AUTH_OPEN_STD:
			MethodFound=AUTH_OPEN_STD;
		break;

		case AUTH_NONE:
		case AUTH_STD:
			MethodFound=AUTH_STD;
		break;
	}
ptr=GetToken(ptr,",",&Token,0);
}

	if ((Settings.AuthFlags & FLAG_AUTH_REQUIRED) && (MethodFound==AUTH_NONE))
	{
		 LogToFile(Settings.LogPath,"WARNING: NO AUTHENTICATION SYSTEM CONFIGURED, but not set to run as an 'open' system");
	}
	else if (MethodFound==AUTH_OPEN_STD)
	{
		LogToFile(Settings.LogPath,"WARNING: 'open' authentication is enabled along with other authentication types. 'open' authentication means no authentication, so other auth types will be disabled.");
	}
	else if (MethodFound==AUTH_DIGEST_STD)
	{
		LogToFile(Settings.LogPath,"WARNING: 'digest' authentication is enabled along with other authentication types. Digest authentication requires plain-text passwords in the *native* alaya authentication file, and cannot authenticate against /etc/passwd, /etc/shadow or PAM.  Most clients will use digest in preference to 'basic' authentication. Thus including 'digest' will thus disable other authentication types.");
	}

DestroyString(Token);
}


int CheckUserExists(char *UserName)
{
HTTPSession *Session;
int result=FALSE;

if (! UserName) return(FALSE);

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));
Session->UserName=CopyStr(Session->UserName,UserName);
Session->Password=CopyStr(Session->Password,"");

if (AuthPasswdFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthNativeFile(Session,FALSE) != USER_UNKNOWN) result=TRUE;

DestroyString(Session->UserName);
DestroyString(Session->Password);

free(Session);

return(result);
}





int CheckServerAllowDenyLists(char *UserName)
{
char *ptr, *Token=NULL;

if (StrLen(Settings.DenyUsers))
{
ptr=GetToken(Settings.DenyUsers,",",&Token,GETTOKEN_QUOTES);

while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		LogToFile(Settings.LogPath,"AUTH: UserName '%s' in 'DenyUsers' list. Login Denied",UserName);
		DestroyString(Token);
		return(FALSE);
	}
	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
}

}

if (! StrLen(Settings.AllowUsers))
{
DestroyString(Token);
return(TRUE);
}

ptr=GetToken(Settings.AllowUsers,",",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Found in 'AllowUsers' list.",UserName);
		DestroyString(Token);
		return(TRUE);
	}
	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
}

return(FALSE);
}


int CheckAccessToken(HTTPSession *Session, char *Salt, char *URL, char *ClientIP, char *CorrectToken)
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


int AuthAccessToken(HTTPSession *Session)
{
char *URL=NULL, *Salt=NULL;
char *ptr;
int result=FALSE;

//if (! (Session->Flags & FLAG_AUTH_ACCESS_TOKEN)) return(FALSE);
if (StrLen(Settings.AccessTokenKey)==0) return(FALSE);

URL=FormatURL(URL,Session,Session->Path);

//Password will be in format <salt>:<access token>
ptr=GetToken(Session->Password,":",&Salt,0);


if (StrLen(Salt) && (StrLen(ptr)))
{
	if ((strncmp(Session->ClientIP,"::ffff:",7)==0) && (CheckAccessToken(Session, Salt, URL, Session->ClientIP+7, ptr))) result=TRUE;
	else if (CheckAccessToken(Session, Salt, URL, Session->ClientIP, ptr)) result=TRUE;
	else if (CheckAccessToken(Session, Salt, URL, "*", ptr)) result=TRUE;

	if (result)
	{ 
		LogToFile(Settings.LogPath,"AUTH: Client Authenticated with AccessToken for %s", Session->UserName);
	}
	else LogToFile(Settings.LogPath,"AUTH: AccessToken Failed for %s@%s", Session->UserName,Session->ClientIP);
}

AuthenticationsTried=CatStr(AuthenticationsTried,"accesstoken ");

DestroyString(Salt);
DestroyString(URL);

return(result);
}


char *GetUserHomeDir(char *RetBuff, char *UserName)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *Dir=NULL, *ptr;
struct passwd *pass_struct;

Dir=CopyStr(RetBuff,"");

//First Try Native File
S=STREAMOpenFile(Settings.AuthPath,O_RDONLY);
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
 	 StripTrailingWhitespace(Tempstr);
		ptr=GetToken(Tempstr,":",&Token,0);
		if (strcmp(Token, UserName)==0)
		{
		ptr=GetToken(ptr,":",&Token,0);
		ptr=GetToken(ptr,":",&Token,0);
		ptr=GetToken(ptr,":",&Token,0);
		ptr=GetToken(ptr,":",&Dir,0);
		break;
		}
	Tempstr=STREAMReadLine(Tempstr,S);
	}
STREAMClose(S);
}

if (! StrLen(Dir))
{
pass_struct=getpwnam(UserName);
if (pass_struct) Dir=CopyStr(Dir,pass_struct->pw_dir);
}

DestroyString(Tempstr);
DestroyString(Token);

return(Dir);
}


int AuthPasswdFile(HTTPSession *Session)
{
struct passwd *pass_struct;
char *ptr;

pass_struct=getpwnam(Session->UserName);
if (pass_struct==NULL) return(USER_UNKNOWN);

#ifdef HAVE_LIBCRYPT

if (
		StrLen(pass_struct->pw_passwd) && 
		StrLen(Session->Password)
	)
{
		ptr=crypt(Session->Password,pass_struct->pw_passwd);
		if (ptr && (strcmp(pass_struct->pw_passwd, ptr)==0) )
		{
			if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via /etc/passwd.",Session->UserName);
			Session->RealUser=CopyStr(Session->RealUser,Session->UserName);
			return(TRUE);
		}
}

AuthenticationsTried=CatStr(AuthenticationsTried,"passwd ");

#endif


return(FALSE);
}


int AuthShadowFile(HTTPSession *Session)
{
char *sptr, *eptr, *Salt=NULL, *Digest=NULL;
int result=FALSE;

#ifdef HAVE_SHADOW_H
#include <shadow.h>
struct spwd *pass_struct=NULL;

pass_struct=getspnam(Session->UserName);

if (pass_struct==NULL) return(USER_UNKNOWN);

sptr=pass_struct->sp_pwdp;

#ifdef HAVE_LIBCRYPT

if (CheckSSLAuthentication(Session, Session->UserName)) result=TRUE;
// this is an md5 password
else if (
	(StrLen(sptr) > 4) && 
	(strncmp(sptr,"$1$",3)==0)
   )
{
	eptr=strchr(sptr+3,'$');
  Salt=CopyStrLen(Salt,sptr,eptr-sptr);

  Digest=CopyStr(Digest, crypt(Session->Password,Salt));
  if (sptr && (strcmp(Digest,sptr)==0) )
	{
		result=TRUE;
	}
}
else
{
   // assume old des crypt password

   sptr=crypt(Session->Password,pass_struct->sp_pwdp);
   if (sptr && (strcmp(pass_struct->sp_pwdp, sptr)==0))
   {
      result=TRUE;
   }
}

AuthenticationsTried=CatStr(AuthenticationsTried,"shadow ");

#endif

if (result && (Settings.Flags & FLAG_LOG_VERBOSE)) 
{
	LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via /etc/shadow.",Session->UserName);
	Session->RealUser=CopyStr(Session->RealUser,Session->UserName);
}

#endif
DestroyString(Salt);
DestroyString(Digest);

return(result);
}



void ListNativeFile(char *Path)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ptr;

S=STREAMOpenFile(Settings.AuthPath,O_RDONLY);
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

DestroyString(Tempstr);
DestroyString(Token);
}



int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Args)
{
STREAM *S;
ListNode *Entries;
char *Tempstr=NULL, *Token=NULL, *Salt=NULL;
ListNode *Curr;
int RetVal=ERR_FILE;


Entries=ListCreate();
S=STREAMOpenFile(Settings.AuthPath,O_RDONLY);

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


S=STREAMOpenFile(Settings.AuthPath,O_WRONLY| O_CREAT | O_TRUNC);
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

		SwitchUser(RealUser);
		mkdir(HomeDir,0770);
	}

	STREAMClose(S);
	RetVal=ERR_OKAY;
}
else RetVal=ERR_FILE;

DestroyString(Tempstr);
DestroyString(Token);
DestroyString(Salt);

ListDestroy(Entries,DestroyString);

return(RetVal);
}
	


int NativeFileCheckPassword(char *Name, char *PassType, char *AuthStr,char *ProvidedPass)
{
char *Salt=NULL, *Password=NULL, *Digest=NULL, *Tempstr=NULL;
char *ptr;
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
		*ptr='\0';
		ptr++;
		Salt=CopyStr(Salt,AuthStr);
		Password=CopyStr(Password,ptr);
}
else 
{
	Salt=CopyStr(Salt,"");
	Password=CopyStr(Password,AuthStr);
}


if (StrLen(PassType) && StrLen(ProvidedPass))
{
	if (strcmp(PassType,"htdigest-md5")==0)
	{
		Tempstr=MCopyStr(Tempstr,Name,":",Settings.AuthRealm,":",ProvidedPass,NULL);
		HashBytes(&Digest,"md5",Tempstr,StrLen(Tempstr),ENCODE_HEX);
	}
	else if (StrLen(Salt))
	{
			//Salted passwords as of version 1.1.1
			Tempstr=MCopyStr(Tempstr,Name,":",ProvidedPass,":",Salt,NULL);
			HashBytes(&Digest, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
	}
	//Old-style unsalted passwords
	else HashBytes(&Digest,PassType,ProvidedPass,StrLen(ProvidedPass),ENCODE_HEX);
		
	if (StrLen(Digest) && (strcmp(Password,Digest)==0)) result=TRUE;
}

DestroyString(Tempstr);
DestroyString(Password);
DestroyString(Salt);
DestroyString(Digest);

return(result);
}



/* HTTP Digest format uses the algorithm MD5(H1,H2) where:

 H1 is MD5(<username>:<auth realm>:password)
 H2 is MD5(<http method>:<extra details>:<request URI>)

 <extra details> contains a number of values sent by the server and echoed back by the client
*/
int NativeFileCheckHTTPDigestAuth(HTTPSession *Session, char *PasswordType, char *Password,char *ProvidedPass)
{
char *Tempstr=NULL, *Digest1=NULL, *Digest2=NULL;
char *Algo=NULL, *URI=NULL, *p_AuthDetails;
int result=FALSE;


if (! ProvidedPass) return(FALSE);
if (! StrLen(PasswordType)) return(FALSE);
if (
			(strcmp(PasswordType, "plain") !=0) &&
			(strcmp(PasswordType, "htdigest-md5") !=0) 
	) return(FALSE);
	

	p_AuthDetails=GetToken(Session->AuthDetails,":",&URI,0);
	p_AuthDetails=GetToken(p_AuthDetails,":",&Algo,0);
	if (! StrLen(URI)) URI=CopyStr(URI,Session->Path);

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


DestroyString(Tempstr);
DestroyString(Digest1);
DestroyString(Digest2);
DestroyString(Algo);
DestroyString(URI);

return(result);
}



int AuthNativeFile(HTTPSession *Session, int HTTPDigest)
{
STREAM *S;
char *Tempstr=NULL, *ptr;
char *Name=NULL, *Pass=NULL, *RealUser=NULL, *HomeDir=NULL, *PasswordType=NULL, *UserSettings=NULL;
int RetVal=USER_UNKNOWN, result;
struct passwd *pass_struct;


S=STREAMOpenFile(Settings.AuthPath,O_RDONLY);
if (! S) return(USER_UNKNOWN);

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{

  StripTrailingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,":",&Name,0);
	ptr=GetToken(ptr,":",&PasswordType,0);
	ptr=GetToken(ptr,":",&Pass,0);
	ptr=GetToken(ptr,":",&RealUser,0);
	ptr=GetToken(ptr,":",&HomeDir,0);
	ptr=GetToken(ptr,":",&UserSettings,0);
	
  if (strcasecmp(Name,Session->UserName)==0)
  {
		RetVal=FALSE;

		if (CheckSSLAuthentication(Session, Name)) RetVal=TRUE;
		else if (HTTPDigest) RetVal=NativeFileCheckHTTPDigestAuth(Session, PasswordType, Pass, Session->Password);
		else RetVal=NativeFileCheckPassword(Name,PasswordType,Pass,Session->Password);

		if (RetVal)
    {
			Session->RealUser=CopyStr(Session->RealUser,RealUser);	
			Session->UserSettings=CopyStr(Session->UserSettings,UserSettings);	
			if (StrLen(HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,HomeDir);	
			else Session->HomeDir=GetUserHomeDir(Session->HomeDir,Session->RealUser);
    }
		break;
  }

  Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);

//Don't let them authenticate if HomeDir and user mapping not set

if (RetVal==TRUE)
{
	if (! StrLen(Session->RealUser)) 
	{
		Session->RealUser=CopyStr(Session->RealUser,Settings.DefaultUser);
	}
 
	if (! StrLen(Session->RealUser)) 
	{
		LogToFile(Settings.LogPath,"AUTH: No 'RealUser' set for '%s'. Login Denied",Session->UserName);
		RetVal=FALSE;
	}

	if (RetVal=TRUE)
	{
		pass_struct=getpwnam(Session->RealUser);
		if (pass_struct) Session->RealUserUID=pass_struct->pw_uid;
	
		if (! StrLen(Session->HomeDir)) 
		{
			LogToFile(Settings.LogPath,"AUTH: No 'HomeDir' set for '%s'. Login Denied",Session->UserName);
			RetVal=FALSE;
		}
	}
}


if ((RetVal==TRUE) && (Settings.Flags & FLAG_LOG_VERBOSE)) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via %s.",Session->UserName,Settings.AuthPath);

AuthenticationsTried=CatStr(AuthenticationsTried,"native ");

DestroyString(Name);
DestroyString(Pass);
DestroyString(Tempstr);
DestroyString(HomeDir);
DestroyString(RealUser);
DestroyString(UserSettings);
DestroyString(PasswordType);

return(RetVal);
}


#ifdef HAVE_LIBPAM

/* PAM works in a bit of a strange way, insisting on having a callback */
/* function that it uses to prompt for the password. We have arranged  */
/* to have the password passed in as the 'appdata' arguement, so this  */
/* function just passes it back!                                       */

int PAMConvFunc(int NoOfMessages, const struct pam_message **messages, 
         struct pam_response **responses, void *appdata)
{
int count;
struct pam_message *mess;
struct pam_response *resp;

*responses=(struct pam_response *) calloc(NoOfMessages,sizeof(struct pam_response));

mess=*messages;
resp=*responses;

for (count=0; count < NoOfMessages; count++)
{
if ((mess->msg_style==PAM_PROMPT_ECHO_OFF) ||
    (mess->msg_style==PAM_PROMPT_ECHO_ON))
    {
      resp->resp=CopyStr(NULL,(char *) appdata); 
      resp->resp_retcode=0;
    }
mess++;
resp++;
}

return(PAM_SUCCESS);
}




int AuthPAM(HTTPSession *Session)
{
static pam_handle_t *pamh;
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
int result;

PAMConvStruct.appdata_ptr=(void *)Session->Password;

result=pam_start("alaya",Session->UserName,&PAMConvStruct,&pamh); 

if (result != PAM_SUCCESS)
{
		pam_end(pamh,result);
		result=pam_start("other",Session->UserName,&PAMConvStruct,&pamh);
}

if (result != PAM_SUCCESS)
{
	pam_end(pamh,result);
  return(USER_UNKNOWN);
}

/* set the credentials for the remote user and remote host */
pam_set_item(pamh,PAM_RUSER,Session->UserName);
if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
else pam_set_item(pamh,PAM_RHOST,"");

result=pam_authenticate(pamh,0);

pam_end(pamh,PAM_SUCCESS);

AuthenticationsTried=CatStr(AuthenticationsTried,"pam ");

if (result==PAM_SUCCESS)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via PAM.",Session->UserName);
 return(TRUE);
}
else return(FALSE);
}
#endif


int Authenticate(HTTPSession *Session)
{
int result=0, Authenticated=FALSE;
char *Token=NULL, *ptr;
struct passwd *pwent;
struct group *grent;

AuthenticationsTried=CopyStr(AuthenticationsTried,"");
if (! CheckUserExists(Session->UserName))
{
	LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->UserName,AuthenticationsTried);
 return(FALSE);
}

AuthenticationsTried=CopyStr(AuthenticationsTried,"");
Session->RealUser=CopyStr(Session->RealUser,Session->UserName);
pwent=getpwnam(Session->UserName);

if (pwent)
{
Session->RealUserUID=pwent->pw_uid;
}

//grent=getgrnam(Session->Group);

if (! StrLen(Session->HomeDir)) Session->HomeDir=GetUserHomeDir(Session->HomeDir,Session->UserName);

if (! CheckServerAllowDenyLists(Session->UserName)) 
{
	LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. User not allowed to log in",Session->UserName);
	return(FALSE);
}

ptr=GetToken(Settings.AuthMethods,",",&Token,0);

while (ptr)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: Try to authenticate '%s' via '%s'. Remaining authentication types: %s",Session->UserName, Token, ptr);
	if (strcasecmp(Token,"native")==0) result=AuthNativeFile(Session,FALSE);
	else if (strcasecmp(Token,"digest")==0) result=AuthNativeFile(Session,TRUE);
	else if (strcasecmp(Token,"shadow")==0) result=AuthShadowFile(Session);
	else if (strcasecmp(Token,"passwd")==0) result=AuthPasswdFile(Session);
	else if (strcasecmp(Token,"accesstoken")==0) result=AuthAccessToken(Session);
	#ifdef HAVE_LIBPAM
	else if (strcasecmp(Token,"pam")==0) result=AuthPAM(Session);
	else if (strcasecmp(Token,"none")==0) 
	{
		result=FALSE;
		break;
	}
	else if (strcasecmp(Token,"deny")==0) 
	{
		result=FALSE;
		break;
	}
	#endif

	if (result==TRUE) break;
	ptr=GetToken(ptr,",",&Token,0);
}

if (result==USER_UNKNOWN) LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->UserName,AuthenticationsTried);
else if (result==FALSE) LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. Bad Password/Credentials. Tried methods: %s ",Session->UserName,AuthenticationsTried);

//We no longer care if it was 'user unknown' or 'password wrong'
if (result !=TRUE) result=FALSE;


DestroyString(Token);
return(result);
}


char *GetDefaultUser()
{
char *Possibilities[]={"wwwrun","nobody","daemon","guest",NULL};
HTTPSession *Session;
int i;

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

for (i=0; Possibilities[i] !=NULL; i++)
{
	Session->UserName=CopyStr(Session->UserName,Possibilities[i]);
	Session->Password=CopyStr(Session->Password,"");
	if (AuthPasswdFile(Session) != USER_UNKNOWN) break;
} 
    
return(Possibilities[i]);  
}
