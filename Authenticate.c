#include "Authenticate.h"
#include "AccessTokens.h"
#include <pwd.h>

#define USER_UNKNOWN -1

#define ENC_MD5_HEX 0
#define ENC_MD5_BASE64 1

#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif


#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>
static pam_handle_t *pamh=NULL;
#endif


char *AuthenticationsTried=NULL;

const char *AuthMethods[]={"none","open","deny","native","pam","pam-account","passwd","shadow","digest","certificate","accesstoken","cookie",NULL};
typedef enum {AUTHTOK_NONE, AUTHTOK_OPEN, AUTHTOK_DENY, AUTHTOK_NATIVE, AUTHTOK_PAM, AUTHTOK_PAM_ACCT, AUTHTOK_PASSWD, AUTHTOK_SHADOW, AUTHTOK_DIGEST, AUTHTOK_CERTIFICATE, AUTHTOK_ACCESSTOKEN, AUTHTOK_ACCESSTOKEN_HTTP, AUTHTOK_COOKIE} TAuthTokens;



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




int AuthenticateExamineMethods(char *Methods, int LogErrors)
{
char *ptr, *Token=NULL;
int MethodsFound=0, val;


LogToFile(Settings.LogPath,"CONSIDER AUTH METHODS: %s",Methods);

ptr=GetToken(Methods,",",&Token,0);
while (ptr)
{
	StripTrailingWhitespace(Token);
	StripLeadingWhitespace(Token);
	val=MatchTokenFromList(Token,AuthMethods,0); 
	switch (val)
	{
		case -1:
			if (LogErrors) LogToFile(Settings.LogPath,"WARNING: unknown authentication method '%s'",Token);
		break;

		case AUTHTOK_NONE: 
		case AUTHTOK_OPEN:
			MethodsFound |= AUTH_OPEN;
		break;

		case AUTHTOK_DENY:
			MethodsFound |= AUTH_DENY;
		break;

		case AUTHTOK_NATIVE:
			MethodsFound |= AUTH_NATIVE;
		break;

		case AUTHTOK_PAM:
			MethodsFound |= AUTH_PAM;
		break;

		case AUTHTOK_PASSWD:
			MethodsFound |= AUTH_PASSWD;
		break;

		case AUTHTOK_SHADOW:
			MethodsFound |= AUTH_SHADOW;
		break;

		case AUTHTOK_DIGEST:
			MethodsFound |= AUTH_DIGEST;
		break;

		case AUTHTOK_ACCESSTOKEN:
			MethodsFound |= AUTH_ACCESSTOKEN;
		break;

		case AUTHTOK_ACCESSTOKEN_HTTP:
		break;
	}

ptr=GetToken(ptr,",",&Token,0);
}



if (LogErrors)
{
	if ((Settings.AuthFlags & FLAG_AUTH_REQUIRED) && (MethodsFound == 0))
	{
	 LogToFile(Settings.LogPath,"WARNING: NO AUTHENTICATION SYSTEM CONFIGURED, but not set to run as an 'open' system");
	}
	else if ((MethodsFound & AUTH_OPEN) && (MethodsFound != AUTH_OPEN))
	{
		LogToFile(Settings.LogPath,"WARNING: 'open' authentication is enabled along with other authentication types. 'open' authentication means no authentication, so other auth types will be disabled.");
	}
	else if (  (MethodsFound & AUTH_DIGEST) && (((MethodsFound & ~(AUTH_DIGEST | AUTH_ACCESSTOKEN)) !=0) ) )
	{
		LogToFile(Settings.LogPath,"WARNING: 'digest' authentication is enabled along with other authentication types. Digest authentication requires plain-text passwords in the *native* alaya authentication file, and cannot authenticate against /etc/passwd, /etc/shadow or PAM.  Most clients will use digest in preference to 'basic' authentication. Thus including 'digest' will thus disable other authentication types.");
	}
}

DestroyString(Token);

return(MethodsFound);
}






int CheckServerAllowDenyLists(char *UserName)
{
char *ptr, *Token=NULL;
int result=FALSE;

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

if (! StrLen(Settings.AllowUsers)) result=TRUE;
else
{
	ptr=GetToken(Settings.AllowUsers,",",&Token,GETTOKEN_QUOTES);
	while (ptr)
	{
		if (strcmp(Token,UserName)==0)
		{
			if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Found in 'AllowUsers' list.",UserName);
			result=TRUE;
			break;
		}
		ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
	}
}
DestroyString(Token);
return(result);
}



int AuthPasswdFile(HTTPSession *Session, char **RealUser, char **HomeDir)
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
			if (RealUser) *RealUser=CopyStr(*RealUser,Session->UserName);
			if (HomeDir) *HomeDir=CopyStr(*HomeDir, pass_struct->pw_dir);
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

// this is an md5 password
if (
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

S=STREAMOpenFile(Settings.AuthPath,SF_RDONLY);
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
S=STREAMOpenFile(Settings.AuthPath,SF_RDONLY);

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


S=STREAMOpenFile(Settings.AuthPath,SF_WRONLY| SF_CREAT | SF_TRUNC);
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



int AuthNativeFile(HTTPSession *Session, int HTTPDigest, char **RealUser, char **HomeDir, char **UserSettings)
{
STREAM *S;
char *Tempstr=NULL, *ptr;
char *Name=NULL, *Pass=NULL, *PasswordType=NULL, *Trash=NULL;
int RetVal=USER_UNKNOWN;


S=STREAMOpenFile(Settings.AuthPath,SF_RDONLY);
if (! S) return(USER_UNKNOWN);

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{

  StripTrailingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,":",&Name,0);

  if (strcasecmp(Name,Session->UserName)==0)
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
		else RetVal=NativeFileCheckPassword(Name,PasswordType,Pass,Session->Password);

		break;
  }

  Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);


if ((RetVal==TRUE) && (Settings.Flags & FLAG_LOG_VERBOSE)) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via %s.",Session->UserName,Settings.AuthPath);

AuthenticationsTried=CatStr(AuthenticationsTried,"native ");

DestroyString(Name);
DestroyString(Pass);
DestroyString(Tempstr);
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
const struct pam_message *mess;
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


int PAMStart(HTTPSession *Session, const char *User)
{
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
const char *PAMConfigs[]={"alaya","httpd","other",NULL};
int result=PAM_PERM_DENIED, i;

  PAMConvStruct.appdata_ptr=(void *)Session->Password;

  for (i=0; (PAMConfigs[i] != NULL) && (result != PAM_SUCCESS); i++)
  {
    result=pam_start(PAMConfigs[i],User,&PAMConvStruct,&pamh);
  }

  if (result==PAM_SUCCESS)
  {
  pam_set_item(pamh,PAM_RUSER,Session->UserName);
  if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
  else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
  else pam_set_item(pamh,PAM_RHOST,"");
  return(TRUE);
  }

  return(FALSE);
}


int AuthPAM(HTTPSession *Session)
{
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
int result;

result=PAMStart(Session, Session->UserName);
if (result != PAM_SUCCESS)
{
	pam_end(pamh,result);
  return(USER_UNKNOWN);
}

result=pam_authenticate(pamh,0);

AuthenticationsTried=CatStr(AuthenticationsTried,"pam ");

if (result==PAM_SUCCESS)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via PAM.",Session->UserName);
 return(TRUE);
}
else return(FALSE);
}




int AuthPAMCheckAccount(HTTPSession *Session)
{
if (! pamh)
{
  if (! PAMStart(Session, Session->RealUser)) return(FALSE);
}

if (pam_acct_mgmt(pamh, 0)==PAM_SUCCESS)
{
  pam_open_session(pamh, 0);
  return(TRUE);
}
return(FALSE);
}



void AuthPAMClose()
{
  if (pamh)
  {
  pam_close_session(pamh, 0);
  pam_end(pamh,PAM_SUCCESS);
  }
}
#endif




int AuthenticateLookupUserDetails(HTTPSession *Session)
{
struct passwd *pwent;

//if we haven't got a real user, first try looking in the 'native' authentication
//file to find a mapping from UserName to RealUser
if (! StrLen(Session->RealUser))
{
	AuthNativeFile(Session, FALSE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
}

//if we didn't find a 'real user' in the native file, try looking the username up in the system
//password file to confirm it is a real username
if (! StrLen(Session->RealUser)) 
{
	Session->RealUser=CopyStr(Session->RealUser,Session->UserName);
	pwent=getpwnam(Session->RealUser);

	//if we didn't find it, then set our real user to be the server default user
  //though really, at this point, it's a mystery where this user is configured
	if (! pwent) Session->RealUser=CopyStr(Session->RealUser,Settings.DefaultUser);
}

//Have to do this again in case first try failed
pwent=getpwnam(Session->RealUser);
if (pwent)
{
	Session->RealUserUID=pwent->pw_uid;

	if (! StrLen(Session->HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,pwent->pw_dir);
	//grent=getgrnam(Session->Group);
}

}



int Authenticate(HTTPSession *Session)
{
int result=0;
char *Token=NULL, *ptr;
int PAMAccount=FALSE;
//struct group *grent;

AuthenticationsTried=CopyStr(AuthenticationsTried,"");

if (! CheckServerAllowDenyLists(Session->UserName)) 
{
	LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. User not allowed to log in",Session->UserName);
	return(FALSE);
}


//check for this as it changes behavior of other auth types
ptr=GetToken(Settings.AuthMethods,",",&Token,0);
while (ptr)
{
  if (strcasecmp(Token,"pam-account")==0) PAMAccount=TRUE;
  ptr=GetToken(ptr,",",&Token,0);
}

ptr=GetToken(Settings.AuthMethods,",",&Token,0);

while (ptr)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: Try to authenticate '%s' via '%s'. Remaining authentication types: %s",Session->UserName, Token, ptr);

	if (strcasecmp(Token,"open")==0) result=TRUE;
	else if (strcasecmp(Token,"native")==0) result=AuthNativeFile(Session,FALSE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
	else if (strcasecmp(Token,"digest")==0) result=AuthNativeFile(Session,TRUE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
	else if (strcasecmp(Token,"passwd")==0) result=AuthPasswdFile(Session, &Session->RealUser, &Session->HomeDir);
	else if (strcasecmp(Token,"shadow")==0) result=AuthShadowFile(Session);
	else if (strcasecmp(Token,"cert")==0) result=CheckSSLAuthentication(Session, Session->UserName);
	else if (strcasecmp(Token,"certificate")==0) result=CheckSSLAuthentication(Session, Session->UserName);
	else if (strcasecmp(Token,"accesstoken")==0) result=AuthAccessToken(Session, Session->Password);
	else if (strcasecmp(Token,"cookie")==0) result=AccessTokenAuthCookie(Session);

	#ifdef HAVE_LIBPAM
	else if (strcasecmp(Token,"pam")==0) 
	{
		result=AuthPAM(Session);
		if (result==TRUE) PAMAccount=TRUE;
	}
	#endif
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

	if (result==TRUE)
  {
    LogToFile(Settings.LogPath,"AUTH: Client Authenticated with %s for %s@%s", Token, Session->UserName,Session->ClientIP);
		break;
  }

	AuthenticationsTried=MCatStr(AuthenticationsTried,Token," ",NULL);

	ptr=GetToken(ptr,",",&Token,0);
}


switch (result)
{
case TRUE:
AuthenticateLookupUserDetails(Session);

if (Session->RealUserUID==0)
{
	LogToFile(Settings.LogPath,"AUTH: No 'RealUser' for '%s'. Login Denied",Session->UserName);
	result=FALSE;
}
if (! StrLen(Session->HomeDir)) 
{
	LogToFile(Settings.LogPath,"AUTH: No 'HomeDir' set for '%s'. Login Denied",Session->UserName);
	result=FALSE;
}

//Use PAMCheckAccount to check if account is allowed to login even if authenticated
if (result && PAMAccount)
{
#ifdef HAVE_LIBPAM
  if (! AuthPAMCheckAccount(Session))
  {
    LogToFile(Settings.LogPath,"PAM Account invalid for '%s'. Login Denied",Session->UserName);
    result=FALSE;
  }
#endif
}
break;


case USER_UNKNOWN: 
	LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->UserName,AuthenticationsTried); 
break;

case FALSE: 
	LogToFile(Settings.LogPath,"AUTH: Authentication failed for UserName '%s'. Bad Password/Credentials. Tried methods: %s ",Session->UserName,AuthenticationsTried);
break;
}


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
	if (AuthPasswdFile(Session, NULL, NULL) != USER_UNKNOWN) break;
} 
    
return(Possibilities[i]);  
}



int CheckUserExists(char *UserName)
{
HTTPSession *Session;
int result=FALSE;

if (! UserName) return(FALSE);

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));
Session->UserName=CopyStr(Session->UserName,UserName);
Session->Password=CopyStr(Session->Password,"");

if (AuthPasswdFile(Session, NULL, NULL) != USER_UNKNOWN) result=TRUE;
if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthNativeFile(Session,FALSE, NULL, NULL, NULL) != USER_UNKNOWN) result=TRUE;

DestroyString(Session->UserName);
DestroyString(Session->Password);

free(Session);

return(result);
}


