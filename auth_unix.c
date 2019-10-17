/*
This file contains functions related to authentication via unix /etc/passwd and /etc/shadow files
*/

#include "auth_unix.h"

#include <pwd.h>
#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif



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


#endif

if (result && (Settings.Flags & FLAG_LOG_VERBOSE)) 
{
	LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via /etc/shadow.",Session->UserName);
}

#endif
Destroy(Salt);
Destroy(Digest);

return(result);
}


