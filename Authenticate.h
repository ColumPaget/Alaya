#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

#define AUTH_OPEN 1
#define AUTH_DENY 2
#define AUTH_NATIVE 4 
#define AUTH_PAM  8
#define AUTH_PASSWD 16 
#define AUTH_SHADOW 32
#define AUTH_DIGEST 64
#define AUTH_ACCESSTOKEN 128




int AuthenticateExamineMethods(char *Methods, int LogErrors);
int CheckUserExists(char *);
int Authenticate(HTTPSession *);
int AuthPAM(HTTPSession *);
char *GetDefaultUser();


int CheckServerAllowDenyLists(char *UserName);
void ListNativeFile(char *Path);
int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Args);
;
#endif
