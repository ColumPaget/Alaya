#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

void AuthenticateExamineMethods(char *Methods);
int CheckUserExists(char *);
int Authenticate(HTTPSession *);
int AuthPasswdFile(HTTPSession *);
int AuthShadowFile(HTTPSession *);
int AuthNativeFile(HTTPSession *, int HTTPDigest);
int AuthMD5(HTTPSession *);
int AuthPAM(HTTPSession *);
//void EncodeMD5(char *, char *,int);
char *GetUserHomeDir(char *RetStr, char *UserName);
char *GetDefaultUser();


int CheckServerAllowDenyLists(char *UserName);
void ListNativeFile(char *Path);
int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Args);
;
#endif
