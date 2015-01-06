#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

void AuthenticateExamineMethods(char *Methods);
int CheckUserExists(char *);
int Authenticate(HTTPSession *);
int AuthPAM(HTTPSession *);
char *GetDefaultUser();


int CheckServerAllowDenyLists(char *UserName);
void ListNativeFile(char *Path);
int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Args);
;
#endif
