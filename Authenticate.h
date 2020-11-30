#ifndef ALAYA_AUTH_H
#define ALAYA_AUTH_H

#include "common.h"

#define USER_UNKNOWN -1

#define AUTH_OPEN 1
#define AUTH_DENY 2
#define AUTH_NATIVE 4
#define AUTH_PAM  8
#define AUTH_PASSWD 16
#define AUTH_SHADOW 32
#define AUTH_DIGEST 64
#define AUTH_ACCESSTOKEN 128




int AuthenticateExamineMethods(const char *Methods, int LogErrors);
int CheckServerAllowDenyLists(const char *UserName);
int CheckUserExists(const char *UserName);
int AuthenticateLookupUserDetails(HTTPSession *Session);
int Authenticate(HTTPSession *Session);
const char *GetDefaultUser();


void AuthNativeListUsers(const char *Path);
int AuthNativeChange(const char *Path, const char *Name, const char *PassType, const char *Pass, const char *HomeDir, const char *RealUser, const char *Args);
;
#endif
