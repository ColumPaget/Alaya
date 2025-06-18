/*

This file contains functions related to alaya's native authentication system

*/

#ifndef ALAYA_AUTH_NATIVE_H
#define ALAYA_AUTH_NATIVE_H

#include "Authenticate.h"
#include "http_session.h"


void AuthNativeListUsers(const char *Path);
int AuthNativeChange( const char *Path,  const char *Name,  const char *PassType,  const char *Pass,  const char *HomeDir,  const char *RealUser,  const char *Args);
int AuthNativeCheck(HTTPSession *Session, int HTTPDigest, char **RealUser, char **HomeDir, char **UserSettings);

#endif
