/*
This file contains functions related to authentication via unix /etc/passwd and /etc/shadow files
*/

#ifndef ALAYA_AUTH_UNIX
#define ALAYA_AUTH_UNIX

#include "Authenticate.h"
#include "http_session.h"

int AuthPasswdFile(HTTPSession *Session, char **RealUser, char **HomeDir);
int AuthShadowFile(HTTPSession *Session);

#endif
