#ifndef ALAYA_ACCESSTOKENS_H
#define ALAYA_ACCESSTOKENS_H

#include "common.h"


void ParseAccessToken(HTTPSession *Session);
int AuthAccessToken(HTTPSession *Session, const char *AccessToken);
int AccessTokenAuthCookie(HTTPSession *Session);
char *MakeAccessToken(char *Buffer, const char *User, const char *Salt, const char *RequestingHost, const char *RequestURL);
int CheckAccessToken(HTTPSession *Session, const char *User, const char *Salt, const char *URL, const char *ClientIP, const char *CorrectToken);
char *MakeAccessCookie(char *RetStr, HTTPSession *Session);


#endif
