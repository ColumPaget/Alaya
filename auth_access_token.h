#ifndef ALAYA_ACCESSTOKENS_H
#define ALAYA_ACCESSTOKENS_H

#include "common.h"
#include "http_session.h"


void ParseAccessToken(HTTPSession *Session);
int AuthAccessToken(HTTPSession *Session, const char *AccessToken);
int AccessTokenAuthCookie(HTTPSession *Session);
char *MakeAccessToken(char *Buffer, const char *User, const char *Key, const char *Salt, const char *RequestingHost, const char *RequestURL);
char *MakeAccessCookie(char *RetStr, HTTPSession *Session);

int AuthURLToken(HTTPSession *Session, const char *AccessToken);


#endif
