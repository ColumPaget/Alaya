#ifndef ALAYA_URL_SHORT_H
#define ALAYA_URL_SHORT_H

#include "common.h"
#include "http_session.h"

#define SHORT_ACT_NONE   0
#define SHORT_ACT_STORE  1
#define SHORT_ACT_QUERY  2


#ifdef USE_URL_SHORTENER

char *URLShortFindInFile(char *URL, const char *Short, STREAM *S);
char *URLShortFind(char *URL, const char *Short, const char *Dir);
void URLShortAdd(const char *Dir, const char *URL);
int URLShortHandle(HTTPSession *Session);

#endif

#endif
