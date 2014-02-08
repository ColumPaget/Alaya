#ifndef WEBSERV_PROXY_H
#define WEBSERV_PROXY_H

#include "common.h"

int IsProxyMethod(int Method);
void HTTPProxyRGETURL(STREAM *S,HTTPSession *Session);
void HTTPProxyConnect(STREAM *S,HTTPSession *ClientHeads);

#endif

