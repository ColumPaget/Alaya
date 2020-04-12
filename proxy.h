#ifndef ALAYA_PROXY_H
#define ALAYA_PROXY_H

#include "common.h"

int IsProxyMethod(int Method);
void HTTPProxyRGETURL(HTTPSession *Session);
void HTTPProxyConnect(HTTPSession *Session);
void SocksProxyConnect(HTTPSession *Session);

#endif

