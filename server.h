#ifndef WEBSERV_SERVER_H
#define WEBSERV_SERVER_H

#include "common.h"

#define HTTP_ENCODE_GZIP 1
#define HTTP_ENCODE_XGZIP 2
#define HTTP_ICECAST 4
#define HTTP_OVERWRITE 8
#define HTTP_KEEP_ALIVE 16
#define HTTP_REUSE_SESSION 32
#define HTTP_AUTHENTICATED 64

//Only used by 'HTTPServerSendHeaders'
#define HEADERS_CGI 1 
#define HEADERS_AUTH 2
#define HEADERS_USECACHE 4
#define HEADERS_SENDFILE 8
#define HEADERS_KEEPALIVE 16

typedef enum {METHOD_HEAD, METHOD_GET,METHOD_POST,METHOD_PUT,METHOD_DELETE,METHOD_MKCOL,METHOD_PROPFIND,METHOD_PROPPATCH,METHOD_MOVE,METHOD_COPY,METHOD_OPTIONS, METHOD_CONNECT, METHOD_RGET,METHOD_RPOST} TMethodTypes;

HTTPSession *HTTPSessionCreate();
void HTTPServerHandleConnection(HTTPSession *Session);
void HTTPServerSendResponse(STREAM *S, HTTPSession *Heads, char *ResponseLine, char *ContentType, char *Body);

void HTTPServerSendFile(STREAM *S, HTTPSession *Session, char *Path, ListNode *Vars, int SendData);

#endif
