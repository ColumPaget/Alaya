#ifndef WEBSERV_SERVER_H
#define WEBSERV_SERVER_H

#include "common.h"

#define HTTP_ENCODE_GZIP 1
#define HTTP_ENCODE_XGZIP 2
#define HTTP_ICECAST 4
#define HTTP_OVERWRITE 8


//Only used by 'HTTPServerSendHeaders'
#define HEADERS_CGI 1 
#define HEADERS_AUTH 2

typedef enum {METHOD_HEAD, METHOD_GET,METHOD_POST,METHOD_PUT,METHOD_DELETE,METHOD_MKCOL,METHOD_PROPFIND,METHOD_PROPPATCH,METHOD_MOVE,METHOD_COPY,METHOD_OPTIONS, METHOD_CONNECT, METHOD_RGET,METHOD_RPOST} TMethodTypes;

HTTPSession *HTTPSessionCreate();
void HTTPServerHandleConnection(HTTPSession *Session);
void HTTPServerSendResponse(STREAM *S, HTTPSession *Heads, char *ResponseLine, char *ContentType, char *Body);

void HTTPServerSendFile(STREAM *S, HTTPSession *Session, char *Path, ListNode *Vars, int SendData);

#endif
