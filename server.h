#ifndef WEBSERV_SERVER_H
#define WEBSERV_SERVER_H

#include "common.h"

//Only used by 'HTTPServerSendHeaders'
#define HEADERS_CGI 1 
#define HEADERS_AUTH 2
#define HEADERS_USECACHE 4
#define HEADERS_SENDFILE 8
#define HEADERS_KEEPALIVE 16
#define HEADERS_POST 32

typedef enum {METHOD_HEAD, METHOD_GET,METHOD_POST,METHOD_PUT,METHOD_DELETE,METHOD_MKCOL,METHOD_PROPFIND,METHOD_PROPPATCH,METHOD_MOVE,METHOD_COPY,METHOD_OPTIONS, METHOD_CONNECT, METHOD_RGET,METHOD_RPOST,METHOD_WEBSOCKET, METHOD_WEBSOCKET75} TMethodTypes;

HTTPSession *HTTPSessionCreate();
void HTTPServerHandleConnection(HTTPSession *Session);
void HTTPServerSendHeaders(STREAM *S, HTTPSession *Session, int Flags);
void HTTPServerSendHTML(STREAM *S, HTTPSession *Session, char *Title, char *Body);
void HTTPServerSendResponse(STREAM *S, HTTPSession *Heads, char *ResponseLine, char *ContentType, char *Body);

void HTTPServerSendFile(STREAM *S, HTTPSession *Session, char *Path, ListNode *Vars, int SendData);
void HTTPServerSendDocument(STREAM *S, HTTPSession *Session, char *Path, int Flags);
int HTTPServerDecideToCompress(HTTPSession *Session, char *Path);

#endif
