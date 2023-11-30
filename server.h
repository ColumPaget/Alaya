#ifndef WEBSERV_SERVER_H
#define WEBSERV_SERVER_H

#include "common.h"

//Only used by 'AlayaServerSendHeaders'
#define HEADERS_CGI 1
#define HEADERS_AUTH 2
#define HEADERS_USECACHE 4
#define HEADERS_SENDFILE 8
#define HEADERS_KEEPALIVE 16
#define HEADERS_POST 32
#define HEADERS_XSSI 64

#define DIR_READONLY 4096

typedef enum {METHOD_HEAD, METHOD_GET,METHOD_POST,METHOD_PUT,METHOD_DELETE,METHOD_MKCOL,METHOD_PROPFIND,METHOD_PROPPATCH,METHOD_MOVE,METHOD_COPY,METHOD_OPTIONS, METHOD_CONNECT, METHOD_LOCK, METHOD_UNLOCK, METHOD_MKCALENDAR, METHOD_REPRT, METHOD_RGET,METHOD_RPOST,METHOD_WEBSOCKET, METHOD_WEBSOCKET75} TMethodTypes;

HTTPSession *HTTPSessionCreate();
void HTTPServerHandleConnection(HTTPSession *Session);
void HTTPServerHandlePost(STREAM *S, HTTPSession *Session);
int HTTPServerActivateSSL(HTTPSession *Session,ListNode *Keys);
void AlayaServerSendHeaders(STREAM *S, HTTPSession *Session, int Flags);
void AlayaServerSendHTML(STREAM *S, HTTPSession *Session, const char *Title, const char *Body);
void AlayaServerSendResponse(STREAM *S, HTTPSession *Heads, const char *ResponseLine, const char *ContentType, const char *Body);
void AlayaServerSendFile(STREAM *S, HTTPSession *Session, const char *Path, ListNode *Vars, int SendData);
int HTTPServerExecCGI(STREAM *ClientCon, HTTPSession *Session, const char *ScriptPath);
void AlayaServerSendDocument(STREAM *S, HTTPSession *Session, const char *Path, int Flags);
int HTTPServerDecideToCompress(HTTPSession *Session, const char *Path);
int HTTPServerReadBody(HTTPSession *Session, char **Data);
void HTTPServerHandleStream(STREAM *Output, HTTPSession *Session, const char *SearchPath, int SendData);
void HTTPServerParsePostContentType(HTTPSession *Session, const char *Data);
#endif
