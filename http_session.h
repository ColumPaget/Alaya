#ifndef ALAYA_HTTP_SESSION
#define ALAYA_HTTP_SESSION

#include "common.h"




//Flag values for Session->Flags
#define SESSION_ENCODE_GZIP      1
#define SESSION_ENCODE_XGZIP     2
#define SESSION_OVERWRITE        8
#define SESSION_KEEPALIVE       16
#define SESSION_REUSE           32
#define SESSION_SSL            128
#define SESSION_ICECAST        256
#define SESSION_AUTHENTICATED 1024
#define SESSION_AUTH_FAIL     2048
#define SESSION_ERR_BADURL    4096
#define SESSION_ALLOW_UPLOAD  8192
#define SESSION_UPLOAD_DONE  16384


typedef struct
{
    int Flags;
    int AuthFlags;
    int Shortener;
    char *Protocol;
    char *Method;
    int MethodID;
    char *ResponseCode;
    char *OriginalURL;
    char *URL;
    char *Path;
    char *Arguments;
    char *Cipher;
    char *Destination;
    char *ContentType;
    char *ContentBoundary;
    char *Cookies;
    char *AuthDetails;
    char *RemoteAuthenticate; //Used in proxy server mode
    char *UserName;
    char *Password;
    char *AuthenticatedUser;
    char *RealUser;
    int RealUserUID;
    char *Group;
    gid_t GroupID;
    char *StartDir;
    char *HomeDir;
    char *Host;
    char *ClientIP;
    char *ClientHost;
    char *ClientMAC;
    char *ClientReferrer;
    char *UserAgent;
    char *ServerName;
    char *UserSettings;
    char *SearchPath;
    unsigned int ServerPort;
    unsigned int ContentSize;
    unsigned int CacheTime;
    unsigned int Depth;
    time_t LastModified;
    time_t IfModifiedSince;
    ListNode *Headers;
    STREAM *S;
} HTTPSession;



HTTPSession *HTTPSessionCreate();
void HTTPSessionDestroy(void *p_Session);
HTTPSession *HTTPSessionClone(HTTPSession *Src);


//Clear down certain elements of a session so we can reuse it with keeplaive, 
//but we keep it's Authentication and TLS/SSL context
void HTTPSessionClear(void *p_Session); 


//This copies certain fields from a request session object
//to a new response session object, but only those ones that
//are appropriate to a response!
HTTPSession *HTTPSessionResponse(HTTPSession *Src);

char *HTTPSessionGetArg(char *RetStr, HTTPSession *Session, const char *Arg);

char *HTTPSessionFormatURL(char *Buff, HTTPSession *Session, const char *ItemPath);
int HTTPSessionCopyURL(HTTPSession *Session, const char *From, const char *To);

#endif
