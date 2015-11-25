#ifndef ALAYA_COMMON_H
#define ALAYA_COMMON_H

#include "libUseful-2.3/libUseful.h"
#include <glob.h>
#include <sys/wait.h>
#include <pwd.h>

//Flag values for Settings->Flags
#define FLAG_NODEMON 1
#define FLAG_CHROOT 2
#define FLAG_CHHOME 4
#define FLAG_CHSHARE 8
#define FLAG_SSL 16
#define FLAG_SSL_PFS 32
#define FLAG_LOG_VERBOSE 64
#define FLAG_LOG_MORE_VERBOSE 128
#define FLAG_COMPRESS 256
#define FLAG_PARTIAL_COMPRESS 512
#define FLAG_CHECK_SCRIPTS 4096
#define FLAG_LOGOUT_AVAILABLE 8192
#define FLAG_LOOKUP_CLIENT 16384
#define FLAG_KEEP_ALIVES 32768
#define FLAG_SIGHUP_RECV 65536


//Flag values for Settings->AuthFlags and Session->AuthFlags
#define FLAG_AUTH_REQUIRED 1
#define FLAG_AUTH_PRESENT  2
#define FLAG_AUTH_DIGEST   4
#define FLAG_AUTH_ACCESS_TOKEN  8
#define FLAG_AUTH_CERT_REQUIRED 16
#define FLAG_AUTH_CERT_SUFFICIENT 32
#define FLAG_AUTH_CERT_ASK 64

//Flag values for Session->Flags
#define SESSION_ENCODE_GZIP 1
#define SESSION_ENCODE_XGZIP 2
#define SESSION_ICECAST 4
#define SESSION_OVERWRITE 8
#define SESSION_KEEP_ALIVE 16
#define SESSION_REUSE 32
#define SESSION_AUTHENTICATED 64
#define SESSION_SSL 128
#define SESSION_ERR_BADURL 4096



#define ERR_OKAY 0
#define ERR_FILE 1
#define ERR_LOG 2
#define ERR_PRINT 4
#define ERR_EXIT 8


#define LOGGED_IN 1
#define LOGGED_OUT 2
#define LOGIN_FAIL 4
#define LOGIN_CHANGE 8
#define LOGIN_CHECK_ALLOWED 16

//Flag Values for Settings->DirListFlags
#define DIR_REJECT      -1
#define DIR_SHOWFILES   1
#define DIR_INDEX_FILES 2
#define DIR_FANCY				4
#define DIR_INTERACTIVE 8
#define DIR_MIMEICONS  16
#define DIR_MEDIA_EXT		4096
#define DIR_IMAGE_EXT		8192
#define DIR_UPLOAD			65536
#define DIR_HASMEDIA		131072
#define DIR_SHOW_VPATHS	262144
#define DIR_TARBALLS		524288


//Flag values for the DropCapabilities function
#define CAPS_LEVEL_STARTUP  1
#define CAPS_LEVEL_NETBOUND 2
#define CAPS_LEVEL_CHROOTED 3
#define CAPS_LEVEL_SESSION  4

typedef enum {PATHTYPE_EXTFILE, PATHTYPE_CGI, PATHTYPE_STREAM, PATHTYPE_LOGOUT, PATHTYPE_PROXY, PATHTYPE_MIMEICONS, PATHTYPE_URL, PATHTYPE_FILE, PATHTYPE_DIR} TPathTypes;



typedef struct
{
int Type;
char *URL;
char *Path;
char *Name;
off_t Size;
time_t Mtime;
} TPathItem;



typedef struct
{
int Flags;
int Port;
char *DefaultUser;
char *DefaultGroup;
gid_t DefaultGroupID;
char *DefaultDir;
int DirListFlags;
char *CgiUser;
char *AllowUsers;
char *DenyUsers;
int AuthFlags;
char *AuthMethods;
char *AuthPath;
char *AuthRealm;
char *ConfigPath;
char *ScriptHashFile;
char *BindAddress;
char *HttpMethods;
char *IndexFiles;
char *M3UFileTypes;
char *AccessTokenKey;
char *ForbiddenURLStrings;
char *Timezone;
char *AddressSpace;
char *StackSize;
int DisplayNameLen;
unsigned long DocumentCacheTime;
ListNode *SSLKeys;
ListNode *VPaths;
ListNode *ScriptHandlers;
ListNode *LoginEntries;
ListNode *SanitizeArgumentsAllowedTags;
ListNode *CustomHeaders;
ListNode *HostConnections;
ListNode *UserAgents;
ListNode *Events;
char *LogPath;
int MaxLogSize;
int MaxLogRotate;
int ActivityTimeout;
} TSettings;


typedef struct
{
int Flags;
int AuthFlags;
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
char *UserName;
char *Password;
char *AuthDetails;
char *RemoteAuthenticate; //Used in proxy server mode
char *AuthenticatedUser;
char *RealUser;
int RealUserUID;
char *Group;
gid_t GroupID;
char *StartDir;
char *HomeDir;
char *AuthType;
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
unsigned int Depth;
time_t LastModified;
time_t IfModifiedSince;
ListNode *Headers;
STREAM *S;
} HTTPSession;



extern TSettings Settings;
extern char *Version;


HTTPSession *HTTPSessionCreate();
void HTTPSessionClear(void *);
void HTTPSessionDestroy(void *);

void SetTimezoneEnv();

void HandleError(int Flags, const char *FmtStr, ...);
TPathItem *PathItemCreate(int Type, char *URL, char *Path);
void PathItemDestroy(void *pi_ptr);

char *FormatURL(char *Buff, HTTPSession *Session, char *ItemPath);
char *MakeAccessToken(char *Buffer, char *User, char *Salt, char *RequestingHost, char *RequestURL);

char *ParentDirectory(char *RetBuff, char *Path);

char *SessionGetArgument(char *RetBuff, HTTPSession *Session, char *ReqName);

int CopyURL(HTTPSession *Session, char *From, char *To);


int ProcessEventTriggers(HTTPSession *Session);


void DropCapabilities(int Level);

#endif

