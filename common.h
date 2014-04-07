#ifndef ALAYA_COMMON_H
#define ALAYA_COMMON_H

#include "libUseful-2.0/libUseful.h"
#include <glob.h>
#include <sys/wait.h>
#include <pwd.h>

#define FLAG_REQUIRE_AUTH 1
#define FLAG_CHROOT 2
#define FLAG_CHHOME 4
#define FLAG_CHSHARE 8
#define FLAG_SSL 16
#define FLAG_NODEMON 32
#define FLAG_LOG_VERBOSE 64
#define FLAG_LOG_MORE_VERBOSE 128
#define FLAG_COMPRESS 256
#define FLAG_PARTIAL_COMPRESS 512
#define FLAG_ACCESS_TOKEN 1024
#define FLAG_HAS_AUTH 2048
#define FLAG_CHECK_SCRIPTS 4096
#define FLAG_LOGOUT_AVAILABLE 8192
#define FLAG_LOOKUP_CLIENT 16384
#define FLAG_DIGEST_AUTH 32768
#define FLAG_NOCACHE 65536

#define ERR_OKAY 0
#define ERR_FILE 1


#define LOGGED_IN 1
#define LOGGED_OUT 2
#define LOGIN_FAIL 4
#define LOGIN_CHANGE 8
#define LOGIN_CHECK_ALLOWED 16

typedef enum {PATHTYPE_EXTFILE, PATHTYPE_CGI, PATHTYPE_STREAM, PATHTYPE_LOGOUT, PATHTYPE_PROXY, PATHTYPE_URL, PATHTYPE_MIMEICONS, PATHTYPE_FILE, PATHTYPE_DIR} TPathTypes; 	


#define DIR_REJECT      -1
#define DIR_SHOWFILES   1
#define DIR_INDEX_FILES 2
#define DIR_FANCY				4
#define DIR_INTERACTIVE 8
#define DIR_MEDIA_EXT		4096
#define DIR_IMAGE_EXT		8192
#define DIR_UPLOAD			65536
#define DIR_HASMEDIA		131072
#define DIR_SHOW_VPATHS	262144
#define DIR_TARBALLS		524288


#define CAPS_LEVEL_STARTUP  1
#define CAPS_LEVEL_NETBOUND 2
#define CAPS_LEVEL_CHROOTED 3
#define CAPS_LEVEL_SESSION  4


typedef struct
{
int Type;
char *URL;
char *Path;
char *Name;
int Size;
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
char *AuthMethods;
char *AuthPath;
char *AuthRealm;
char *ConfigPath;
char *ScriptHashFile;
char *BindAddress;
char *HttpMethods;
char *IndexFiles;
char *M3UFileTypes;
int DisplayNameLen;
ListNode *SSLKeys;
ListNode *VPaths;
ListNode *ScriptHandlers;
ListNode *LoginEntries;
ListNode *SanitizeArgumentsAllowedTags;
ListNode *CustomHeaders;
ListNode *HostConnections;
ListNode *UserAgents;
char *LogPath;
int MaxLogSize;
} TSettings;


typedef struct
{
int Flags;
char *Protocol;
char *Method;
int MethodID;
char *ResponseCode;
char *URL;
char *Path;
char *Arguments;
char *Destination;
char *ContentType;
char *ContentBoundary;
char *Cookies;
char *UserName;
char *Password;
char *AuthDetails;
char *RemoteAuthenticate; //Used in proxy server mode
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


TPathItem *PathItemCreate(int Type, char *URL, char *Path);
void PathItemDestroy(void *pi_ptr);

void ParseConfigItem(char *ConfigLine);
void ParseConfigItemList(const char *Settings);

char *FormatURL(char *Buff, HTTPSession *Session, char *ItemPath);
char *MakeAccessToken(char *Buffer, char *Salt, char *Method, char *RequestingHost, char *RequestURL);

char *ParentDirectory(char *RetBuff, char *Path);

char *SessionGetArgument(char *RetBuff, HTTPSession *Session, char *ReqName);

int CopyURL(HTTPSession *Session, char *From, char *To);


void DropCapabilities(int Level);

#endif

