#include "libUseful-2.3/libUseful.h"

#ifndef ALAYA_SETTINGS_H
#define ALAYA_SETTINGS_H


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
#define FLAG_AUTH_COOKIE 16
#define FLAG_AUTH_HASCOOKIE 32
#define FLAG_AUTH_CERT_ASK 64
#define FLAG_AUTH_CERT_SUFFICIENT 128
#define FLAG_AUTH_CERT_REQUIRED 256


typedef struct
{
int Flags;
int Port;
char *DefaultUser;
char *DefaultGroup;
gid_t DefaultGroupID;
char *DefaultDir;
int DirListFlags;
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
char *PackFormats;
char *LogPath;
int MaxLogSize;
int MaxLogRotate;
int ActivityTimeout;
} TSettings;

extern TSettings Settings;

void InitSettings();
void PostProcessSettings(TSettings *Settings);
void ReadConfigFile(TSettings *Settings);
void ParseConfigItem(char *ConfigLine);
void ParseConfigItemList(const char *Settings);
void ParseSettings(int argc, char *argv[], TSettings *Settings);

#endif

