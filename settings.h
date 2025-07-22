#ifndef ALAYA_SETTINGS_H
#define ALAYA_SETTINGS_H

#include "common.h"

//Flag values for Settings->Flags
#define FLAG_NODEMON                  1
#define FLAG_CHROOT                   2
#define FLAG_CHHOME                   4
#define FLAG_CHSHARE                  8
#define FLAG_SSL                     16
#define FLAG_SSL_PFS                 32
#define FLAG_PFS_GENERATE            64
#define FLAG_ALLOW_SU               128
#define FLAG_COMPRESS               256
#define FLAG_PARTIAL_COMPRESS       512
#define FLAG_USE_UNSHARE           1024
#define FLAG_USE_REUSEPORT         2048
#define FLAG_CHECK_SCRIPTS         4096
#define FLAG_LOGOUT_AVAILABLE      8192
#define FLAG_LOOKUP_CLIENT        16384
#define FLAG_KEEPALIVES           32768
#define FLAG_SIGHUP_RECV          65536
#define FLAG_LOG_VERBOSE         131072
#define FLAG_LOG_MORE_VERBOSE    262144
#define FLAG_USE_FASTOPEN        524288
#define FLAG_USE_HTTPS_FASTOPEN 1048576


//Flag values for Settings->AuthFlags and Session->AuthFlags
#define FLAG_AUTH_REQUIRED          1
#define FLAG_AUTH_PRESENT           2
#define FLAG_AUTH_BASIC             4
#define FLAG_AUTH_DIGEST            8
#define FLAG_AUTH_COOKIE           32
#define FLAG_AUTH_HASCOOKIE        64
#define FLAG_AUTH_CERT_ASK        128
#define FLAG_AUTH_CERT_SUFFICIENT 256
#define FLAG_AUTH_CERT_REQUIRED   512
#define FLAG_AUTH_ADMIN          1024
#define FLAG_AUTH_ACCESS_TOKEN   2048
#define FLAG_AUTH_URL_TOKEN      4096

typedef struct
{
    int Flags;
    int Port;
    int ListenQueueLen;
    char *DefaultUser;
    char *DefaultGroup;
    gid_t DefaultGroupID;
    char *DefaultDir;
    char *AdminUser;
    int DirListFlags;
    char *AllowUsers;
    char *DenyUsers;
    char *AllowIPs;
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
    char *URLTokenKey;
    char *ForbiddenURLStrings;
    char *Timezone;
    char *AddressSpace;
    char *StackSize;
    int DisplayNameLen;
    int TTL;
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
    ListNode *ProxyConfig;
    char *PackFormats;
    char *LogPath;
    char *PidFilePath;
    int MaxLogSize;
    int MaxLogRotate;
    int ActivityTimeout;
    char *URLShortner;
} TSettings;

extern TSettings Settings;

void InitSettings();
void PostProcessSettings(TSettings *Settings);
void ReadConfigFile(const char *Path);
void ParseConfigItem(const char *ConfigLine);
void ParseConfigItemList(const char *Settings);
void SettingsParseCommandLine(int argc, char *argv[], TSettings *Settings);

#endif

