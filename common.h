#ifndef ALAYA_COMMON_H
#define ALAYA_COMMON_H

#ifdef USE_LIBUSEFUL_BUNDLED
#include "libUseful-bundled/libUseful.h"
#else
#include "libUseful-5/libUseful.h"
#endif

#include "settings.h"
#include <glob.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fnmatch.h>

#include "http_session.h"


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
#define DIR_CENTER     32 //only used by FormatFancyIem
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

typedef enum {PATHTYPE_NONE, PATHTYPE_LOCAL, PATHTYPE_EXTFILE, PATHTYPE_CGI, PATHTYPE_WEBSOCKET, PATHTYPE_STREAM, PATHTYPE_LOGOUT, PATHTYPE_PROXY, PATHTYPE_REDIRECT, PATHTYPE_CALENDAR, PATHTYPE_MIMEICONS, PATHTYPE_FILETYPE, PATHTYPE_USERADMIN, PATHTYPE_URL, PATHTYPE_FILE, PATHTYPE_DIR} TPathTypes;


#define PATHITEM_EXEC 1
#define PATHITEM_READONLY 2
#define PATHITEM_NOAUTH 4
#define PATHITEM_COMPRESS 16
#define PATHITEM_NO_COMPRESS 32

typedef struct
{
    int Type;
    int Flags;
    char *URL;
    char *Path;
    char *Name;
    char *ContentType;
    off_t Size;
    unsigned int CacheTime;
    char *User;
    char *Password;
    char *Group;
    time_t Mtime;
    char *OnUpload;
} TPathItem;





extern char *Version;


void SetTimezoneEnv();

void HandleError(int Flags, const char *FmtStr, ...);
TPathItem *PathItemCreate(int Type, const char *URL, const char *Path);
void PathItemDestroy(void *pi_ptr);
char *ParentDirectory(char *RetBuff, const char *Path);

char *FindScriptHandlerForScript(char *RetStr, const char *ScriptPath);

void DropCapabilities(int Level);

#endif

