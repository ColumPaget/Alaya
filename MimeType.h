
#ifndef ALAYA_MIME_TYPES_H
#define ALAYA_MIME_TYPES_H

#include "common.h"

#define FILE_NOSUCH 0
#define FILE_EXISTS 1
#define FILE_DIR    2

#define FM_MEDIA_TAG 1
#define FM_IMAGE_TAG 2

typedef struct
{
int Type;
char *ContentType;
char *Icon;
char *Data;
int Len;
int Flags;
} TFileMagic;


void LoadFileMagics(char *MimeTypesPath, char *MagicsPath);
TFileMagic *GetContentTypeInfo(char *ContentType);
TFileMagic *GetFileTypeInfo(char *ContentType);
TFileMagic *GetFileMagicForFile(char *Path, STREAM *S);

#endif
