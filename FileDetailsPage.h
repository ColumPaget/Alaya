#ifndef ALAYA_FILE_EDIT
#define ALAYA_FILE_EDIT

#include "common.h"
#include "http_session.h"


#define FDETAILS_ACCESSTOKEN 1
#define FDETAILS_URLTOKEN    2

void FileDetailsSaveProps(STREAM *S, HTTPSession *Session, const char *Props);
void DirectoryItemEdit(STREAM *S, HTTPSession *Session, const char *Path, int Flags);

#endif
