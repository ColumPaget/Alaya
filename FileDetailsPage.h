#ifndef ALAYA_FILE_EDIT
#define ALAYA_FILE_EDIT

#include "common.h"

char *FormatFileProperties(char *HTML, int FType, char *Path, ListNode *Vars);
void FileDetailsSaveProps(STREAM *S, HTTPSession *Session, char *Props);
void DirectoryItemEdit(STREAM *S, HTTPSession *Session, char *Path);

#endif
