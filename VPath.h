#ifndef ALAYA_MIME_TYPES_H
#define ALAYA_MIME_TYPES_H

#include "common.h"

char *HTTPServerSubstituteArgs(char *RetStr, const char *Template, HTTPSession *Session);
void VPathHandleFilePath(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData);
int VPathProcess(STREAM *S, HTTPSession *Session, int Flags);

#endif
