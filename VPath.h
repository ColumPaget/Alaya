#ifndef ALAYA_VPATH_H
#define ALAYA_VPATH_H

#include "common.h"
#include "http_session.h"


void VPathParse(ListNode *List, const char *PathType, const char *Data);
TPathItem *VPathFind(int Type, const char *Match);
char *HTTPServerSubstituteArgs(char *RetStr, const char *Template, HTTPSession *Session);
//void VPathHandleFilePath(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData);
int VPathProcess(STREAM *S, HTTPSession *Session, int Flags);

#endif
