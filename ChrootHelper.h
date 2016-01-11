#ifndef ALAYA_CHROOT_HELPERS_H
#define ALAYA_CHROOT_HELPERS_H

#include "common.h"

//These functions relate to requests for data from outside of the current
//path and possibly outside of chroot. These scripts/documents are served 
//through a request passed to the 'master' alaya parent process

void AlayaLog(char *Msg);


STREAM *ChrootSendRequest(HTTPSession *Session, const char *Type, const char *Path, const char *SearchPath);
int ChrootProcessRequest(STREAM *S, HTTPSession *Session, const char *Type, const char *Path, const char *SearchPath);
int HandleChildProcessRequest(STREAM *S);

void VPathMimeIcons(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData);
void HTTPServerHandleVPath(STREAM *S,HTTPSession *Session,TPathItem *VPath,int SendData);
int HTTPServerHandleRegister(HTTPSession *Session, int Flags);

#endif
