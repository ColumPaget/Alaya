#ifndef ALAYA_UPLOAD_H
#define ALAYA_UPLOAD_H

#include "common.h"

int UploadMultipartPost(STREAM *S, HTTPSession *Session);
void UploadSelectPage(STREAM *S, HTTPSession *Session, const char *Path);

#endif
