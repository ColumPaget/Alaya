#ifndef ALAYA_UPLOAD_H
#define ALAYA_UPLOAD_H

#include "common.h"

void UploadMultipartPost(STREAM *S, HTTPSession *Session);
void UploadSelectPage(STREAM *S,HTTPSession *Session,char *Path);

#endif 
