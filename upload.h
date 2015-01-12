#ifndef ALAYA_UPLOAD_H
#define ALAYA_UPLOAD_H

#include "common.h"

void HTTPServerHandleMultipartPost(STREAM *S, HTTPSession *Session);
void HtmlUploadPage(STREAM *S,HTTPSession *Session,char *Path);

#endif 
