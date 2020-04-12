#ifndef ALAYA_ICECAST_H
#define ALAYA_ICECAST_H

#include "common.h"
#include "server.h"

void IcecastHandleStream(STREAM *Output, HTTPSession *Session, const char *SearchPath);

#endif

