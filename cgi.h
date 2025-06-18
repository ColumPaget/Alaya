#ifndef ALAYA_CGI_H
#define ALAYA_CGI_H

#include "common.h"
#include "http_session.h"

int CGIExecProgram(STREAM *ClientCon, HTTPSession *Session, const char *ScriptPath);

#endif

