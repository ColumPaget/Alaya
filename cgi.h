#ifndef ALAYA_CGI_H
#define ALAYA_CGI_H

#include "common.h"

int CGIExecProgram(STREAM *ClientCon, HTTPSession *Session, const char *ScriptPath);

#endif

