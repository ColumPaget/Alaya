#ifndef ALAYA_DIRLIST_H
#define ALAYA_DIRLIST_H

#include "common.h"

void HTTPServerSendDirectory(STREAM *S, HTTPSession *Heads, char *Path, ListNode *Vars);

#endif

