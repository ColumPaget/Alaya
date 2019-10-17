#ifndef ALAYA_DIRLIST_H
#define ALAYA_DIRLIST_H

#include "common.h"

int DirectorySend(STREAM *S, HTTPSession *Session, const char *Path, ListNode *Vars, int Flags);

#endif

