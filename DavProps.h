#ifndef DAV_PROPPATCH_H
#define DAV_PROPPATCH_H

#include "common.h"


void ChangeProperty(char *File, char *PropName, char *PropValue);
void AddStandardProps(ListNode *PropList);
void HTTPServerPropFind(STREAM *S,HTTPSession *Heads);
void HTTPServerPropPatch(STREAM *S,HTTPSession *Heads);

#endif
