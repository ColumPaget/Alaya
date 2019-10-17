#ifndef DAV_PROPPATCH_H
#define DAV_PROPPATCH_H

#include "common.h"

char *DavPropsGet(char *RetStr, const char *Target, const char *Property);
int DavPropsStore(const char *Target, const char *Property, const char *Value);
int DavPropsIncr(const char *Target, const char *Property);

void AddStandardProps(ListNode *PropList);
void HTTPServerPropFind(STREAM *S,HTTPSession *Heads);
void HTTPServerPropPatch(STREAM *S,HTTPSession *Heads);

#endif
