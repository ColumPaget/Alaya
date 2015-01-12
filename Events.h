#ifndef ALAYA_EVENTS_H
#define ALAYA_EVENTS_H

#include "common.h"

typedef enum {EVENT_METHOD, EVENT_PATH, EVENT_USER, EVENT_PEERIP, EVENT_BADURL, EVENT_HEADER, EVENT_RESPONSE} TEventTypes;


int EventHeadersMatch(char *TriggerMatch, HTTPSession *Session, char **MatchStr);
int EventTriggerMatch(ListNode *Node, HTTPSession *Session, char **MatchStr);
void ProcessEventTrigger(HTTPSession *Session, char *URL, char *TriggerScript, char *ExtraInfo);
void ProcessSessionEventTriggers(HTTPSession *Session);


#endif
