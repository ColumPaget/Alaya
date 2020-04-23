#ifndef ALAYA_EVENTS_H
#define ALAYA_EVENTS_H

#include "common.h"

typedef enum {EVENT_METHOD, EVENT_PATH, EVENT_USER, EVENT_PEERIP, EVENT_BADURL, EVENT_HEADER, EVENT_RESPONSE, EVENT_UPLOAD} TEventTypes;

void ProcessSessionEventTriggers(HTTPSession *Session);


#endif
