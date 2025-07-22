#ifndef ALAYA_EVENTS_H
#define ALAYA_EVENTS_H

#include "common.h"
#include "http_session.h"

typedef enum {EVENT_METHOD, EVENT_PATH, EVENT_USER, EVENT_PEERIP, EVENT_BADURL, EVENT_HEADER, EVENT_RESPONSE, EVENT_UPLOAD, EVENT_AUTH} TEventTypes;

void ProcessSessionEventTriggers(HTTPSession *Session);


#endif
