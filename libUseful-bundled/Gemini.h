/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

//provides support for the gemini protocol. you would normally not use
//this function, but instead S=STREAMOpen("gemini://myhost","r");

#ifndef LIBUSEFUL_GEMINI_H
#define LIBUSEFUL_GEMINI_H

#include "Stream.h"


#ifdef __cplusplus
extern "C" {
#endif


STREAM *GeminiOpen(const char *URL, const char *Config);

#ifdef __cplusplus
}
#endif



#endif


