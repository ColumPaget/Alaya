/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

#ifndef LIBUSEFUL_CGI_H
#define LIBUSEFUL_CGI_H

#include "includes.h"


#ifdef __cplusplus
extern "C" {
#endif


//simple utility function that checks for a document size in
//the environment variable CONTENT_LENGTH, and then reads bytes up to that size
char *CGIReadDocument(char *RetStr, STREAM *S);

#ifdef __cplusplus
}
#endif

#endif
