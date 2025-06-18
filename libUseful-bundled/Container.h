/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/


#ifndef LIBUSEFUL_CONTAINER_H
#define LIBUSEFUL_CONTAINER_H


#ifdef __cplusplus
extern "C" {
#endif


#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>

//this module relates to namespaces/containers. Much of this is pretty linux specific, and would be called
//via 'ProcessApplyConfig' rather than calling this function directly.

int ContainerApplyConfig(int Flags, const char *Config);

#ifdef __cplusplus
}
#endif

#endif
