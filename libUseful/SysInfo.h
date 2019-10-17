/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/

#ifndef LIBUSEFUL_SYSINFO
#define LIBUSEFUL_SYSINFO


#include "defines.h"
#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {OSINFO_TYPE, OSINFO_ARCH, OSINFO_RELEASE, OSINFO_HOSTNAME, OSINFO_UPTIME, OSINFO_TOTALMEM, OSINFO_FREEMEM, OSINFO_BUFFERMEM, OSINFO_LOAD, OSINFO_HOMEDIR, OSINFO_TMPDIR, OSINFO_PROCS, OSINFO_USERINFO, OSINFO_DOMAINNAME} EOSInfo;

// pass in one of the OSINFO_ defines above to get out a string answer
const char *OSSysInfoString(int Info);

// pass in one of the OSINFO_ defines to get a numeric answer
unsigned long OSSysInfoLong(int Info);

#ifdef __cplusplus
}
#endif


#endif

