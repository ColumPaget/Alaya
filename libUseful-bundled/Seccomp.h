/*
Copyright (c) 2025 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

#ifndef LIBUSEFUL_SECCOMP_H
#define LIBUSEFUL_SECCOMP_H

#include "includes.h"


#ifdef __cplusplus
extern "C" {
#endif

int SeccompAddRules(const char *RuleList);

#ifdef __cplusplus
}
#endif



#endif
