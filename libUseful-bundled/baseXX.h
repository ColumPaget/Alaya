/*
Copyright (c) 2025 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/


#ifndef LIBUSEFUL_BASEXX_H
#define LIBUSEFUL_BASEXX_H

#include "includes.h"


#ifdef __cplusplus
extern "C" {
#endif


//the mysterious '5' in baseXXencode is the number of bits that can be encoded in one character of base32
#define base32encode(Out, In, Len, Encoder, Pad) (baseXXencode((Out), (In), (Len), 5, (Encoder), (Pad))) 
//the mysterious '16' in baseXXdecode is the highest bit that can be encoded in base32
#define base32decode(Out, In, Encoder) (baseXXdecode((Out), (In), (Encoder), 16))

//the mysterious '6' in baseXXencode is the number of bits that can be encoded in one character of base64
#define base64encode(Out, In, Len, Encoder, Pad) (baseXXencode((Out), (In), (Len), 6, (Encoder), (Pad))) 
//the mysterious '32' in baseXXdecode is the highest bit that can be encoded in base64
#define base64decode(Out, In, Encoder) (baseXXdecode((Out), (In), (Encoder) , 32))

int baseXXdecode(unsigned char *Out, const char *In, const char *Encoder, int MaxChunk);
char *baseXXencode(char *Out, const char *Input, int Len, int ChunkSize, const char *Encoder, char Pad);

#ifdef __cplusplus
}
#endif


#endif
