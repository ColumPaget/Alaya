/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

#ifndef LIBUSEFUL_STRLEN_CACHE_H
#define LIBUSEFUL_STRLEN_CACHE_H

#include "includes.h"

/* 
Libuseful has an internal caching system for strlen results, as functions like CopyStr use
strlen a lot. For large strings (basically manipulating entire documents in memory) this can
result in very dramatic speedups on old systems without AVX strlen processor instructions. 
However, for short strings it can be slightly slower than libc strlen. The magic number seems 
to come at about 100 characters long. 

Hence 'StrLen' (defined in String.h) does not use this cache. StrLenFromCache is the version
of StrLen that does use the cache. Furthermore short strings are not added to the cache, as
the benefit of caching them is too small to warrant evicting longer strings from the cache.

All this means that libUseful string functions like CopyStr trade off being slightly slower
than strlen for short strings, against being much better than strlen for large strings. In
normal use these differences aren't noticable, but become so when dealing with large strings.

There is a danger to this when using functions that directly manipulate strings. If one directly
sets a character in a string to be '\0' (the null char or zero byte) then the string would 
usually be considered 'truncated' at that point. However StrLenFromCache will still report
the cached length of the string. This can result in 'CatStr' appending data *after* the
null/zero byte, which means such data will effectively be lost. This is why functions like:

StrTrunc(char *Str, int Len) 
StrTruncChar(char *Str, char Term);
StrRTruncChar(char *Str, char Term);

are provided to allow string truncation that works with caching.



The caching system can be switched on and off using:

LibUsefulSetValue("StrLenCache", "Y");  // turn caching on
LibUsefulSetValue("StrLenCache", "N");  // turn caching off

it can also be compiled out using the `./configure --disable-strlen-cache` option

*/



#ifdef __cplusplus
extern "C" {
#endif


//this function allows you to set the number of rows in the string-len cache, and the minimum
//length of a string to be included in the cache. The defaults are '10' rows in the cache and
//'100' characters minimum in a string to be included. 

//If all is well, function returns TRUE
//If StrLenCaching is disabled at libUseful compile time function returns FALSE and errno is set to ENOTSUP
//if memory for the cache cannot be allocated then the function returns FALSE and errno is set to ENOMEM
//Note: if caching is turned off with LibUsefulSetValue then this function still returns true, as you
//can change the settings for the cache even when you're not currently using the feature
int StrLenCacheInit(int Size, int MinStrLen);


//thse are used internally, you'll not normally use any of these functions
int StrLenFromCache(const char *Str);
void StrLenCacheDel(const char *Str);
void StrLenCacheUpdate(const char *Str, int incr);
void StrLenCacheAdd(const char *Str, size_t len);

#ifdef __cplusplus
}
#endif



#endif

