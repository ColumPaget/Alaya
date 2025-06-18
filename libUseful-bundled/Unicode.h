/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/


/* 
This file relates to outputing unicode characters at the terminal. It supplies functions to lookup characters by name.

Unicode in libUseful is usually enabled using 'tilde strings' like ~:alien: that are parsed and converted by the functions  int 'Terminal.h' like TerminalPutStr and TerminalFormatStr

Since libUseful-5.57 'Nerdfonts' characters are also supported.

Both unicode and nerdfonts require you to have your system locale setup for UTF8 and to be using a font that supports the extra unicode and/or nerdfonts characters.

Both unicode and nerdfonts names are looked up in files. For unicode a few names are provided in 'unicode-names.conf' that comes supplied with libUseful and is installed in '$(PREFIX)/etc' (where $(PREFIX) is the install prefix of libUseful).

For nerdfonts a file listing names to character-number mappings must be supplied. One source for such files is:

https://github.com/8bitmcu/NerdFont-Cheat-Sheet

Either space-separated or comma-seperated files will work so long as:

 1) the file is called 'nerdfont.csv' 'nerdfont.csv.txt' or 'nerdfont.txt' 
 2) there is one mapping per line
 3) the first field is the name and the second is the character-number
 4) neither space or , exist in the name

The nerdfonts file should, by default, go in '$(PREFIX)/etc'

libUseful goes through the following proceedure to find the unicode.conf and nerdfont.csv files:

 For unicode:
 1) has the libUseful variable 'Unicode:NamesFile' been set? If so, assume it is the FULL PATH to a file
 2) has the environment variable 'UNICODE_NAMES_FILE' been set? If so, assume it is the FULL PATH to a file
 3) search for unicode-names.conf in $(PREFIX)/etc
 4) get the $PATH environment variable. For each directory in '$PATH' chop off the last directory level (usually 'bin') and replace it with 'etc'. Search for unicode-names.conf in the resulting directories.

 For nerdfonts:
 1) has the libUseful variable 'Nerdfonts:NamesFile' been set? If so, assume it is the FULL PATH to a file
 2) has the environment variable 'NERDFONTS_NAMES_FILE' been set? If so, assume it is the FULL PATH to a file
 3) search for nerdfont.csv.txt, nerdfont.csv or nerdfont.txt in $(PREFIX)/etc
 4) get the $PATH environment variable. For each directory in '$PATH' chop off the last directory level (usually 'bin') and replace it with 'etc'. Search for nerdfont.csv.txt nerdfont.csv nerdfont.txt in the resulting directories.
*/


#ifndef LIBUSEFUL_UNICODE_H
#define LIBUSEFUL_UNICODE_H

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

// set the GLOBAL unicode level.
// this is a global value that represents the unicode abilities of an OS or device. 
// Functions like 'UnicodeStr' and 'StrAddUnicodeChar' use this information in all their operations.  

// There are 3 values
// level 0: no unicode support, unicode chars will be replaced with '?'
// level 1: unicode support up to 0x800, chars above this will be replaced with '?'
// level 2: unicode support up to 0x10000, chars above this will be replaced with '?'
// level 3: unicode support up to 0x1FFFF, chars above this will be replaced with '?'
// level 9: unicode support up to 0x1FFFF plus nerdfonts support (also up to character 0x1FFFF)
void UnicodeSetUTF8(int level);

//decode a single UTF-8 sequence pointed to by ptr and return it as an unsigned int, incrementing ptr to 
//point beyond the just decoded sequence
unsigned int UnicodeDecode(const char **ptr);

//encode a single unicode value ('Code') to a UTF-8 string using the supplied UnicodeLevel 
//rather than the global unicode level set by UnicodeSetUTF9
char *UnicodeEncodeChar(char *RetStr, int UnicodeLevel, int Code);

//encode a single unicode value ('Code') to a unicode string honoring the global unicode level
char *UnicodeStr(char *RetStr, int Code);

char *BufferAddUnicodeChar(char *RetStr, unsigned int len, unsigned int uchar);

//encode a single unicode value ('Code') to a unicode string honoring the global unicode level, and append that string to a character string
char *StrAddUnicodeChar(char *RetStr, int uchar);

//lookup a unicode string by name at the specified Unicode support level
char *UnicodeStrFromNameAtLevel(char *RetStr, int UnicodeLevel, const char *Name);

//lookup a unicode string by name, honoring the global unicode level
char *UnicodeStrFromName(char *RetStr, const char *Name);

//list of comma-seperated character names to load into unicode/nerdfonts cache. You would normally not need to call this function as it is used internally, but you could call it and supply the names for all the characters/emojii you intend to use and this will lower the number of reads from the unicode-names.conf and nerdfont.csv files.
int UnicodeNameCachePreload(const char *Names);

//extract unicode/nerdfonts character names from a tilde-formatted string containing entries like `~:alien:` and pass the names to UnicodeNameCachePreload. You would normally not need to call this function as it is used internally, but you could call it and supply the names for all the characters/emojii you intend to use and this will lower the number of reads from the unicode-names.conf and nerdfont.csv files.
int UnicodeNameCachePreloadFromTerminalStr(const char *String);


#ifdef __cplusplus
}
#endif

#endif

