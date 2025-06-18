
/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

#ifndef LIBUSEFUL_STRINGLIST_H
#define LIBUSEFUL_STRINGLIST_H

/*
Utility functions to hand a string of strings, separated by a separator string or character
*/


#ifdef __cplusplus
extern "C" {
#endif

//check if Item is in string 'List' where 'List' is separated into strings by 'Sep'
//e.g. InStringList("that", "this,that,theother", ",");


//is an Item in a List of strings separated by Sep?
int InStringList(const char *Item, const char *List, const char *Sep);

//get an item at Pos in a List of strings seperated by Sep
char *StringListGet(char *RetStr, const char *List, const char *Sep, int Pos);

//add Item to the end of a list of strings (here RetStr as it's also what's returned) separated by Sep
char *StringListAdd(char *RetStr, const char *Item, const char *Sep);

//add Item to the end of a list of strings (here RetStr as it's also what's returned) separated by Sep, but only do that if it's not already in the string
char *StringListAddUnique(char *RetStr, const char *Item, const char *Sep);

//take a list of strings (Input) separated by Sep, and return a copy of Input except each string only occurs once
char *StringListToUnique(char *RetStr, const char *Input, const char *Sep);


#ifdef __cplusplus
}
#endif

#endif
