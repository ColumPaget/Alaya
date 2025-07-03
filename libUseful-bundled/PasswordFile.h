/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: LGPL-3.0-or-later
*/

// These functions relate to a password file that stores passwords
// in the form:
// <user>:<pass type>:<salt>:<credential>:<extra>
//
// if 'pass type' is blank or is 'plain' then the password is stored as-is in plaintext
// otherwise 'pass type' will be a hash type, like md5, sha256 etc.
//
// For hash types a 20 character salt is generated and prepended to the password,
// and the resulting string is then hashed before being stored.
//
// 'extra' is populated with any extra data for/about this user.
//
// kernel locking is used to ensure that only one process can be editing the file at any time
// and though many processes can read from the file at once, they cannot do so while the file
// is being written/edited.
//
// File deletions require rewriting the file. This is done by writing to a new file and then
// using an atomic rename, so the file should be preseved in the event of, say, a powercut
// while editing this file. 


#ifndef LIBUSEFUL_PASSWORD_FILE_H
#define LIBUSEFUL_PASSWORD_FILE_H


#include "includes.h"

typedef struct
{
char *User;
char *Type;
char *Salt;
char *Cred;
char *Extra;
} TPasswordEntry;


#ifdef __cplusplus
extern "C" {
#endif


//free memory of a TPasswordEntry
void PasswordEntryDestroy(void *p_Entry);


//read next entry in password file
TPasswordEntry *PasswordFileReadEntry(STREAM *S);

//read user's password entry from file 'Path'
TPasswordEntry *PasswordFileGet(const char *Path, const char *User);

// Add an entry to the password file, replacing any previous entries for that user. Because it has
// to remove previous entries, this function builds an new password file, and then atomically moves
// it into place to replace the existing one. It will not remove any duplicate entries for other
// users.
int PasswordFileAdd(const char *Path, const char *PassType, const char *User, const char *Password, const char *Extra);

// Add an entry to the password file, not replacing previous entries, to previous passwords can still be
// used. This does not require rebuilding the file, and thus may be more efficient than PasswordFileAdd
int PasswordFileAppend(const char *Path, const char *PassType, const char *User, const char *Password, const char *Extra);

//Remove a user from a password file. This should fail safely if anything goes wrong, as it writes a new file and then
//atomically moves the new file over the old one only if the writing process completes. Thus if anything happens (e.g. powercut)
//during this action, the old file should be preserved.
int PasswordFileDelete(const char *Path, const char *User);


//check a users password matches the one stored in password file at 'Path'
int PasswordFileCheck(const char *Path, const char *User, const char *Password, char **ReturnedData);

#ifdef __cplusplus
}
#endif




#endif
