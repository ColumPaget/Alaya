#ifndef LIBUSEFUL_TAR_H
#define LIBUSEFUL_TAR_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

int TarReadHeader(STREAM *S, ListNode *Vars);
size_t TarFind(STREAM *Tar, const char *FileName);
int TarUnpack(STREAM *Tar, const char *Pattern);
int TarWriteHeader(STREAM *S, const char *FileName, struct stat *FStat);
int TarWriteFooter(STREAM *Tar);
int TarWriteBytes(STREAM *Tar, const char *Bytes, int Len);
int TarAddFile(STREAM *Tar, STREAM *File);
int TarFiles(STREAM *Tar, const char *FilePattern);


#ifdef __cplusplus
}
#endif


#endif
