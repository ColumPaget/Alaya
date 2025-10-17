#ifndef LIBUSEFUL_TAR_H
#define LIBUSEFUL_TAR_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

int TarFiles(STREAM *Tar, const char *FilePattern);


#ifdef __cplusplus
}
#endif


#endif
