
#ifndef LIBUSEFUL_MEMORY_H
#define LIBUSEFUL_MEMORY_H

#include "includes.h"

#define MEMORY_INIT_DONE		1
#define MEMORY_CLEAR_ONFREE 2

extern int LibUsefulMemFlags;

int LibUsefulObjectSize(const void *Object, int Type);
void MemoryInit();


#endif
