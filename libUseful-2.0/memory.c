#include "memory.h"
#include <malloc.h>


int LibUsefulMemFlags=0;

extern void *_end;

static void *(*old_malloc_hook) (size_t);
static void (*old_free_hook) (void *);

void *HeapBase=NULL, *HeapTop=NULL;


int LibUsefulObjectSize(const void *Object, int Type)
{
int size=-1;
void *p_size, *ds_end;

p_size=(void *) &size;
ds_end=&_end;



if (Object > &size) 
{
	size=__builtin_object_size(Object,1);
	if (size==-1) size=p_size-Object;
}
else 
{
	if ((Object >= HeapBase) && (Object < HeapTop))  size=malloc_usable_size(Object);
}

return(size);
}



static void * libuseful_malloc_hook (size_t size)
{
  void *mem_start, *mem_end;


  __malloc_hook = old_malloc_hook;
  mem_start = malloc (size);
  __malloc_hook = libuseful_malloc_hook;

	mem_end=mem_start+size;
	if (! HeapBase) HeapBase=mem_start;
	else if (mem_start < HeapBase) HeapBase=mem_start;
	
	if (! HeapTop) HeapTop=mem_end;
	else if (mem_end > HeapTop) HeapTop=mem_end;

  return(mem_start);
}


static void libuseful_free_hook(void *Memory)
{ 
int size;

if (! Memory) return;

//  if (LibUsefulMemFlags & MEMORY_CLEAR_ONFREE)
	if (0)
  {
    size=LibUsefulObjectSize(Memory, 0);
    if (size > 0) 
		{
			memset(Memory,0,size);
		}
  }

__free_hook = old_free_hook;
		free(Memory);
__free_hook = libuseful_free_hook;
}



void MemoryInit()
{
  old_malloc_hook = __malloc_hook;
  __malloc_hook = libuseful_malloc_hook;
  old_free_hook = __free_hook;
  __free_hook = libuseful_free_hook;


	LibUsefulMemFlags |= MEMORY_INIT_DONE;
}



