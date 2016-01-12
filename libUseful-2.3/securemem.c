#include "securemem.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>

void SecureClearMem(char *Mem, int Size)
{
char *ptr;

	if (! Mem) return;
	xmemset((volatile char *) Mem,0,Size);
	for (ptr=Mem; ptr < (Mem + Size); ptr++)
	{
		if (*ptr != 0) 
		{
			fprintf(stderr,"LIBUSEFUL ERROR: Failed to clear secure memory");
			exit(3);				
		}
	}
}


void SecureDestroy(char *Mem, int Size)
{

	if (! Mem) return;
	SecureClearMem(Mem, Size);
  munlock(Mem, Size);
	free(Mem);
}


char *SecureRealloc(char *OldMem, int OldSize, int NewSize, int Flags)
{
int MemSize;
char *NewMem=NULL;
int val=0, PageSize;

PageSize=getpagesize();
MemSize=(NewSize / PageSize + 1) * PageSize;
if (posix_memalign(&NewMem, PageSize, MemSize)==0)
{
	if (OldMem)
	{
		if (NewSize < OldSize) val=NewSize;
		else val=OldSize;
		memcpy(NewMem,OldMem,val);
		//Still use OldSize to clear OldMem
		SecureClearMem(OldMem, OldSize);
	}


	#ifdef HAVE_MADVISE

		#ifdef HAVE_MADVISE_NOFORK
			if (Flags & SMEM_NOFORK) madvise(NewMem,NewSize,MADV_DONTFORK);
		#endif
		
		#ifdef HAVE_MADVISE_DONTDUMP
			if (Flags & SMEM_NODUMP) madvise(NewMem,NewSize,MADV_DONTDUMP);
		#endif

	#endif

	#ifdef HAVE_MLOCK
		 if (Flags & SMEM_LOCK) mlock(NewMem, NewSize);
	#endif
}
else
{
		fprintf(stderr,"LIBUSEFUL ERROR: Failed to allocate secure memory");
		exit(3);				
}

return(NewMem);
}
