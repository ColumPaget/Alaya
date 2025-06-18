#include "HashCRC32.h"
#include "crc32.h"

void HashUpdateCRC(HASH *Hash, const char *Data, int Len)
{
#ifndef USE_LGPL
    crc32Update((unsigned long *) Hash->Ctx, (unsigned char *) Data, Len);
#endif
}


HASH *HashCloneCRC(HASH *Hash)
{
    HASH *NewHash=NULL;

#ifndef USE_LGPL
    NewHash=(HASH *) calloc(1,sizeof(HASH));
    NewHash->Type=CopyStr(NewHash->Type,Hash->Type);
    NewHash->Ctx=(void *) calloc(1,sizeof(unsigned long));
    memcpy(NewHash->Ctx, Hash->Ctx, sizeof(unsigned long));
#endif

    return(NewHash);
}


int HashFinishCRC(HASH *Hash, char **HashStr)
{
    int len=0;

#ifndef USE_LGPL
    unsigned long crc;

    *HashStr=CopyStr(*HashStr, "");
    len=sizeof(unsigned long);
    crc32Finish((unsigned long *) Hash->Ctx);
    crc=htonl(* (unsigned long *) Hash->Ctx);

    *HashStr=SetStrLen(*HashStr,len);
    memcpy(*HashStr,&crc,len);
#endif

    return(len);
}


int HashInitCRC(HASH *Hash, const char *Name, int Len)
{
#ifndef USE_LGPL
    Hash->Ctx=(void *) calloc(1,sizeof(unsigned long));
    if (Hash->Ctx)
    {
        crc32Init((unsigned long *) Hash->Ctx);
        Hash->Update=HashUpdateCRC;
        Hash->Finish=HashFinishCRC;
        Hash->Clone=HashCloneCRC;
        return(TRUE);
    }
#endif

    return(FALSE);
}

void HashRegisterCRC32()
{
#ifndef USE_LGPL
    HashRegister("crc32", 32, HashInitCRC);
#endif
}
