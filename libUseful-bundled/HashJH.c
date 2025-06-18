#include "HashJH.h"

#ifdef USE_JH

#include "jh_ref.h"

int HashFinishJH(HASH *Hash, char **HashStr)
{
    int len;
    char *DigestBuff=NULL;

    DigestBuff=(char *) calloc(1,1024);

    len=JHFinal((hashState *) Hash->Ctx, (unsigned char *) DigestBuff);
    *HashStr=SetStrLen(*HashStr,len);
    memcpy(*HashStr,DigestBuff,len);

    DestroyString(DigestBuff);

    return(len);
}



void HashUpdateJH(HASH *Hash, const char *Data, int Len)
{
    JHUpdate( (hashState *) Hash->Ctx, (unsigned char *) Data, Len);
}


HASH *HashCloneJH(HASH *Hash)
{
    HASH *NewHash;

    NewHash=(HASH *) calloc(1,sizeof(HASH));
    NewHash->Type=CopyStr(NewHash->Type,Hash->Type);
    NewHash->Ctx=(void *) calloc(1,sizeof(hashState *));
    memcpy(NewHash->Ctx, Hash->Ctx, sizeof(hashState *));

    return(NewHash);
}

#endif


int HashInitJH(HASH *Hash, const char *Name, int Length)
{
#ifdef USE_JH
    switch (Length)
    {
    case 224:
    case 256:
    case 384:
    case 512:
        Hash->Ctx=(void *) calloc(1,sizeof(hashState));
        JHInit((hashState *) Hash->Ctx, Length);
        Hash->Update=HashUpdateJH;
        Hash->Finish=HashFinishJH;
        Hash->Clone=HashCloneJH;
        return(TRUE);
        break;

    }
#endif

    return(FALSE);
}


void HashRegisterJH()
{
#ifdef USE_JH
    HashRegister("jh224", 224, HashInitJH);
    HashRegister("jh256", 256, HashInitJH);
    HashRegister("jh384", 384, HashInitJH);
    HashRegister("jh512", 512, HashInitJH);
    HashRegister("jh-224", 224, HashInitJH);
    HashRegister("jh-256", 256, HashInitJH);
    HashRegister("jh-384", 384, HashInitJH);
    HashRegister("jh-512", 512, HashInitJH);
#endif
}
