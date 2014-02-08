#include "Hash.h"
#include "string.h"

char *EncodeBase64(char *Return, char *Text, int len)
{
char *RetStr;

RetStr=SetStrLen(Return,len *2);
to64frombits(RetStr,Text,len);

return(RetStr);
}

char *DecodeBase64(char *Return, int *len, char *Text)
{
char *RetStr;

RetStr=SetStrLen(Return,StrLen(Text) *2);
*len=from64tobits(RetStr,Text);

return(RetStr);
}

int HMAC(char **Return, char *Algo, char *iKey, int iKeyLen, char *iText, int iTextLen)
{
int blocksize=64, len, i;
char *Key=NULL, *Text=NULL;
int KeyLen, TextLen;
char *Tempstr=NULL, *Digest=NULL, *OpadKey=NULL, *IpadKey=NULL;

len=StrLen(iKey);

if (len > blocksize) KeyLen=HashBytes(&Key,Algo,iKey,iKeyLen,0);
else 
{
KeyLen=len;
Key=SetStrLen(Key,len);
memcpy(Key,iKey,len);
}

Key=SetStrLen(Key,blocksize);
IpadKey=SetStrLen(IpadKey,blocksize);
OpadKey=SetStrLen(OpadKey,blocksize);

for (i=0; i < blocksize; i++)
{
IpadKey[i]=Key[i] ^ 0x5c;
OpadKey[i]=Key[i] ^ 0x36;
}

len=StrLen(Text);
Tempstr=SetStrLen(Tempstr,blocksize+len);
memcpy(Tempstr,IpadKey,blocksize);
memcpy(Tempstr+blocksize,Text,len);
len=HashBytes(&Digest,Algo,Tempstr,blocksize+len,0);

Tempstr=SetStrLen(Tempstr,blocksize+len);
memcpy(Tempstr,OpadKey,blocksize);
memcpy(Tempstr+blocksize,Digest,len);
len=HashBytes(Return,Algo,Tempstr,blocksize+len,0);

DestroyString(Digest);
DestroyString(Tempstr);
DestroyString(IpadKey);
DestroyString(OpadKey);

return(len);
}


char *EncodeHash(char *Buffer, char *Digest, int len, int Encoding)
{
char *Tempstr=NULL, *RetStr=NULL;
int i;

RetStr=SetStrLen(Buffer,128);
if (Encoding==ENCODE_BASE64) to64frombits(RetStr,Digest,len);
else
{
	for (i=0; i < len; i++)
	{
	Tempstr=FormatStr(Tempstr,"%02x",Digest[i] & 255);
	RetStr=CatStr(RetStr,Tempstr);
	}
}

DestroyString(Tempstr);
return(RetStr);
}




#include "crc32.h"

void HashUpdateCRC(THash *Hash, char *Data, int Len)
{
crc32Update((unsigned long *) &Hash->Ctx, Data, Len);
}


int HashFinishCRC(THash *Hash, int Encoding, char **HashStr)
{
unsigned long crc;
int len;

len=sizeof(unsigned long);
crc32Finish((unsigned long *) Hash->Ctx);
//crc=htonl((unsigned long *) Hash->Ctx);

free(Hash->Ctx);

if (Encoding > 0) 
{
*HashStr=EncodeHash(*HashStr, (char *) &crc, len, Encoding);
return(StrLen(*HashStr));
}
else
{
*HashStr=SetStrLen(*HashStr,len);
memcpy(*HashStr,&crc,len);
return(len);
}
}


void HashInitCRC(THash *Hash)
{
Hash->Ctx=(void *) calloc(1,sizeof(unsigned long));
crc32Init((unsigned long *) Hash->Ctx);
Hash->Update=HashUpdateCRC;
Hash->Finish=HashFinishCRC;
}


#include "md5.h"
#define MD5LEN 16

void HashUpdateMD5(THash *Hash, char *Data, int Len)
{
MD5Update((MD5_CTX *) Hash->Ctx, Data, Len);
}


int HashFinishMD5(THash *Hash, int Encoding, char **HashStr)
{
int count, len;
char *Tempstr=NULL, *DigestBuff=NULL;

DigestBuff=(char *) calloc(1,MD5LEN+1);
MD5Final(DigestBuff, (MD5_CTX *) Hash->Ctx);

free(Hash->Ctx);

if (Encoding > 0)
{
*HashStr=EncodeHash(*HashStr, DigestBuff, MD5LEN, Encoding);
len=StrLen(*HashStr);
}
else
{
len=MD5LEN;
*HashStr=SetStrLen(*HashStr,len);
memcpy(*HashStr,DigestBuff,len);
}

DestroyString(DigestBuff);
DestroyString(Tempstr);

return(len);
}


void HashInitMD5(THash *Hash)
{
Hash->Ctx=(void *) calloc(1,sizeof(MD5_CTX));
MD5Init((MD5_CTX *) Hash->Ctx);
Hash->Update=HashUpdateMD5;
Hash->Finish=HashFinishMD5;
}

#include "sha1.h"
#define SHA1LEN 20

void HashUpdateSHA1(THash *Hash, char *Data, int Len)
{
sha1_process_bytes(Data,Len,(struct sha1_ctx *) Hash->Ctx);
}


int HashFinishSHA1(THash *Hash, int Encoding, char **HashStr)
{
int count, len;
char *Tempstr=NULL, *DigestBuff=NULL;

DigestBuff=(char *) calloc(1,SHA1LEN+1);
sha1_finish_ctx((struct sha1_ctx *) Hash->Ctx, DigestBuff);
free(Hash->Ctx);

if (Encoding > 0)
{
	 *HashStr=EncodeHash(*HashStr, DigestBuff, SHA1LEN, Encoding);
	 len=StrLen(*HashStr);
}
else
{
len=SHA1LEN;
*HashStr=SetStrLen(*HashStr,len);
memcpy(*HashStr,DigestBuff,len);
}

DestroyString(DigestBuff);
DestroyString(Tempstr);

return(len);
}


void HashInitSHA1(THash *Hash)
{
Hash->Ctx=(void *) calloc(1,sizeof(struct sha1_ctx));
sha1_init_ctx((struct sha1_ctx *) Hash->Ctx);
Hash->Update=HashUpdateSHA1;
Hash->Finish=HashFinishSHA1;
}


#include "sha2.h"

int HashFinishSHA256(THash *Hash, int Encoding, char **HashStr)
{
int count, len;
char *Tempstr=NULL;
uint8_t *DigestBuff=NULL;

DigestBuff=(uint8_t *) calloc(1,SHA256_DIGEST_LENGTH+1);
SHA256_Final(DigestBuff, (SHA256_CTX *) Hash->Ctx);
free(Hash->Ctx);

if (Encoding > 0)
{
	 *HashStr=EncodeHash(*HashStr, DigestBuff, SHA256_DIGEST_LENGTH, Encoding);
	 len=StrLen(*HashStr);
}
else
{
len=SHA256_DIGEST_LENGTH;
*HashStr=SetStrLen(*HashStr,len);
memcpy(*HashStr,DigestBuff,len);
}

DestroyString(DigestBuff);
DestroyString(Tempstr);

return(len);
}


void HashUpdateSHA256(THash *Hash, char *Data, int Len)
{
SHA256_Update((SHA256_CTX *) Hash->Ctx, Data, Len);
}

void HashInitSHA256(THash *Hash)
{
Hash->Ctx=(void *) calloc(1,sizeof(SHA256_CTX));
SHA256_Init((SHA256_CTX *) Hash->Ctx);
Hash->Update=HashUpdateSHA256;
Hash->Finish=HashFinishSHA256;
}


int HashFinishSHA512(THash *Hash, int Encoding, char **HashStr)
{
int count, len;
char *Tempstr=NULL, *DigestBuff=NULL;

DigestBuff=(char *) calloc(1,SHA512_DIGEST_LENGTH+1);
SHA512_Final(DigestBuff, (SHA512_CTX *) Hash->Ctx);
free(Hash->Ctx);

if (Encoding > 0)
{
	 *HashStr=EncodeHash(*HashStr, DigestBuff, SHA512_DIGEST_LENGTH, Encoding);
	 len=StrLen(*HashStr);
}
else
{
len=SHA512_DIGEST_LENGTH;
*HashStr=SetStrLen(*HashStr,len);
memcpy(*HashStr,DigestBuff,len);
}

DestroyString(DigestBuff);
DestroyString(Tempstr);

return(len);
}


void HashUpdateSHA512(THash *Hash, char *Data, int Len)
{
SHA512_Update((SHA512_CTX *) Hash->Ctx, Data, Len);
}

void HashInitSHA512(THash *Hash)
{
Hash->Ctx=(void *) calloc(1,sizeof(SHA512_CTX));
SHA512_Init((SHA512_CTX *) Hash->Ctx);
Hash->Update=HashUpdateSHA512;
Hash->Finish=HashFinishSHA512;
}




THash *HashInit(char *Type)
{
THash *Hash=NULL;

Hash=(THash *) calloc(1,sizeof(THash));
if (strcasecmp(Type,"md5")==0) HashInitMD5(Hash);
else if (strcasecmp(Type,"sha")==0) HashInitSHA1(Hash);
else if (strcasecmp(Type,"sha1")==0) HashInitSHA1(Hash);
else if (strcasecmp(Type,"sha256")==0) HashInitSHA256(Hash);
else if (strcasecmp(Type,"sha512")==0) HashInitSHA512(Hash);
else if (strcasecmp(Type,"crc32")==0) HashInitCRC(Hash);
else 
{
	free(Hash);
	Hash=NULL;
}

return(Hash);
}


void HashDestroy(THash *Hash)
{
//Hash->Ctx is destroyed in 'HashFinish'
DestroyString(Hash->Type);
free(Hash);
}


int HashBytes(char **Return, char *Type, char *text, int len, int Encoding)
{
THash *Hash;
int result;

Hash=HashInit(Type);
if (! Hash) return(0);
Hash->Update(Hash, text, len);
result=Hash->Finish(Hash, Encoding, Return);
HashDestroy(Hash);

return(result);
}


int HashFile(char **Return, char *Type, char *Path, int Encoding)
{
THash *Hash;
STREAM *S;
char *Tempstr=NULL;
int result;

S=STREAMOpenFile(Path,O_RDONLY);
if (! S) return(FALSE);

Hash=HashInit(Type);
if (! Hash) 
{
	STREAMClose(S);
	return(FALSE);
}


Tempstr=SetStrLen(Tempstr,4096);
result=STREAMReadBytes(S,Tempstr,4096);
while (result !=EOF)
{
	Hash->Update(Hash, Tempstr, result);
result=STREAMReadBytes(S,Tempstr,4096);
}

DestroyString(Tempstr);
STREAMClose(S);

result=Hash->Finish(Hash, Encoding, Return);
HashDestroy(Hash);

return(result);
}

