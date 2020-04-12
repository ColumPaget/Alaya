#include <sys/sysmacros.h>
#include "tar.h"
#include <glob.h>
#include <pwd.h>
#include <grp.h>

#define TAR_RECORDSIZE 512
#define FILE_MODE_OFFSET 100
#define USER_OFFSET  108
#define GROUP_OFFSET 116
#define SIZE_OFFSET  124
#define MTIME_OFFSET 136
#define CHECKSUM_OFFSET 148
#define FTYPE_OFFSET 157

typedef struct 
{                              /* byte offset */
  char name[100];               /*   0 */
  char mode[8];                 /* 100 */
  char uid[8];                  /* 108 */
  char gid[8];                  /* 116 */
  char size[12];                /* 124 */
  char mtime[12];               /* 136 */
  char chksum[8];               /* 148 */
  char typeflag;                /* 156 */
  char linkname[100];           /* 157 */
  char magic[6];                /* 257 */
  char version[2];              /* 263 */
  char uname[32];               /* 265 */
  char gname[32];               /* 297 */
  char devmajor[8];             /* 329 */
  char devminor[8];             /* 337 */
  char prefix[155];             /* 345 */
                                /* 500 */
	char pad[12];
} TTarHeader;

const char *TarItemStrings[]={"file","hardlink","symlink","blkdev","chrdev","dir","fifo",NULL};
typedef enum {TAR_FILE, TAR_HARDLINK, TAR_SYMLINK, TAR_CHRDEV, TAR_BLKDEV, TAR_DIR, TAR_FIFO} TarItemTypes ;


static int TarReadHeader(STREAM *S, ListNode *Vars)
{
char *Tempstr=NULL, *ptr;
int len, result, RetVal=FALSE;
TTarHeader *Head;

len=sizeof(TTarHeader);
Head=(TTarHeader *) calloc(1,len);
result=STREAMReadBytes(S,(char *) Head,len);
printf("HEAD: %d %s\n",result,(char *) Head);
if (result == len)
{
Tempstr=CopyStr(Tempstr,Head->prefix);
Tempstr=CatStr(Tempstr,Head->name);
SetVar(Vars,"Path",Tempstr);

//Convert 'Size' from octal. Yes, octal.
Tempstr=FormatStr(Tempstr,"%d",strtol(Head->size,NULL,8));
SetVar(Vars,"Size",Tempstr);

//mode is in octal too
Tempstr=FormatStr(Tempstr,"%d",strtol(Head->mode,NULL,8));
SetVar(Vars,"Mode",Tempstr);

//mtime in, yes, you guessed it, octal 
Tempstr=FormatStr(Tempstr,"%d",strtol(Head->mtime,NULL,8));
SetVar(Vars,"Mtime",Tempstr);


SetVar(Vars,"Type","file"); 
StripTrailingWhitespace(Head->magic);

if (strcmp(Head->magic,"ustar")==0) 
{
result=Head->typeflag - '0';
ptr=(char *) ArrayGetItem((void **) TarItemStrings, result);
if (ptr) SetVar(Vars, "Type", ptr);
switch (result)
{
	case TAR_HARDLINK: SetVar(Vars,"Type","hardlink"); break;
	case TAR_SYMLINK: SetVar(Vars,"Type","symlink"); break;
	case TAR_CHRDEV: SetVar(Vars,"Type","chardev"); break;
	case TAR_BLKDEV: SetVar(Vars,"Type","blkdev"); break;
	case TAR_DIR: SetVar(Vars,"Type","directory"); break;
}

}
RetVal=TRUE;
}

Destroy(Tempstr);
free(Head);

return(RetVal);
}


size_t TarFind(STREAM *Tar, const char *FileName)
{
ListNode *Vars;
const char *p_SearchName, *p_FName, *p_FType;
int size;

p_SearchName=FileName;
if (*p_SearchName=='/') p_SearchName++;

Vars=ListCreate();
while (TarReadHeader(Tar, Vars))
{
	p_FName=GetVar(Vars,"Path");
	p_FType=GetVar(Vars,"Type");
	if (
			(p_FType && (strcmp(p_SearchName, p_FType)==0) ) &&
			(p_FName && (strcmp("file", p_FName)==0) )
		)
	{
		size=atoll(GetVar(Vars,"Size"));
		break;
	}
}

ListDestroy(Vars,Destroy);

return(size);
}


int TarUnpack(STREAM *Tar, const char *Pattern)
{
ListNode *Vars;
char *Path=NULL, *Tempstr=NULL;
const char *ptr;
int bytes_read, bytes_total, val, result, count=0;
STREAM *S;

Vars=ListCreate();
while (TarReadHeader(Tar, Vars))
{
	Path=CopyStr(Path,GetVar(Vars,"Path"));
	if (StrValid(Path) && (fnmatch(Pattern, Path, 0)==0))
	{
		ptr=GetVar(Vars,"Type");
		if (ptr)
		{
		if (strcmp(ptr,"directory")==0)
		{
			mkdir(Path,atoi(GetVar(Vars,"Mode")));
		}
		else if (strcmp(ptr,"file")==0)
		{
			MakeDirPath(Path,0700);
			S=STREAMOpen(Path,"wc");
			if (S) 
			{
				fchmod(S->out_fd,atoi(GetVar(Vars,"Mode")));
				count++;
			}
			bytes_read=0;
			bytes_total=atoi(GetVar(Vars,"Size"));
			Tempstr=SetStrLen(Tempstr,BUFSIZ);
			while (bytes_read < bytes_total)
			{
        val=bytes_total - bytes_read;
        if (val > BUFSIZ) val=BUFSIZ;
        if ((val % 512)==0) result=val;
        else result=((val / 512) + 1) * 512;
        result=STREAMReadBytes(Tar,Tempstr,result);
        if (result > val) result=val;
        if (S) STREAMWriteBytes(S,Tempstr,result);
        bytes_read+=result;
			}
			STREAMClose(S);	
		}
		}
	}
	ListClear(Vars,Destroy);
}

ListDestroy(Vars,Destroy);
Destroy(Tempstr);
Destroy(Path);

return(count);
}



static TTarHeader *TarGenerateHeader(const char *Path, char TypeFlag, struct stat *FStat)
{
TTarHeader *Head;
const char *ptr;
struct passwd *pwd;
struct group *grp;
int i, chksum=0;

	Head=(TTarHeader *) calloc(1,sizeof(TTarHeader));

	ptr=Path;
	if (*ptr=='/') ptr++;
	memcpy(Head->name,ptr,StrLen(ptr));

	memset(Head->chksum,' ',8);
	memcpy(Head->magic,"ustar\0",6);
	memcpy(Head->version,"00",2);

	snprintf(Head->mode,8,"%07o",FStat->st_mode);
	snprintf(Head->uid,8,"%07o",FStat->st_uid);
	snprintf(Head->gid,8,"%07o",FStat->st_gid);
	snprintf(Head->size,12,"%011lo",(unsigned long) FStat->st_size);
	snprintf(Head->mtime,12,"%011lo",(unsigned long) FStat->st_mtime);

	pwd=getpwuid(FStat->st_uid);
	if (pwd) strcpy(Head->uname,pwd->pw_name);

	grp=getgrgid(FStat->st_gid);
	if (grp) strcpy(Head->gname,grp->gr_name);


	Head->typeflag=TypeFlag;

if ( (TypeFlag == '3') || (TypeFlag == '4') ) 
{
	snprintf(Head->devmajor,8,"%07o",major(FStat->st_rdev));
	snprintf(Head->devminor,8,"%07o",minor(FStat->st_rdev));
}

ptr=(char *) Head;
for (i=0; i < 512; i++) chksum+=*(ptr+i);
snprintf(Head->chksum,8,"%06o",chksum);


	return(Head);
}


static int TarWriteHeader(STREAM *S, const char *Path, struct stat *FStat)
{
char *Tempstr=NULL, *ptr;
char TypeFlag;
TTarHeader *Head;

if ((! S) || StrEnd(Path) || (! FStat)) return(FALSE);

if (S_ISDIR(FStat->st_mode)) TypeFlag='5';
else if (S_ISLNK(FStat->st_mode)) TypeFlag='2';
else if (S_ISCHR(FStat->st_mode)) TypeFlag='3';
else if (S_ISBLK(FStat->st_mode)) TypeFlag='4';
else if (S_ISFIFO(FStat->st_mode)) TypeFlag='6';
else TypeFlag='0';

Head=TarGenerateHeader(Path, TypeFlag, FStat);
STREAMWriteBytes(S,(char *) Head,512);

Destroy(Tempstr);
free(Head);

return(TRUE);
}


static int TarWriteParsedHeader(STREAM *S, const char *Info)
{
char *Name=NULL, *Value=NULL, *Path=NULL;
char TypeChar='0';
const char *ptr;
char *tptr;
unsigned long devmin, devmaj;
struct stat FStat;
TTarHeader *Head;

FStat.st_mtime=GetTime(TIME_CACHED);
FStat.st_mode=0600;
FStat.st_uid=getuid();
FStat.st_gid=getgid();
ptr=GetToken(Info, "\\S",&Path,GETTOKEN_QUOTES);
ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
while (ptr)
{
if (strcmp(Name,"uid")==0) FStat.st_uid=strtol(Value,NULL,10);
else if (strcmp(Name,"gid")==0) FStat.st_gid=strtol(Value,NULL,10);
else if (strcmp(Name,"size")==0) FStat.st_size=strtol(Value,NULL,10);
else if (strcmp(Name,"dev")==0)
{
devmaj=strtol(Value,&tptr,10);
if (tptr)
{
	if (*tptr==',') tptr++;
	devmin=strtol(tptr,&tptr,10);
	FStat.st_rdev=makedev(devmaj, devmin);
}
}
else if (strcmp(Name,"type")==0) 
{
TypeChar=MatchTokenFromList(Value,TarItemStrings,0) + '0';
}

ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
}

Head=TarGenerateHeader(Path, TypeChar, &FStat);
STREAMWriteBytes(S,(char *) Head,512);

Destroy(Name);
Destroy(Value);
Destroy(Path);
}


static int TarWriteFooter(STREAM *Tar)
{
char *Tempstr=NULL;

if (! Tar) return(FALSE);
Tempstr=SetStrLen(Tempstr,TAR_RECORDSIZE);
memset(Tempstr,0,TAR_RECORDSIZE);
STREAMWriteBytes(Tar,Tempstr,TAR_RECORDSIZE);
STREAMWriteBytes(Tar,Tempstr,TAR_RECORDSIZE);

Destroy(Tempstr);

return(TRUE);
}


static int TarWriteBytes(STREAM *Tar, const char *Bytes, int Len)
{
int blocks, tarlen;
char *Fill=NULL;

blocks=Len / TAR_RECORDSIZE;
if ((Len % TAR_RECORDSIZE) !=0) blocks++;
tarlen=blocks * TAR_RECORDSIZE;
STREAMWriteBytes(Tar, Bytes, Len);

Fill=(char *) calloc(1, TAR_RECORDSIZE);
STREAMWriteBytes(Tar, Fill, tarlen-Len);
Destroy(Fill);

return(TRUE);
}


static int TarAddFile(STREAM *Tar, STREAM *File)
{
char *Buffer=NULL;
int result;

if ((! Tar) || (! File)) return(FALSE);
Buffer=SetStrLen(Buffer,TAR_RECORDSIZE);

memset(Buffer,0,TAR_RECORDSIZE);
result=STREAMReadBytes(File,Buffer,TAR_RECORDSIZE);
while (result > 0)
{
	STREAMWriteBytes(Tar,Buffer,TAR_RECORDSIZE);
	memset(Buffer,0,TAR_RECORDSIZE);
	result=STREAMReadBytes(File,Buffer,TAR_RECORDSIZE);
}

Destroy(Buffer);

return(TRUE);
}



static int TarInternalProcessFiles(STREAM *Tar, const char *FilePattern)
{
glob_t Glob;
char *Tempstr=NULL;
const char *ptr;
struct stat FStat;
int i, count=0;
STREAM *S;

ptr=GetToken(FilePattern,"\\S",&Tempstr,GETTOKEN_QUOTES);
if (ptr) glob(Tempstr,0,NULL,&Glob);
while (ptr)
{
	ptr=GetToken(ptr,"\\S",&Tempstr,GETTOKEN_QUOTES);
	if (ptr) glob(Tempstr,GLOB_APPEND,NULL,&Glob);
}

for (i=0; i < Glob.gl_pathc; i++)
{
	stat(Glob.gl_pathv[i],&FStat);
	if (S_ISDIR(FStat.st_mode))
	{
		Tempstr=MCopyStr(Tempstr,Glob.gl_pathv[i],"/*",NULL);
		TarInternalProcessFiles(Tar, Tempstr);
	}
	else 
	{
		S=STREAMOpen(Glob.gl_pathv[i],"r");
		if (S)
		{
			TarWriteHeader(Tar, Glob.gl_pathv[i],&FStat);
			TarAddFile(Tar, S);
			STREAMClose(S);
			count++;
		}
	}
}


globfree(&Glob);
Destroy(Tempstr);

return(count);
}


int TarFiles(STREAM *Tar, const char *FilePattern)
{
int count;

	if ((! Tar) || StrEnd(FilePattern)) return(0);
	count=TarInternalProcessFiles(Tar, FilePattern);

	return(count);
}
