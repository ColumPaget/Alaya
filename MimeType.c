#include "MimeType.h"

ListNode *FileMagics=NULL;

#define FILEMAGIC 1
#define FILEEXTN  2

TFileMagic *GetFileMagic(char *Data, int Len)
{
ListNode *Curr;
TFileMagic *FM;

Curr=ListGetNext(FileMagics);
while (Curr)
{
	FM=(TFileMagic *) Curr->Item;
	if ( (FM->Type==FILEMAGIC) && (Len >= FM->Len) && (strncmp(Data,FM->Data,FM->Len)==0)) return(FM);
	Curr=ListGetNext(Curr);
}

return(NULL);
}


TFileMagic *GetFileTypeInfo(char *FName)
{
ListNode *Curr;
TFileMagic *FM;
char *ptr;


ptr=strrchr(FName,'.');
if (ptr)
{
ptr++;
Curr=ListGetNext(FileMagics);
while (Curr)
{
	FM=(TFileMagic *) Curr->Item;
	if ( (FM->Type==FILEEXTN) && (strcasecmp(ptr,FM->Data)==0)) 
	{
		return(FM);
	}
	Curr=ListGetNext(Curr);
}
}

Curr=ListFindNamedItem(FileMagics,"application/octet-stream");
if (Curr) return(TFileMagic *) Curr->Item;

return(NULL);
}



TFileMagic *GetContentTypeInfo(char *ContentType)
{
ListNode *Node;

Node=ListFindNamedItem(FileMagics,ContentType);
if ((! Node) && (strcmp(ContentType,"folder") !=0)) Node=ListFindNamedItem(FileMagics,"application/octet-stream");
if (Node) return(TFileMagic *) Node->Item;

return(NULL);
}


char *ContentTypeFromFileName(char *RetBuff, char *FName)
{
TFileMagic *FM;
char *RetStr=NULL;

RetStr=CopyStr(RetBuff,"");
FM=GetFileTypeInfo(FName);
if (FM) RetStr=CopyStr(RetStr,FM->ContentType);

return(RetStr);
}



void MimeTypesAddItem(char *ContentType, int Type, char *Data, int Len)
{
TFileMagic *FM;
char *Tempstr=NULL;

  FM=(TFileMagic *) calloc(1,sizeof(TFileMagic));
  FM->Type=Type;
  FM->ContentType=CopyStr(FM->ContentType,ContentType);
  FM->Data=CopyStr(FM->Data,Data);
  FM->Len=Len;

  ListAddNamedItem(FileMagics,FM->ContentType,FM);

	DestroyString(Tempstr);
}


int LoadMagicsFile(char *MagicsPath)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ContentType=NULL, *ptr;
TFileMagic *FM;

S=STREAMOpenFile(MagicsPath,O_RDONLY);
Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
	StripTrailingWhitespace(Tempstr);
	StripLeadingWhitespace(Tempstr);
	
	ptr=GetToken(Tempstr,"\\S",&ContentType,0);
	ptr=GetToken(ptr,"\\S",&Token,0);
	while (ptr)
	{
	  FM=(TFileMagic *) calloc(1,sizeof(TFileMagic));
	   FM->Type=FILEMAGIC;
	   FM->ContentType=CopyStr(FM->ContentType,ContentType);
	   ptr=GetToken(ptr,"\\S",&Token,0);
	   FM->Len=atoi(Token);
	   FM->Data=CopyStr(FM->Data,ptr);
	   ListAddItem(FileMagics,FM);
	}
	Tempstr=STREAMReadLine(Tempstr,S);
}

DestroyString(Tempstr);
DestroyString(Token);
DestroyString(ContentType);
STREAMClose(S);
}



void MimeTypesSetFlag(char *ContentType, int Flag)
{
ListNode *Curr;
TFileMagic *FM;

Curr=ListGetNext(FileMagics);
while (Curr)
{
	if (strcmp(Curr->Tag,ContentType)==0)
	{
	FM=(TFileMagic *) Curr->Item;
	FM->Flags |= Flag;
	}
Curr=ListGetNext(Curr);
}
}


void LoadFileMagics(char *MimeTypesPath, char *MagicsPath)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ContentType=NULL, *ptr;
int len;

if (! FileMagics) FileMagics=ListCreate();

//Load some defaults, even if we have a mime-types file, it might not
//hall all of these
   MimeTypesAddItem("folder", 0, "", 0);
   MimeTypesAddItem("text/plain", FILEEXTN, "txt", 0);
   MimeTypesAddItem("text/css", FILEEXTN, "css", 0);
   MimeTypesAddItem("text/html", FILEEXTN, "htm", 0);
   MimeTypesAddItem("text/html", FILEEXTN, "html", 0);
   MimeTypesAddItem("image/jpeg", FILEEXTN, "jpeg", 0);
   MimeTypesAddItem("image/jpeg", FILEEXTN, "jpg", 0);
   MimeTypesAddItem("image/png", FILEEXTN, "png", 0);
   MimeTypesAddItem("image/bmp", FILEEXTN, "bmp", 0);
   MimeTypesAddItem("image/gif", FILEEXTN, "gif", 0);
   MimeTypesAddItem("image/pgn", FILEEXTN, "png", 0);
   MimeTypesAddItem("audio/mp3", FILEEXTN, "mp3", 0);
   MimeTypesAddItem("audio/ogg", FILEEXTN, "ogg", 0);
   MimeTypesAddItem("video/flv", FILEEXTN, "flv", 0);
   MimeTypesAddItem("video/mp4", FILEEXTN, "mp4", 0);
   MimeTypesAddItem("video/mpeg", FILEEXTN, "mpeg", 0);
   MimeTypesAddItem("video/webm", FILEEXTN, "webm", 0);
   MimeTypesAddItem("video/3gp", FILEEXTN, "3gp", 0);
   MimeTypesAddItem("video/quicktime", FILEEXTN, "mov", 0);
   MimeTypesAddItem("video/x-ms-wmv", FILEEXTN, "wmv", 0);
   MimeTypesAddItem("video/x-ms-video", FILEEXTN, "avi", 0);
   MimeTypesAddItem("application/sh", FILEEXTN, "sh", 0);
   MimeTypesAddItem("application/xml", FILEEXTN, "xml", 0);
   MimeTypesAddItem("application/xml", FILEEXTN, "xsl", 0);
   MimeTypesAddItem("application/pdf", FILEEXTN, "pdf", 0);
   MimeTypesAddItem("application/rtf", FILEEXTN, "rtf", 0);
   MimeTypesAddItem("application/javascript", FILEEXTN, "js", 0);
   MimeTypesAddItem("application/json", FILEEXTN, "json", 0);
   MimeTypesAddItem("application/zip", FILEEXTN, "zip", 0);
   MimeTypesAddItem("application/zip", FILEEXTN, "zip", 0);
   MimeTypesAddItem("application/x-bzip", FILEEXTN, "bz", 0);
   MimeTypesAddItem("application/x-bzip2", FILEEXTN, "bz2", 0);
   MimeTypesAddItem("application/x-gzip", FILEEXTN, "gz", 0);
   MimeTypesAddItem("application/x-shockwave-flash", FILEEXTN, "swf", 0);
   MimeTypesAddItem("application/x-sh", FILEEXTN, "sh", 0);


S=STREAMOpenFile(MimeTypesPath,O_RDONLY);
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		StripTrailingWhitespace(Tempstr);
		StripLeadingWhitespace(Tempstr);

		ptr=GetToken(Tempstr,"\\S",&ContentType,0);
		ptr=GetToken(ptr,"\\S",&Token,0);

		while (ptr)
		{
		   MimeTypesAddItem(ContentType, FILEEXTN, Token, StrLen(Token));
		   ptr=GetToken(ptr,"\\S",&Token,0);
		}
		Tempstr=STREAMReadLine(Tempstr,S);
	}
STREAMClose(S);
}

MimeTypesSetFlag("audio/mp3",FM_MEDIA_TAG);
MimeTypesSetFlag("audio/ogg",FM_MEDIA_TAG);
MimeTypesSetFlag("image/jpeg",FM_IMAGE_TAG);
MimeTypesSetFlag("image/png",FM_IMAGE_TAG);
MimeTypesSetFlag("image/bmp",FM_IMAGE_TAG);

DestroyString(Tempstr);
DestroyString(Token);
DestroyString(ContentType);
}



int ExamineFile(char *FName, int ExamineContents, ListNode *Vars)
{
STREAM *S=NULL;
char *Buffer=NULL;
int result;
TFileMagic *FM=NULL;
struct stat FileStat;

if (stat(FName,&FileStat)==-1) return(FILE_NOSUCH);



Buffer=FormatStr(Buffer,"%d",FileStat.st_size);
SetVar(Vars,"FileSize",Buffer);
Buffer=FormatStr(Buffer,"%d",FileStat.st_ctime);
SetVar(Vars,"CTime-Secs",Buffer);
Buffer=FormatStr(Buffer,"%d",FileStat.st_mtime);
SetVar(Vars,"MTime-Secs",Buffer);


//if it's a directory, don't both doing any more examining
if (S_ISDIR(FileStat.st_mode)) 
{
	SetVar(Vars,"IsCollection","1");
	SetVar(Vars,"ContentType","Directory");
	DestroyString(Buffer);
	return(FILE_DIR);
}


if (! (FileStat.st_mode & S_IWUSR)) SetVar(Vars,"IsReadOnly","1");
if ((FileStat.st_mode & S_IXUSR)) SetVar(Vars,"IsExecutable","T");
else SetVar(Vars,"IsExecutable","F");


if (ExamineContents)
{
	//First try to identify by file magic
	S=STREAMOpenFile(FName,O_RDONLY);
	if (S) 
	{
		Buffer=SetStrLen(Buffer,21);
		result=STREAMReadBytes(S,Buffer,20);
		FM=GetFileMagic(Buffer,result);
	}
}

// Do this even if S not open or ExamineContents not set
if (! FM) FM=GetFileTypeInfo(FName);
if (FM) SetVar(Vars,"ContentType",FM->ContentType);


// if 'S' open then ExamineContents WAS set
if (S) 
{
	if (FM->Flags & (FM_MEDIA_TAG | FM_IMAGE_TAG))
	{
		STREAMSeek(S,0,SEEK_SET);
		MediaReadDetails(S, Vars);
	}
	STREAMClose(S);
}


DestroyString(Buffer);

return(TRUE);
}


