#include "MimeType.h"

ListNode *FileMagics=NULL;

#define FILEMAGIC 1
#define FILEEXTN  2

TFileMagic *GetFileMagic(const char *Data, int Len)
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


TFileMagic *GetFileTypeInfo(const char *FName)
{
ListNode *Curr;
TFileMagic *FM;
const char *ptr;


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



TFileMagic *GetContentTypeInfo(const char *ContentType)
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



void MimeTypesAddItem(const char *ContentType, int Type, const char *Data, int Len)
{
TFileMagic *FM;
char *Tempstr=NULL;

  FM=(TFileMagic *) calloc(1,sizeof(TFileMagic));
  FM->Type=Type;
  FM->ContentType=CopyStr(FM->ContentType,ContentType);
  FM->Data=CopyStr(FM->Data,Data);
  FM->Len=Len;

  ListAddNamedItem(FileMagics,FM->ContentType,FM);

	Destroy(Tempstr);
}


int LoadMagicsFile(const char *MagicsPath)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ContentType=NULL;
const char *ptr;
TFileMagic *FM;

S=STREAMFileOpen(MagicsPath,SF_RDONLY);
if (! S) return(FALSE);
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

Destroy(Tempstr);
Destroy(Token);
Destroy(ContentType);
STREAMClose(S);

return(TRUE);
}



void MimeTypesSetFlag(const char *ContentType, int Flag)
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


void LoadFileMagics(const char *MimeTypesPath, const char *MagicsPath)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ContentType=NULL;
const char *ptr;

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
   MimeTypesAddItem("application/x-xz", FILEEXTN, "xz", 0);
   MimeTypesAddItem("application/x-tar", FILEEXTN, "tar", 0);
   MimeTypesAddItem("application/x-tgz", FILEEXTN, "tgz", 0);
   MimeTypesAddItem("application/x-tbz", FILEEXTN, "tbz", 0);
   MimeTypesAddItem("application/x-tbz", FILEEXTN, "txz", 0);
   MimeTypesAddItem("application/x-shockwave-flash", FILEEXTN, "swf", 0);
   MimeTypesAddItem("application/x-sh", FILEEXTN, "sh", 0);


S=STREAMFileOpen(MimeTypesPath,SF_RDONLY);
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

Destroy(Tempstr);
Destroy(Token);
Destroy(ContentType);
}



TFileMagic *GetFileMagicForFile(const char *Path, STREAM *S)
{
TFileMagic *FM=NULL;
char *Buffer=NULL;
int result;

if (S)
{
	Buffer=SetStrLen(Buffer,21);
	result=STREAMReadBytes(S,Buffer,20);
	FM=GetFileMagic(Buffer,result);
	STREAMSeek(S,0,SEEK_SET);
}

// Do this even if S not open 
if (! FM) FM=GetFileTypeInfo(Path);

Destroy(Buffer);
return(FM);
}


