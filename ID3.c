#include "ID3.h"

#define ID3v1_LEN 128
char *TagTypes[]={"ID31TAGEND","TAG","ID3","Ogg","\x89PNG","\xFF\xD8\xFF",NULL};
typedef enum {TAG_ID3_END,TAG_ID3,TAG_ID3v2,TAG_OGG,TAG_PNG,TAG_JPEG};


typedef struct
{
char TAG[3];
char Title[30];
char Artist[30];
char Album[30];
char Year[4];
char Comment[30];
char Genre;
}TID3v1_TAG;

/*
void WriteID3Tag(char *Path, TTaskOp*Track)
{
TID3v1_TAG *Tag;
int fd;
char *ptr;

Tag=(TID3v1_TAG *) calloc(1,sizeof(TID3v1_TAG));

strncpy(Tag->TAG,"TAG",3);
ptr=GetVar(Track->Vars,"Artist");
strncpy(Tag->Artist,ptr,TAGFIELD_LEN);
ptr=GetVar(Track->Vars,"Album");
strncpy(Tag->Album,ptr,TAGFIELD_LEN);
ptr=GetVar(Track->Vars,"Title");
strncpy(Tag->Title,ptr,TAGFIELD_LEN);
strcpy(Tag->Comment,"");
ptr=GetVar(Track->Vars,"Comment");
if (StrLen(ptr)) strncpy(Tag->Comment,ptr,TAGFIELD_LEN);


strncpy(Tag->Year,"????",4);
Tag->Genre=12;

fd=open(Path,O_APPEND | O_WRONLY);
if (fd > -1)
{
	write(fd,Tag,sizeof(TID3v1_TAG));
	close(fd);
}
free(Tag);
}
*/


int ID3v1ReadTag(STREAM *S, ListNode *Vars)
{
char *Tempstr=NULL;
TID3v1_TAG *Tag;
int result=FALSE;

Tag=(TID3v1_TAG *) calloc(1,sizeof(TID3v1_TAG));

STREAMReadBytes(S,(char *) Tag,sizeof(TID3v1_TAG));

Tempstr=CopyStrLen(Tempstr,Tag->Artist,30);
SetVar(Vars,"Artist",Tempstr);
Tempstr=CopyStrLen(Tempstr,Tag->Album,30);
SetVar(Vars,"Album",Tempstr);
Tempstr=CopyStrLen(Tempstr,Tag->Title,30);
SetVar(Vars,"Title",Tempstr);
Tempstr=CopyStrLen(Tempstr,Tag->Comment,30);
SetVar(Vars,"Comment",Tempstr);
Tempstr=CopyStrLen(Tempstr,Tag->Year,4);
SetVar(Vars,"Year",Tempstr);

result=TRUE;

DestroyString(Tempstr);
free(Tag);

return(result);
}

int ConvertSyncsafeBytes(uint8_t High, uint8_t Low)
{
int val;

val=High;
val >> 1;
val |= Low;

return(val);
}


int ID3v2ReadTag(STREAM *S, ListNode *Vars)
{
char *Tempstr=NULL, *TagName=NULL;
uint8_t Version, Revision;
int TagNameLen=4, len, result;
char *ID3v2Fields[]={"TCOM","TALB","TIT2","COMM","TBPM","TPE1","TPE2","TYER","TLEN","TCON","TRCK",NULL};
typedef enum {TAG_COMPOSER,TAG_ALBUM,TAG_TITLE,TAG_COMMENT,TAG_BPM,TAG_ARTIST,TAG_BAND,TAG_YEAR,TAG_LEN,TAG_GENRE,TAG_TRACK};

Tempstr=SetStrLen(Tempstr,100);

//Read 'ID3'
STREAMReadBytes(S,Tempstr,3);

//ReadTag Version
STREAMReadBytes(S,(char *) &Version,1);
STREAMReadBytes(S,(char *) &Revision,1);

//Other info
STREAMReadBytes(S,Tempstr,5);

//Read Tag Frames
while (1)
{
TagName=SetStrLen(TagName,TagNameLen);
result=STREAMReadBytes(S,TagName,TagNameLen);
TagName[result]='\0';
if (*TagName=='/0') break;

//Flags
STREAMReadBytes(S,Tempstr,2);


//Data len, stored in a crazy 'syncsafe' format
STREAMReadBytes(S,Tempstr,4);
len=ConvertSyncsafeBytes(Tempstr[1], Tempstr[0]);
if (len < 1) break;

//Encoding Byte, this counts as part of the data, so we read len-1
STREAMReadBytes(S,Tempstr,1);

Tempstr=SetStrLen(Tempstr,len);
result=STREAMReadBytes(S,Tempstr,len-1);
Tempstr[result]='\0';

if (StrLen(Tempstr))
{
	result=MatchTokenFromList(TagName,ID3v2Fields,0);
	switch (result)
	{
		case TAG_ARTIST:
		case TAG_BAND:
		case TAG_COMPOSER: SetVar(Vars,"Artist",Tempstr); break;
		case TAG_ALBUM: SetVar(Vars,"Album",Tempstr); break;
		case TAG_TITLE: SetVar(Vars,"Title",Tempstr); break;
		case TAG_COMMENT: SetVar(Vars,"Comment",Tempstr); break;
		case TAG_BPM: SetVar(Vars,"BPM",Tempstr); break;
		case TAG_YEAR: SetVar(Vars,"Year",Tempstr); break;
		case TAG_GENRE: SetVar(Vars,"Genre",Tempstr); break;
		case TAG_TRACK: SetVar(Vars,"AlbumTrackNumber",Tempstr); break;
		case TAG_LEN: 
			//convert from milliseconds
			len=atoi(Tempstr) / 1000;
			Tempstr=FormatStr(Tempstr,"%d:%d",len / 60, len % 60);
			SetVar(Vars,"Duration",Tempstr); 
		break;

	}
}

}

DestroyString(TagName);
DestroyString(Tempstr);

return(TRUE);
}



int ReadTagType(STREAM *S)
{
char *Tempstr=NULL;
int result;
	
Tempstr=SetStrLen(Tempstr,20);
memset(Tempstr,0,20);
STREAMReadBytes(S,Tempstr,20);
result=MatchTokenFromList(Tempstr,TagTypes,MATCH_TOKEN_PART|MATCH_TOKEN_CASE);
STREAMSeek(S,(double) 0, SEEK_SET); 

DestroyString(Tempstr);
	
return(result);
}




int OggReadHeader(STREAM *S, uint8_t *SegTable)
{
char *Tempstr=NULL, *ptr;
uint8_t NoOfSegments=0;

Tempstr=SetStrLen(Tempstr,4096);
memset(Tempstr,0,4096);
STREAMReadBytes(S,Tempstr,4);

if (strcmp(Tempstr,"OggS")==0)
{
//Read ogg gubbins and throw it away
STREAMReadBytes(S,Tempstr,22);
STREAMReadBytes(S,(char *) &NoOfSegments,1);
STREAMReadBytes(S,SegTable,NoOfSegments);
}

DestroyString(Tempstr);

return(NoOfSegments);
}

int OggReadData(STREAM *S, char **Data)
{
uint8_t *SegTable=NULL;
uint8_t NoOfSegments;
char *Tempstr=NULL, *ptr;
int i, len=0, result;

*Data=realloc(*Data,4096);
SegTable=(uint8_t *) calloc(1,255);
Tempstr=SetStrLen(Tempstr,1024);

//Read segment header
NoOfSegments=OggReadHeader(S, SegTable);

for (i=0; i < NoOfSegments; i++)
{
	memset(Tempstr,0,255);
	result=STREAMReadBytes(S,Tempstr,SegTable[i]);
	ptr=(*Data) +len;
	memcpy(ptr,Tempstr,result);
	len+=result;
}

DestroyString(SegTable);
DestroyString(Tempstr);

return(len);
}


void OggInterpretComment(char *Data, int MaxLen, ListNode *Vars)
{
uint32_t flen, NoOfFields, i;
char *Tempstr=NULL, *Name=NULL, *Token=NULL, *Value=NULL, *ptr, *end;

if (MaxLen==0) return;
end=Data+MaxLen;

//+7 to get beyond '<typechar>vorbis'
ptr=Data+7;


//Skip 'Vendor' field
flen=(*(uint32_t *) ptr);
ptr+=4;
ptr+=flen;

//Read 'NoOfFields'
NoOfFields=(*(uint32_t *) ptr);
ptr+=4;


for (i=0; i < NoOfFields; i++)
{
	//sanity check
	if (ptr >= end) break;

	flen=(*(uint32_t *) ptr);
	ptr+=4;

	//255 means the field is a continuation of what went before
	if (i==0) Tempstr=CatStr(Tempstr," '");
	else if (flen < 255 ) Tempstr=CatStr(Tempstr,"' '");
	Tempstr=CatStrLen(Tempstr,ptr,flen);
	
	ptr+=flen;
}

if (StrLen(Tempstr)) Tempstr=CatStr(Tempstr,"'");

ptr=GetToken(Tempstr," ",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	Value=CopyStr(Value,GetToken(Token,"=",&Name,0));
	SetVar(Vars,Name,Value);
ptr=GetToken(ptr," ",&Token,GETTOKEN_QUOTES);
}


DestroyString(Tempstr);
DestroyString(Token);
DestroyString(Value);
DestroyString(Name);
}



int OggReadTag(STREAM *S, ListNode *Vars)
{
char *Data=NULL;
int len;

OggReadData(S,&Data);
len=OggReadData(S,&Data);

OggInterpretComment(Data, len, Vars);

DestroyString(Data);

return(TRUE);
}



int TIFFParseHeader(char *Data,int len, ListNode *Vars)
{
char *ptr;
int offset, NoOfTags;

ptr=Data+4;

LogToFile(Settings.LogPath,"DATA: [%s]",Data);
if (strncmp(Data,"II",2)==0)
{
	offset=(* (uint32_t *) ptr);
	ptr=(Data+offset);
	NoOfTags=(* (uint16_t *) ptr);
}
else
{
	offset=ntohs(* (uint32_t *) ptr);
	ptr=(Data+offset);
	NoOfTags=(ntohs(* (uint16_t *) ptr));
}

LogToFile(Settings.LogPath,"Offset: %d NoOfTags: %d",offset,NoOfTags);
}


int JPEGReadHeader(STREAM *S, ListNode *Vars)
{
char *Data=NULL, *ptr;
int len, w, l;
#define READ_LEN 1024

Data=SetStrLen(Data,READ_LEN);
len=STREAMReadBytes(S,Data,READ_LEN);

if (len==READ_LEN)
{
if (memcmp(Data+6,"JFIF",4)==0) 
{
	len=ntohs(* (uint16_t *) (Data+4));
	ptr=Data+len+4;
}
else ptr=Data+2;

LogToFile(Settings.LogPath,"PTR: [%s] [%x] [%x] [%s]",Data,ptr[0],ptr[1],ptr+4);

if (
		(memcmp(ptr,"\xFF\xE1",2)==0) &&
		(memcmp(ptr+4,"Exif\x00\x00",6)==0) 
	)
	{
		ptr+=10;
		TIFFParseHeader(ptr,(Data+READ_LEN)-ptr, Vars);
	}
}

DestroyString(Data);

return(TRUE);
}



int PNGReadHeader(STREAM *S, ListNode *Vars)
{
char *Data=NULL, *Type=NULL;
int val, w, l, d;
uint16_t *ptr;

Data=SetStrLen(Data,30);
val=STREAMReadBytes(S,Data,30);

if (val==30)
{
if (strncmp(Data+12,"IHDR",4)==0)
{
	w=ntohl(* (uint32_t *) (Data+16));
	l=ntohl(* (uint32_t *) (Data+20));
	d=*(Data+24);
	
	switch (*(Data+25))
	{
	case 0: Type=CopyStr(Type,"Greyscale "); break;
	case 2: Type=CopyStr(Type,"Truecolor"); d=d*3; break;
	case 3: Type=CopyStr(Type,"IndexedColor "); d=d*3; break;
	case 4: Type=CopyStr(Type,"Greyscale+Alpha "); break;
	case 6: Type=CopyStr(Type,"Truecolor+Alpha "); d=d*3; break;
	}
	
	Data=FormatStr(Data,"PNG: Resolution: %dx%d Depth: %d Type: %s",w,l,d,Type);
	SetVar(Vars,"ImageDetails",Data);
}
}

DestroyString(Type);
DestroyString(Data);

return(TRUE);
}



int MediaReadDetails(STREAM *S, ListNode *Vars)
{
int result=FALSE;

result=ReadTagType(S);
if (result==-1)
{
	STREAMSeek(S,(double) 0 - ID3v1_LEN,SEEK_END);
	result=ReadTagType(S);
	if (result==TAG_ID3) result=TAG_ID3_END;
	else result=-1;
}

switch (result)
{
case TAG_ID3: result=ID3v1ReadTag(S,Vars); break;
case TAG_ID3_END: STREAMSeek(S,(double) 0 - ID3v1_LEN,SEEK_END); result=ID3v1ReadTag(S,Vars); break;
case TAG_ID3v2: result=ID3v2ReadTag(S,Vars); break;
case TAG_OGG: result=OggReadTag(S,Vars); break;
case TAG_JPEG: result=JPEGReadHeader(S,Vars); break;
case TAG_PNG: result=PNGReadHeader(S,Vars); break;
//case TAG_TIFF: STREAMSeek(S,(double) 0, SEEK_SET); result=TIFFReadHeader(S,Vars); break;
}

//Set us back to the start of the file 
STREAMSeek(S,(double) 0, SEEK_SET);

return(result);
}

