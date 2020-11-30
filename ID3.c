#include "ID3.h"

#define ID3v1_LEN 128
const char *TagTypes[]= {"","ID31TAGEND","TAG","ID3\x02","ID3\x03","ID3\x04","Ogg","\x89PNG","\xFF\xD8\xFF","BM",NULL};
typedef enum {TAG_NONE, TAG_ID3_END,TAG_ID3,TAG_ID3v2,TAG_ID3v3,TAG_ID3v4,TAG_OGG,TAG_PNG,TAG_JPEG,TAG_BMP} TTagType;


typedef struct
{
    char TAG[3];
    char Title[30];
    char Artist[30];
    char Album[30];
    char Year[4];
    char Comment[30];
    char Genre;
} TID3v1_TAG;

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


static int ID3v1ReadTag(STREAM *S, ListNode *Vars)
{
    char *Tempstr=NULL;
    TID3v1_TAG *Tag;
    int result=FALSE;

    Tag=(TID3v1_TAG *) calloc(1,sizeof(TID3v1_TAG));

    STREAMReadBytes(S,(char *) Tag,sizeof(TID3v1_TAG));

    Tempstr=CopyStrLen(Tempstr,Tag->Artist,30);
    SetVar(Vars,"Media-Artist",Tempstr);
    Tempstr=CopyStrLen(Tempstr,Tag->Album,30);
    SetVar(Vars,"Media-Album",Tempstr);
    Tempstr=CopyStrLen(Tempstr,Tag->Title,30);
    SetVar(Vars,"Media-Title",Tempstr);
    Tempstr=CopyStrLen(Tempstr,Tag->Comment,30);
    SetVar(Vars,"Media-Comment",Tempstr);
    Tempstr=CopyStrLen(Tempstr,Tag->Year,4);
    SetVar(Vars,"Media-Year",Tempstr);

    result=TRUE;

    Destroy(Tempstr);
    free(Tag);

    return(result);
}


static int ConvertSyncsafeBytes(uint8_t Top, uint8_t High, uint8_t Low)
{
    return((Top * 65536) + (High * 256) + Low);
}


typedef enum {TAG_COMPOSER,TAG_ALBUM,TAG_TITLE,TAG_COMMENT,TAG_BPM,TAG_ARTIST,TAG_BAND,TAG_YEAR,TAG_LEN,TAG_GENRE,TAG_TRACK,TAG_WEBPAGE_COM,TAG_WEBPAGE_COPYRIGHT,TAG_WEBPAGE_AUDIOFILE, TAG_WEBPAGE_ARTIST, TAG_WEBPAGE_AUDIOSOURCE, TAG_WEBPAGE_STATION,TAG_WEBPAGE_PUBLISHER,TAG_USER_URL,TAG_IMAGE} TID3Tags;





/*
Picture type:  $00  Other
                  $01  32x32 pixels 'file icon' (PNG only)
                  $02  Other file icon
                  $03  Cover (front)
                  $04  Cover (back)
                  $05  Leaflet page
                  $06  Media (e.g. lable side of CD)
                  $07  Lead artist/lead performer/soloist
                  $08  Artist/performer
                  $09  Conductor
                  $0A  Band/Orchestra
                  $0B  Composer
                  $0C  Lyricist/text writer
                  $0D  Recording Location
                  $0E  During recording
                  $0F  During performance
                  $10  Movie/video screen capture
                  $11  A bright coloured fish
                  $12  Illustration
                  $13  Band/artist logotype
                  $14  Publisher/Studio logotype
*/

static void ID3v2ReadPicture(char *Data, int Len, ListNode *Vars)
{
    char *ptr, *imgtype;
    int offset;
    char *Tempstr=NULL, *Encoded=NULL;
    uint8_t Type;

    ptr=Data;

    //text encoding
    ptr++;

    if (strncmp(ptr,"JPG",3)==0) imgtype="image/jpeg";
    if (strncmp(ptr,"PNG",3)==0) imgtype="image/png";
    ptr+=3;

    //Image type, see above commented list
    Type=*ptr;
    ptr++;

    for (; *ptr != '\0'; ptr++) /*description string*/ ;
    ptr++;

    offset=ptr-Data;
    if (ptr && (Len < 8196))
    {
        Encoded=EncodeBytes(Encoded, ptr,Len-offset,ENCODE_BASE64);
        Tempstr=MCopyStr(Tempstr,"<img src='data:",imgtype,";base64,",Encoded,"'>",NULL);
        SetVar(Vars,"Thumbnail",Tempstr);
    }

    Destroy(Tempstr);
    Destroy(Encoded);
}


static int ID3v2ReadTag(STREAM *S, ListNode *Vars)
{
    char *Tempstr=NULL, *TagName=NULL, *ptr;
    uint8_t Version, Revision;
    uint32_t Len;
    int TagNameLen=3, result;

//Some of these don't exist, but are left as placeholders to match against TID3Tags
    const char *ID3v2Fields[]= {"TCM","TAL","TT2","COM","BPM","TP1","TP2","TYE","TLE","TCO","TRK","WCOM","WCP","WAF","WAR","WAS","WORS","WPB","WXX","PIC",NULL};

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
        if (result < 1) break;
        StrTrunc(TagName, result);

//Flags
        STREAMReadBytes(S,Tempstr,3);
        Len=ConvertSyncsafeBytes(Tempstr[0], Tempstr[1], Tempstr[2]);
        if (Len < 1) break;


        Tempstr=SetStrLen(Tempstr,Len);
        result=STREAMReadBytes(S,Tempstr,Len);

        if (result < 1) break;
        StrTrunc(Tempstr, result);

        if (result > 0)
        {
            result=MatchTokenFromList(TagName,ID3v2Fields,0);
            switch (result)
            {
            case TAG_ARTIST:
            case TAG_BAND:
            case TAG_COMPOSER:
                SetVar(Vars,"Media-Artist",Tempstr+1);
                break;
            case TAG_ALBUM:
                SetVar(Vars,"Media-Album",Tempstr+1);
                break;
            case TAG_TITLE:
                SetVar(Vars,"Media-Title",Tempstr+1);
                break;
            case TAG_COMMENT:
                SetVar(Vars,"Media-Comment",Tempstr+1);
                break;
            case TAG_BPM:
                SetVar(Vars,"Media-BPM",Tempstr+1);
                break;
            case TAG_YEAR:
                SetVar(Vars,"Media-Year",Tempstr+1);
                break;
            case TAG_GENRE:
                SetVar(Vars,"Media-Genre",Tempstr+1);
                break;
            case TAG_TRACK:
                SetVar(Vars,"Media-Track",Tempstr+1);
                break;
            case TAG_USER_URL:
                SetVar(Vars,"Media-AssociatedURL",Tempstr+1);
                break;
            case TAG_WEBPAGE_COM:
                SetVar(Vars,"Media-CommerialWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_COPYRIGHT:
                SetVar(Vars,"Media-Copyright/LegalWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_AUDIOFILE:
                SetVar(Vars,"Media-AudiofileWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_ARTIST:
                SetVar(Vars,"Media-ArtistWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_AUDIOSOURCE:
                SetVar(Vars,"Media-AudioSourceWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_STATION:
                SetVar(Vars,"Media-RadioStationWebpage",Tempstr+1);
                break;
            case TAG_WEBPAGE_PUBLISHER:
                SetVar(Vars,"Media-PublisherWebpage",Tempstr+1);
                break;

            case TAG_LEN:
                //convert from milliseconds
                Len=atoi(Tempstr) / 1000;
                Tempstr=FormatStr(Tempstr,"%d:%d",Len / 60, Len % 60);
                SetVar(Vars,"Media-Duration",Tempstr);
                break;

            case TAG_IMAGE:
                ID3v2ReadPicture(Tempstr, Len, Vars);
                break;
            }
        }

    }

    Destroy(TagName);
    Destroy(Tempstr);

    return(TRUE);
}



static int ID3v3ReadTag(STREAM *S, ListNode *Vars)
{
//WPUB	Publishers official webpage
    const char *ID3v3Fields[]= {"TCOM","TALB","TIT2","COMM","TBPM","TPE1","TPE2","TYER","TLEN","TCON","TRCK","WCOM","WCOP","WOAF","WOAR","WOAS","WORS","WPUB","WXXX",NULL};
    typedef enum {TAG_COMPOSER,TAG_ALBUM,TAG_TITLE,TAG_COMMENT,TAG_BPM,TAG_ARTIST,TAG_BAND,TAG_YEAR,TAG_LEN,TAG_GENRE,TAG_TRACK,TAG_WEBPAGE_COM,TAG_WEBPAGE_COPYRIGHT,TAG_WEBPAGE_AUDIOFILE, TAG_WEBPAGE_ARTIST, TAG_WEBPAGE_AUDIOSOURCE, TAG_WEBPAGE_STATION,TAG_WEBPAGE_PUBLISHER,TAG_USER_URL} TID3TagType;
    char *Tempstr=NULL, *TagName=NULL;
    uint8_t Version, Revision;
    int TagNameLen=4, len, result;
    TID3TagType TagType;


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
        if (result < 1) break;
        StrTrunc(TagName, result);

//Flags
        STREAMReadBytes(S,Tempstr,2);

        STREAMReadBytes(S,Tempstr,4);
//Data len, stored in a crazy 'syncsafe' format
        len=ConvertSyncsafeBytes(0, Tempstr[0], Tempstr[1]);
        if (len < 1) break;

//Encoding Byte, this counts as part of the data, so we read len-1
        STREAMReadBytes(S,Tempstr,1);

        Tempstr=SetStrLen(Tempstr,len);
        result=STREAMReadBytes(S,Tempstr,len-1);
        if (result < 1) break;
        StrTrunc(Tempstr, result);

        if (StrLen(Tempstr))
        {
            TagType=MatchTokenFromList(TagName,ID3v3Fields,0);
            switch (TagType)
            {
            case TAG_ARTIST:
            case TAG_BAND:
            case TAG_COMPOSER:
                SetVar(Vars,"Media-Artist",Tempstr);
                break;
            case TAG_ALBUM:
                SetVar(Vars,"Media-Album",Tempstr);
                break;
            case TAG_TITLE:
                SetVar(Vars,"Media-Title",Tempstr);
                break;
            case TAG_COMMENT:
                SetVar(Vars,"Media-Comment",Tempstr);
                break;
            case TAG_BPM:
                SetVar(Vars,"Media-BPM",Tempstr);
                break;
            case TAG_YEAR:
                SetVar(Vars,"Media-Year",Tempstr);
                break;
            case TAG_GENRE:
                SetVar(Vars,"Media-Genre",Tempstr);
                break;
            case TAG_TRACK:
                SetVar(Vars,"Media-AlbumTrackNumber",Tempstr);
                break;
            case TAG_USER_URL:
                SetVar(Vars,"Media-AssociatedURL",Tempstr);
                break;
            case TAG_WEBPAGE_COM:
                SetVar(Vars,"Media-CommerialWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_COPYRIGHT:
                SetVar(Vars,"Media-Copyright/LegalWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_AUDIOFILE:
                SetVar(Vars,"Media-AudiofileWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_ARTIST:
                SetVar(Vars,"Media-ArtistWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_AUDIOSOURCE:
                SetVar(Vars,"Media-AudioSourceWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_STATION:
                SetVar(Vars,"Media-RadioStationWebpage",Tempstr);
                break;
            case TAG_WEBPAGE_PUBLISHER:
                SetVar(Vars,"Media-PublisherWebpage",Tempstr);
                break;

            case TAG_LEN:
                //convert from milliseconds
                len=atoi(Tempstr) / 1000;
                Tempstr=FormatStr(Tempstr,"%d:%d",len / 60, len % 60);
                SetVar(Vars,"Media-Duration",Tempstr);
                break;

            }
        }

    }

    Destroy(TagName);
    Destroy(Tempstr);

    return(TRUE);
}





static int OggReadHeader(STREAM *S, uint8_t *SegTable)
{
    char *Tempstr=NULL;
    uint8_t NoOfSegments=0;

    Tempstr=SetStrLen(Tempstr,4096);
    memset(Tempstr,0,4096);
    STREAMReadBytes(S,Tempstr,4);

    if (strcmp(Tempstr,"OggS")==0)
    {
//Read ogg gubbins and throw it away
        STREAMReadBytes(S,Tempstr,22);
        STREAMReadBytes(S,(char *) &NoOfSegments,1);
        STREAMReadBytes(S,(char *) SegTable,NoOfSegments);
    }

    Destroy(Tempstr);

    return(NoOfSegments);
}



static int OggReadData(STREAM *S, char **Data)
{
    uint8_t *SegTable=NULL;
    uint8_t NoOfSegments;
    char *Tempstr=NULL, *ptr;
    int i, len=0, result;

    SegTable=(uint8_t *) calloc(1, 255);
    Tempstr=SetStrLen(Tempstr, 1024);

//Read segment header
    NoOfSegments=OggReadHeader(S, SegTable);

    for (i=0; i < NoOfSegments; i++)
    {
        memset(Tempstr,0,255);
        result=STREAMReadBytes(S, Tempstr, (int) SegTable[i]);
        *Data=SetStrLen(*Data, len + result);
        ptr=(*Data) +len;
        memcpy(ptr, Tempstr, result);
        len+=result;
    }

    Destroy(SegTable);
    Destroy(Tempstr);

    return(len);
}


static void OggInterpretComment(const char *Data, int MaxLen, ListNode *Vars)
{
    uint32_t flen, NoOfFields, i;
    char *Tempstr=NULL, *Name=NULL, *Token=NULL, *Value=NULL;
    const char *ptr, *end;

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
        if (StrValid(Tempstr) && (flen < 255) ) Tempstr=CatStr(Tempstr, "\n");

        Token=CopyStrLen(Token, ptr, flen);
        strrep(Token, '\n', ' ');
        Tempstr=CatStr(Tempstr, Token);

        ptr+=flen;
    }

    ptr=GetNameValuePair(Tempstr,"\n","=", &Name, &Value);
    while (ptr)
    {
        Token=MCopyStr(Token,"Media-",Name,NULL);
        SetVar(Vars, Token, Value);
        ptr=GetNameValuePair(ptr,"\n","=", &Name, &Value);
    }


    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Value);
    Destroy(Name);
}



static int OggReadTag(STREAM *S, ListNode *Vars)
{
    char *Data=NULL;
    int len;

    OggReadData(S,&Data);
    len=OggReadData(S,&Data);

    OggInterpretComment(Data, len, Vars);

    Destroy(Data);

    return(TRUE);
}



static int TIFFParseHeader(char *Data,int len, ListNode *Vars)
{
    char *ptr;
    int offset, NoOfTags;

    ptr=Data+4;

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

    return(NoOfTags);
}



static const char *JPEGParseAPP0(const char *Data, ListNode *Vars)
{
    const char *ptr;
    unsigned int len, x, y;
    char *Tempstr=NULL;

    ptr=Data;

//first two bytes are the length of this APP0 packet. But we don'tcare
    len=ntohs(* (uint16_t *) ptr);
    ptr+=2;
    if (memcmp(ptr,"JFIF\0",5)!=0) return(NULL);
    ptr+=5;

//next two are JFIF version
    ptr+=2;

//single byte that's 0==pixels, 1==pixels per inch 2==pixels per cm
    if (*ptr==0)
    {
        ptr++;

        x=(unsigned int) * (uint16_t *) ptr;
        ptr+=2;
        y=(unsigned int) * (uint16_t *) ptr;

        Tempstr=FormatStr(Tempstr,"%ux%u",x,y);
        SetVar(Vars,"Media-Resolution",Tempstr);
    }

    Destroy(Tempstr);

    return(Data+len);
}



static int JPEGReadHeader(STREAM *S, ListNode *Vars)
{
    char *Data=NULL;
    const char *ptr;
    int len;
#define READ_LEN 1024

    Data=SetStrLen(Data,READ_LEN);
    len=STREAMReadBytes(S,Data,READ_LEN);

    ptr=Data;
    if ((len==READ_LEN) && (memcmp(ptr,"\xFF\xD8",2)==0 ))
    {
        ptr+=2;
        if (memcmp(ptr,"\xFF\xE0",2)==0) ptr=JPEGParseAPP0(ptr+2, Vars);



        /*
        if (
        		(memcmp(ptr,"\xFF\xE1",2)==0) &&
        		(memcmp(ptr+4,"Exif\x00\x00",6)==0)
        	)
        	{
        		ptr+=10;
        		TIFFParseHeader(ptr,(Data+READ_LEN)-ptr, Vars);
        	}
        */

    }
    Destroy(Data);

    return(TRUE);
}



static int PNGReadHeader(STREAM *S, ListNode *Vars)
{
    char *Data=NULL, *Type=NULL;
    int val, w, l, d;

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
            case 0:
                Type=CopyStr(Type,"Greyscale ");
                break;
            case 2:
                Type=CopyStr(Type,"Truecolor");
                d=d*3;
                break;
            case 3:
                Type=CopyStr(Type,"IndexedColor ");
                d=d*3;
                break;
            case 4:
                Type=CopyStr(Type,"Greyscale+Alpha ");
                break;
            case 6:
                Type=CopyStr(Type,"Truecolor+Alpha ");
                d=d*3;
                break;
            }

            Data=FormatStr(Data,"PNG: Resolution: %dx%d Depth: %d Type: %s",w,l,d,Type);
            SetVar(Vars,"ImageDetails",Data);
        }
    }

    Destroy(Type);
    Destroy(Data);

    return(TRUE);
}


//BMP HEADER
/*
uint32_t size;
uint32_t Reserved;
uint32_t DataStart;
uint32_t BMISize;
uint32_t ImageWidth;
uint32_t ImageHeight;
uint16_t BitPlanes;
uint16_t BitCount;
uint32_t Compression;
uint32_t ImageSize;
uint32_t XPixPerMeter;
uint32_t YPixPerMeter;
uint32_t NoOfColors;
uint32_t NoOfImportantColors;
*/

static int BMPReadHeader(STREAM *S, ListNode *Vars)
{
    char *Data=NULL, *Tempstr=NULL;
    const char *ptr;
    int x, y, result;

    Data=SetStrLen(Data,255);
    result=STREAMReadBytes(S,Data,255);
    ptr=Data;

    ptr+=2; //'BM'
    ptr+=4; //32 bit file size
    ptr+=4; //32 bit 'reserved'
    ptr+=4; //32 bit image data offset
    ptr+=4; //32 bit image bmi size

    x=* (int32_t *) ptr;  //32 bit image width in pixels
    ptr+=4;
    y=* (int32_t *) ptr;  //32 bit image height in pixels

    Tempstr=FormatStr(Tempstr,"%ux%u",x,y);
    SetVar(Vars,"Media-Resolution",Tempstr);


    Destroy(Tempstr);
    return(TRUE);
}


static int MediaReadTagType(STREAM *S)
{
    char *Tempstr=NULL;
    int result=-1, i;

    Tempstr=SetStrLen(Tempstr,20);
    memset(Tempstr,0,20);
    STREAMReadBytes(S,Tempstr,20);

    for (i=0; TagTypes[i] !=NULL; i++)
    {
        if (memcmp(Tempstr, TagTypes[i], StrLen(TagTypes[i]))==0) result=i;
    }
    STREAMSeek(S,(double) 0, SEEK_SET);


    Destroy(Tempstr);

    return(result);
}




int MediaReadDetails(STREAM *S, ListNode *Vars)
{
    TTagType TagType=TAG_NONE;
    int result=0;

    TagType=MediaReadTagType(S);
    if (TagType==-1)
    {
        STREAMSeek(S,(double) 0 - ID3v1_LEN,SEEK_END);
        TagType=MediaReadTagType(S);
        if (TagType==TAG_ID3) TagType=TAG_ID3_END;
        else TagType=TAG_NONE;
    }

    switch (TagType)
    {
    case TAG_NONE:
        break;
    case TAG_ID3:
        result=ID3v1ReadTag(S,Vars);
        break;
    case TAG_ID3_END:
        STREAMSeek(S,(double) 0 - ID3v1_LEN,SEEK_END);
        result=ID3v1ReadTag(S,Vars);
        break;
    case TAG_ID3v2:
        result=ID3v2ReadTag(S,Vars);
        break;
    case TAG_ID3v3:
        result=ID3v3ReadTag(S,Vars);
        break;
    case TAG_ID3v4:
        result=ID3v3ReadTag(S,Vars);
        break;
    case TAG_OGG:
        result=OggReadTag(S,Vars);
        break;
    case TAG_JPEG:
        result=JPEGReadHeader(S,Vars);
        break;
    case TAG_BMP:
        result=BMPReadHeader(S,Vars);
        break;
//case TAG_PNG: result=PNGReadHeader(S,Vars); break;
//case TAG_TIFF: STREAMSeek(S,(double) 0, SEEK_SET); result=TIFFReadHeader(S,Vars); break;
    }

//Set us back to the start of the file
    STREAMSeek(S,(double) 0, SEEK_SET);

    return(result);
}


