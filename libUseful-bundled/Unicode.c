#include "Unicode.h"
#include "FileSystem.h"
#include "StringList.h"

static int GlobalUnicodeLevel=0;
static ListNode *UnicodeNamesCache=NULL;

void UnicodeSetUTF8(int level)
{
    GlobalUnicodeLevel=level;
}


char *UnicodeEncodeChar(char *RetStr, int UnicodeLevel, int Code)
{
    char *Tempstr=NULL;

    if ((Code==0) || (UnicodeLevel == 0)) return(AddCharToStr(RetStr, '?'));

    if (Code < 0x800)
    {
        Tempstr=FormatStr(Tempstr,"%c%c",128+64+((Code & 1984) >> 6), 128 + (Code & 63));
    }
    else if (Code < 0x10000)
    {
        Tempstr=CopyStr(Tempstr, "?");
        if ((UnicodeLevel > 1) && (Code < 0x10000)) Tempstr=FormatStr(Tempstr,"%c%c%c", (Code >> 12) | 224, ((Code >> 6) & 63) | 128, (Code & 63) | 128);
    }
    else
    {
        Tempstr=CopyStr(Tempstr, "?");
        if ((UnicodeLevel > 2) && (Code < 0x110000)) Tempstr=FormatStr(Tempstr,"%c%c%c%c", (Code >> 18) | 240, ((Code >> 12) & 63) | 128, ((Code >> 6) & 63) | 128, (Code & 63) | 128);
    }

    RetStr=CatStr(RetStr,Tempstr);
    DestroyString(Tempstr);

    return(RetStr);
}


char *UnicodeStr(char *RetStr, int Code)
{
    return(UnicodeEncodeChar(RetStr, GlobalUnicodeLevel, Code));
}



char *BufferAddUnicodeChar(char *RetStr, unsigned int len, unsigned int uchar)
{
    switch (uchar)
    {
    //non-breaking space
    case 0x00a0:
        RetStr=AddCharToBuffer(RetStr, len, ' ');
        break;


    //en-dash and em-dash
    case 0x2010:
    case 0x2011:
    case 0x2012:
    case 0x2013:
    case 0x2014:
    case 0x2015:
        RetStr=AddCharToBuffer(RetStr, len, '-');
        break;

    //2019 is apostrophe in unicode. presumably it gives you as special, pretty apostrophe, but it causes hell with
    //straight ansi terminals, so we remap it here
    case 0x2018:
    case 0x2019:
        RetStr=AddCharToBuffer(RetStr, len, '\'');
        break;


    case 0x201a:
        RetStr=AddCharToBuffer(RetStr, len, ',');
        break;


    case 0x201b:
        RetStr=AddCharToBuffer(RetStr, len, '`');
        break;


    //left and right double quote. We simplify down to just double quote
    case 0x201c:
    case 0x201d:
    case 0x201e:
        RetStr=AddCharToBuffer(RetStr, len, '"');
        break;

    case 0x2024:
        RetStr=AddCharToBuffer(RetStr, len, '.');
        break;

    case 0x2039:
        RetStr=AddCharToBuffer(RetStr, len, '<');
        break;

    case 0x203A:
        RetStr=AddCharToBuffer(RetStr, len, '>');
        break;

    case 0x2044:
        RetStr=AddCharToBuffer(RetStr, len, '/');
        break;

    case 0x204e:
    case 0x2055:
        RetStr=AddCharToBuffer(RetStr, len, '*');
        break;

    default:
        if (uchar < 127) RetStr=AddCharToBuffer(RetStr, len,  uchar);
        else RetStr=UnicodeStr(RetStr, uchar);
        break;
    }

    return(RetStr);
}



char *StrAddUnicodeChar(char *RetStr, int uchar)
{
    int len;

    len=StrLen(RetStr);
    RetStr=(BufferAddUnicodeChar(RetStr, len, uchar));
    StrLenCacheAdd(RetStr, len + 1);

    return(RetStr);
}

unsigned int UnicodeDecode(const char **ptr)
{
    unsigned int val=0;

//unicode bit pattern 110
    if (((**ptr) & 224) == 192)
    {
        val=((**ptr) & 31) << 6;
        if (ptr_incr(ptr, 1) != 1) return(0);
        val |= (**ptr) & 127;
    }
    else if (((**ptr) & 224) == 224)
    {
        val=((**ptr) & 31) << 12;
        if (ptr_incr(ptr, 1) != 1) return(0);
        val |= ((**ptr) & 31) << 6;
        if (ptr_incr(ptr, 1) != 1) return(0);
        val |= (**ptr) & 127;
    }
    else
    {
        val=(unsigned int) **ptr;
    }

    ptr_incr(ptr, 1);

    return(val);
}



int UnicodeStrFromCache(char **RetStr, const char *Name)
{
    ListNode *Node;
    long code;

    Node=ListFindNamedItem(UnicodeNamesCache, Name);
    if (Node)
    {
        code=strtol((const char *) Node->Item, NULL, 16);
        *RetStr=UnicodeStr(*RetStr, code);
        return(TRUE);
    }

    return(FALSE);
}

static STREAM *UnicodeNamesFileOpen(const char *FName, const char *EnvVarName, const char *LibUsefulVar)
{
    char *Tempstr=NULL;
    STREAM *S=NULL;

    if (StrValid(LibUsefulVar)) Tempstr=CopyStr(Tempstr, LibUsefulGetValue(LibUsefulVar));
    if ( (! StrValid(Tempstr)) && (StrValid(EnvVarName)) ) Tempstr=CopyStr(Tempstr, getenv(EnvVarName));

    if (! StrValid(Tempstr)) Tempstr=MCopyStr(Tempstr, SYSCONFDIR,  "/", FName, NULL);
    if (access(Tempstr, R_OK) !=0) Tempstr=FindFileInPrefixSubDirectory(Tempstr, getenv("PATH"), "/etc/", FName);

    S=STREAMOpen(Tempstr, "r");

    Destroy(Tempstr);
    return(S);
}


int UnicodeNamesInCache(const char *Names)
{
    char *Name=NULL;
    const char *ptr;
    int result=TRUE;

    ptr=GetToken(Names, ",", &Name, 0);
    while (ptr)
    {
        if (! ListFindNamedItem(UnicodeNamesCache, Name))
        {
            result=FALSE;
            break;
        }
        ptr=GetToken(ptr, ",", &Name, 0);
    }

    Destroy(Name);

    return(result);
}



int UnicodeNameCachePreloadFromFile(const char *FName, const char *EnvVarName, const char *LibUsefulVar, const char *Names)
{
    char *Name=NULL, *Tempstr=NULL;
    const char *ptr;
    int RetVal=FALSE;
    STREAM *S;


    S=UnicodeNamesFileOpen(FName, EnvVarName, LibUsefulVar);
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr, S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            ptr=GetToken(Tempstr, "\\S|,", &Name, GETTOKEN_MULTI_SEP);

            if (StrValid(Name) && InStringList(Name, Names, ","))
            {
                if (! UnicodeNamesCache) UnicodeNamesCache=ListCreate();
                SetVar(UnicodeNamesCache, Name, ptr);
            }
            Tempstr=STREAMReadLine(Tempstr, S);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Name);

    return(RetVal);
}



int UnicodeNameCachePreload(const char *Names)
{
if (GlobalUnicodeLevel == 0) return(FALSE);

if (UnicodeNamesInCache(Names)) return(TRUE);
if (UnicodeNameCachePreloadFromFile("unicode-names.conf", "UNICODE_NAMES_FILE", "Unicode:NamesFile", Names)) return(TRUE);
if (UnicodeNamesInCache(Names)) return(TRUE);
if (GlobalUnicodeLevel > 8)
{
if (UnicodeNameCachePreloadFromFile("nerdfont.csv.txt", "NERDFONTS_NAMES_FILE", "NerdFonts:NamesFile", Names)) return(TRUE);
if (UnicodeNameCachePreloadFromFile("nerdfont.csv", NULL, NULL, Names)) return(TRUE);
if (UnicodeNameCachePreloadFromFile("nerdfont.txt", NULL, NULL, Names)) return(TRUE);
}

return(FALSE);
}



int UnicodeNameCachePreloadFromTerminalStr(const char *String)
{
    char *Names=NULL, *Name=NULL;
    const char *ptr;
    int result;

    for (ptr=String; *ptr != '\0'; ptr++)
    {
        if (*ptr=='~')
        {
            ptr++;
            if (*ptr==':')
            {
		//using GETTOKEN_INCLUDE_SEP means the ':' is included in the list of tokens
		//so when we call GetToken here, the ptr it returns isn't past the closing ':'
		//it's right on it. ptr++ in the for statment then moves us past this token
                ptr=GetToken(ptr+1, ":", &Name, GETTOKEN_INCLUDE_SEP);
                Names=StringListAdd(Names, Name, ",");
            }

        }
    }

    result=UnicodeNameCachePreload(Names);

    Destroy(Names);
    Destroy(Name);

    return(result);
}




char *UnicodeStrFromNameAtLevel(char *RetStr, int UnicodeLevel, const char *Name)
{
    if (UnicodeStrFromCache(&RetStr, Name)) return(RetStr);
    UnicodeNameCachePreload(Name);

    UnicodeStrFromCache(&RetStr, Name);
    return(RetStr);
}



char *UnicodeStrFromName(char *RetStr, const char *Name)
{
    return(UnicodeStrFromNameAtLevel(RetStr, GlobalUnicodeLevel, Name));
}
