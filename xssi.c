#include "xssi.h"

char *XSSIExec(char *RetStr, const char *TagType, const char *TagData)
{
    char *Name=NULL, *Value=NULL, *Tempstr=NULL;
    const char *ptr;
    STREAM *S;

    ptr=GetNameValuePair(TagData, "\\S", "=", &Name, &Value);
    while (ptr)
    {
        if (strcmp(Name, "cmd")==0)
        {
            Tempstr=MCopyStr(Tempstr, "cmd:",Value,NULL);
            S=STREAMOpen(Tempstr, "r");
            if (S)
            {
                Tempstr=STREAMReadDocument(Tempstr, S);
                RetStr=CatStr(RetStr, Tempstr);
                STREAMClose(S);
            }
        }

        if (strcmp(Name, "cgi")==0)
        {
            S=STREAMOpen(Value, "r");
            Tempstr=STREAMReadDocument(Tempstr, S);
            STREAMClose(S);
            RetStr=CatStr(RetStr, Tempstr);
        }

        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Tempstr);

    return(RetStr);
}


char *XSSIInclude(char *RetStr, const char *TagType, const char *TagData)
{
    char *Name=NULL, *Value=NULL, *Tempstr=NULL;
    const char *ptr;
    STREAM *S;

    ptr=GetNameValuePair(TagData, "\\S", "=", &Name, &Value);
    while (ptr)
    {
        //when chrooted file and virtual are the same, as the root directory is also the document root
        if (strcmp(Name, "file")==0)
        {
            S=STREAMOpen(Value, "r");
            if (S)
            {
                Tempstr=STREAMReadDocument(Tempstr, S);
                STREAMClose(S);
                RetStr=CatStr(RetStr, Tempstr);
                LogToFile(Settings.LogPath,"XSSI: [%s] ", RetStr);
            }
        }
        if (strcmp(Name, "virtual")==0)
        {
            S=STREAMOpen(Value, "r");
            if (S)
            {
                Tempstr=STREAMReadDocument(Tempstr, S);
                STREAMClose(S);
                RetStr=CatStr(RetStr, Tempstr);
            }
        }

        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Tempstr);

    return(RetStr);
}


char *XSSIEcho(char *RetStr, const char *TagType, const char *TagData)
{
    char *Name=NULL, *Value=NULL, *Tempstr=NULL;
    const char *ptr;

    ptr=GetNameValuePair(TagData, "\\S", "=", &Name, &Value);
    while (ptr)
    {
        if (strcmp(Name, "var")==0)
        {
            Tempstr=getenv(Value);
            RetStr=CatStr(RetStr, Tempstr);
        }
        ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
    }

    Destroy(Name);
    Destroy(Value);
    Destroy(Tempstr);

    return(RetStr);
}



char *XSSITag(char *RetStr, const char *TagType, const char *TagData)
{
    if (strcmp(TagType,"#include")==0) RetStr=XSSIInclude(RetStr, TagType, TagData);
    else if (strcmp(TagType,"#exec")==0) RetStr=XSSIExec(RetStr, TagType, TagData);
    else if (strcmp(TagType,"#echo")==0) RetStr=XSSIEcho(RetStr, TagType, TagData);

    return(RetStr);
}

char *XSSIDocument(char *RetStr, const char *Document)
{
    char *TagType=NULL, *Namespace=NULL, *TagData=NULL;
    const char *ptr;

    ptr=XMLGetTag(Document, &Namespace, &TagType, &TagData);
    while (ptr)
    {
        if (strncmp(TagType, "!--",3)==0) RetStr=XSSITag(RetStr, TagType+3, TagData);
        else if (StrValid(Namespace)) RetStr=MCatStr(RetStr, "<",Namespace,":",TagType," ",TagData,">",NULL);
        else if (StrValid(TagType)) RetStr=MCatStr(RetStr, "<",TagType," ",TagData,">",NULL);
        else RetStr=MCatStr(RetStr, TagData);

        ptr=XMLGetTag(ptr, &Namespace, &TagType, &TagData);
    }

    DestroyString(Namespace);
    DestroyString(TagType);
    DestroyString(TagData);

    return(RetStr);
}
