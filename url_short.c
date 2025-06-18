#include "url_short.h"
#include "settings.h"
#include "server.h"

//none of these functions will be called
//if we are not using url shortener

#ifdef USE_URL_SHORTENER



char *URLShortFindInFile(char *URL, const char *Short, STREAM *S)
{
    char *Tempstr=NULL, *Found=NULL;
    const char *ptr;

    URL=CopyStr(URL, "");

    Tempstr=STREAMReadLine(Tempstr, S);
    while (Tempstr)
    {
        StripTrailingWhitespace(Tempstr);
        ptr=GetToken(Tempstr, "\\S", &Found, 0);
        if (strcmp(Found, Short)==0)
        {
            URL=CopyStr(URL, ptr);
            break;
        }
        Tempstr=STREAMReadLine(Tempstr, S);
    }

    Destroy(Tempstr);
    Destroy(Found);

    return(URL);
}


char *URLShortFind(char *URL, const char *Short, const char *Dir)
{
    char *Tempstr=NULL, *Found=NULL;
    STREAM *S;
    int val;

    URL=CopyStr(URL, "");

    val=fnv_hash(Short, 8192);
    Tempstr=FormatStr(Tempstr, "%s/%08d.urlshort", Dir, val);

    S=STREAMOpen(Tempstr, "r");
    if (S)
    {
        URL=URLShortFindInFile(URL, Short, S);
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Found);

    return(URL);
}




char *URLShortGet(char *Short, const char *Dir, const char *URL)
{
    char *Tempstr=NULL, *Hash=NULL;
    STREAM *S;
    unsigned int val;

    Tempstr=MCopyStr(Tempstr, Settings.URLTokenKey, ":", NULL);
    Tempstr=CatStr(Tempstr, URL);

    HashBytes(&Hash, "sha512", Tempstr, StrLen(Tempstr), ENCODE_PBASE64);
    StrTrunc(Hash, '=');
    Short=CopyStr(Short, Hash + StrLen(Hash) - 16);

    val=fnv_hash(Short, 8192);

    Tempstr=FormatStr(Tempstr, "%s/%08d.urlshort", Dir, val);
    MakeDirPath(Tempstr, 0700);

    S=STREAMOpen(Tempstr, "rwc");
    if (S)
    {
        STREAMSeek(S, 0, SEEK_END);
        Tempstr=MCopyStr(Tempstr, Short, " ", URL, "\n", NULL);
        STREAMWriteLine(Tempstr, S);
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Hash);

    return(Short);
}



int URLShortHandle(HTTPSession *Session)
{
    char *ShortnerURL=NULL, *ShortnerDir=NULL;
    char *Name=NULL, *Value=NULL, *Data=NULL;
    const char *ptr;
    int Act=SHORT_ACT_NONE;

    if (StrValid(Settings.URLShortner))
    {
        ptr=GetToken(Settings.URLShortner, ",", &ShortnerURL, 0);
        ShortnerDir=CopyStr(ShortnerDir, ptr);


        if (CompareStr(ShortnerURL, Session->URL)==0)
        {
            ptr=GetNameValuePair(Session->Arguments, "&", "=", &Name, &Value);
            while (ptr)
            {
                if (strcmp(Name, "u")==0)
                {
                    Act=SHORT_ACT_STORE;
                    Data=CopyStr(Data, Value);
                }
                else if (strcmp(Name, "s")==0)
                {
                    Act=SHORT_ACT_QUERY;
                    Data=CopyStr(Data, Value);
                }
                ptr=GetNameValuePair(ptr, "&", "=", &Name, &Value);
            }
        }



        if (Act==SHORT_ACT_STORE)
        {
            Value=URLShortGet(Value, ShortnerDir, Data);
            Name=MCopyStr(Name, ShortnerURL, "?s=", Value, NULL);
            Value=HTTPSessionFormatURL(Value, Session, Name);
            Data=HTTPUnQuote(Data, Value);

            AlayaServerSendResponse(Session->S, Session, "200 OKAY", "text/plain", Data);
        }
        else if (Act==SHORT_ACT_QUERY)
        {
            Value=URLShortFind(Value, Data, ShortnerDir);

            if (StrValid(Value)) Session->Path=HTTPUnQuote(Session->Path, Value);
            else Act=SHORT_ACT_NONE;
        }

    }

    Destroy(ShortnerURL);
    Destroy(ShortnerDir);
    Destroy(Name);
    Destroy(Value);
    Destroy(Data);

    return(Act);
}

#endif
