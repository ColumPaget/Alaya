#include "FileDetailsPage.h"
#include "directory_listing.h"
#include "server.h"
#include "common.h"
#include "MimeType.h"
#include "FileProperties.h"
#include "auth_access_token.h"


char *FormatFileProperties(char *HTML, HTTPSession *Session, int FType, const char *URL, const char *Path, ListNode *Vars, int Flags)
{
    ListNode *Curr;
    char *Tempstr=NULL, *Salt=NULL;
    const char *ptr;
    const char *IgnoreFields[]= {"FileSize","ContentType","CTime-Secs","MTime-Secs", "IsExecutable", "creationdate", "getlastmodified", "getcontentlength", "getcontenttype", "executable",NULL};


    if (Flags & FDETAILS_ACCESSTOKEN)
    {
        GenerateRandomBytes(&Salt,32,ENCODE_RBASE64);
        Tempstr=MakeAccessToken(Tempstr, Session->UserName, Settings.AccessTokenKey, Salt, Session->ClientIP, URL);
        HTML=MCatStr(HTML,"<tr bgcolor=#FFAAAA><td>Access Token</td><td colspan=2>",URL,"?AccessToken=",Tempstr,"</td></tr>",NULL);
    }

    if (Flags & FDETAILS_URLTOKEN)
    {
        GenerateRandomBytes(&Salt,32,ENCODE_RBASE64);
        Tempstr=MakeAccessToken(Tempstr, Session->UserName, Settings.URLTokenKey, Salt, "", URL);
        HTML=MCatStr(HTML,"<tr bgcolor=#FFAAAA><td>URL Token</td><td colspan=2>",URL,"?URLToken=",Tempstr,"</td></tr>",NULL);
    }

    if (FType != FILE_DIR)
    {
        ptr=GetVar(Vars,"FileSize");
        if (ptr) HTML=MCatStr(HTML,"<tr><td>Size</td><td colspan=2>", ToMetric(strtod(ptr, NULL),0), " - (",ptr," bytes)","</td></tr>",NULL);
    }

    ptr=GetVar(Vars,"MTime-Secs");
    if (ptr)
    {
        HTML=MCatStr(HTML,"<tr><td>Modify Time</td><td colspan=2>",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",atoi(ptr),Settings.Timezone),"</td></tr>",NULL);
    }

    ptr=GetVar(Vars,"CTime-Secs");
    if (ptr)
    {
        HTML=MCatStr(HTML,"<tr><td>Create Time</td><td colspan=2>",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",atoi(ptr),Settings.Timezone),"</td></tr>",NULL);
    }

    HTML=MCatStr(HTML,"<tr bgcolor=#CCFFCC><td>ContentType</td><td colspan=2>",GetVar(Vars,"ContentType"),"</td></tr>",NULL);

    if (FType != FILE_DIR)
    {
        Tempstr=CopyStr(Tempstr,"");
        //	HashFile(&Tempstr,"md5",Path,ENCODE_HEX);
        //	HTML=MCatStr(HTML,"<tr><td>MD5 Sum</td><td>",Tempstr,"</td></tr>",NULL);
    }


    Curr=ListGetNext(Vars);
    while (Curr)
    {
        if ((Curr->ItemType!=FILE_USER_VALUE)  && StrLen(Curr->Item) && (MatchTokenFromList(Curr->Tag,IgnoreFields,0)==-1))  HTML=MCatStr(HTML,"<tr bgcolor=#CCFFCC><td>",Curr->Tag,"</td><td colspan=2>",(char *) Curr->Item,"</td></tr>",NULL);
        Curr=ListGetNext(Curr);
    }

    Curr=ListGetNext(Vars);
    while (Curr)
    {
        if (Curr->ItemType==FILE_USER_VALUE)
        {
            HTML=MCatStr(HTML,"<tr bgcolor=#CCFFCC><td>",Curr->Tag,"</td><td>",(char *) Curr->Item,"</td><td><input type=submit name=\"editprop:",Curr->Tag,":",URL,"\" value=\"edit\"></tr>",NULL);
        }
        Curr=ListGetNext(Curr);
    }

    Destroy(Tempstr);
    Destroy(Salt);

    return(HTML);
}




//Path is the ACTUAL path to the item, not it's VPath or URL. Thus, use Session->URL
//unless accessing the actual file
void DirectoryItemEdit(STREAM *S, HTTPSession *Session, const char *Path, int Flags)
{
    char *HTML=NULL, *Tempstr=NULL, *URL=NULL, *Salt=NULL, *wptr;
    const char *ptr;
    ListNode *Vars;
    int FType;


    HTML=MCopyStr(HTML,"<html>\r\n<head><title>Editing ",Session->URL,"</title></head>\r\n<body>\r\n<form>\r\n",NULL);


    HTML=CatStr(HTML,"<table align=center width=90%% border=0>");

    Vars=ListCreate();
    FType=LoadFileProperties(Path, Vars);


//Parent Directory Link
    Tempstr=CopyStr(Tempstr, Session->Path);
    StrRTruncChar(Tempstr, '/');

    HTML=MCatStr(HTML,"<tr><td colspan=3><a href=\"",Tempstr,"\">.. (Parent Directory)</a></td><td> &nbsp; </td></tr>",NULL);


    HTML=MCatStr(HTML,"<tr bgcolor=#CCCCFF><td>Path</td><td colspan=2>",Session->URL,"</td></tr>",NULL);

    HTML=MCatStr(HTML,"<tr bgcolor=#FFCCCC><td>Actions</td><td colspan=2><input type=submit name='get:",Session->Path,"' value=Get /> <input type=submit name='del:",Session->Path,"' value=Del /> <input type=text name=renameto /><input type=submit name='renm:",Session->Path,"' value=Rename /><input type=submit name='genaccess:",Session->Path,"' value='Access Token'></td></tr>",NULL);

    URL=HTTPSessionFormatURL(URL,Session, Session->URL);
    HTML=FormatFileProperties(HTML, Session, FType, URL, Path, Vars, Flags);

    //We must use the URL that this file was asked under, not its directory path. The directory path may not be
    //directly accessible to the user, and they may be accessing it via a VPATH

    /* This feature not ready yet.
    if (0)
    {
    Tempstr=CopyStr(Tempstr,GetVar(Vars,"Comment"));
    HTML=MCatStr(HTML,"<tr><td>Comment</td><td><textarea rows=3 cols=40 name=fileproperty:comment>",Tempstr,"</textarea> <input type=submit name='sprops:",URL,"' value=change></td></tr>",NULL);
    }
    */



    HTML=CatStr(HTML,"</table>");
    HTML=CatStr(HTML,"</form></body></html>");

    AlayaServerSendResponse(S, Session, "200 OKAY", "text/html",HTML);

    Destroy(Tempstr);
    Destroy(Salt);
    Destroy(HTML);
    Destroy(URL);

    ListDestroy(Vars,Destroy);
}



void FileDetailsSaveProps(STREAM *S, HTTPSession *Session, const char *Path)
{
    char *QuotedName=NULL, *QuotedValue=NULL, *Name=NULL, *Value=NULL;
    const char *ptr;
    ListNode *Props;

    Props=ListCreate();
    ptr=GetNameValuePair(Session->Arguments,"&","=",&QuotedName,&QuotedValue);
    while (ptr)
    {
        Name=HTTPUnQuote(Name, QuotedName);
        Value=HTTPUnQuote(Value, QuotedValue);
        if (strncasecmp(Name,"fileproperty:",13)==0) SetVar(Props,Name+13,Value);
        ptr=GetNameValuePair(ptr,"&","=",&QuotedName,&QuotedValue);
    }

    SetProperties(Path, Props);


    ListDestroy(Props,Destroy);

    Destroy(QuotedName);
    Destroy(QuotedValue);
    Destroy(Value);
    Destroy(Name);
}
