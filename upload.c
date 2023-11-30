#include "upload.h"
#include "server.h"
#include "Events.h"

#define UPLOAD_FAILED -1
#define UPLOAD_DONE 1
#define UPLOAD_UNPACK 2

int UploadReadMultipartHeaders(STREAM *S, char **Field, char **FileName)
{
    char *Tempstr=NULL, *Name=NULL, *Value=NULL;
    const char *ptr;
    int result=FALSE;

    Tempstr=STREAMReadLine(Tempstr,S);
    while (StrValid(Tempstr))
    {
        StripTrailingWhitespace(Tempstr);
        ptr=GetToken(Tempstr,":",&Name,0);

        if (strcasecmp(Name,"Content-Disposition")==0)
        {
            ptr=GetNameValuePair(ptr,";","=",&Name,&Value);
            while (ptr)
            {
                StripLeadingWhitespace(Name);
                StripTrailingWhitespace(Name);
                StripLeadingWhitespace(Value);
                StripTrailingWhitespace(Value);
                if (strcasecmp(Name,"name")==0)
                {
                    *Field=CopyStr(*Field,Value);
                    result=TRUE;
                }

                if (strcasecmp(Name,"filename")==0)
                {
                    *FileName=CopyStr(*FileName,Value);
                    result=TRUE;
                }
                ptr=GetNameValuePair(ptr,";","=",&Name,&Value);
            }
        }
        Tempstr=STREAMReadLine(Tempstr,S);
        StripTrailingWhitespace(Tempstr);
    }

    Destroy(Tempstr);
    Destroy(Name);
    Destroy(Value);

    return(result);
}


int MultipartReadFile(STREAM *S, const char *FName, const char *Boundary, int BoundaryLen)
{
    char *Tempstr=NULL;
    const char *ptr;
    int result, RetVal=FALSE;
    STREAM *FOut=NULL;
    off_t fsize;

    FOut=STREAMFileOpen(FName,SF_CREAT | SF_TRUNC | SF_WRONLY);
    if (! FOut) return(UPLOAD_FAILED);
    STREAMLock(FOut, LOCK_EX);

    Tempstr=SetStrLen(Tempstr,4096);
    result=STREAMReadBytesToTerm(S, Tempstr, 4096, '\n');
    while (result > -1)
    {
        if ( (result < (BoundaryLen + 6)) && (strncmp(Tempstr,Boundary,BoundaryLen)==0))
        {
            //As we read to a '\n' we may have left its '\r' partner attached to
            //the end of the data
            ptr=Tempstr+result-2;
            if (strcmp(ptr,"\r\n")==0) result-=2;
            if ((result >= BoundaryLen) && (strncmp(Tempstr+BoundaryLen,"--\r\n",4)==0))
            {
                //must remove '\r\n' from end of file (it's the start of the boundary)
                RetVal=UPLOAD_DONE;
            }
            break;
        }
        else if (FOut) STREAMWriteBytes(FOut,Tempstr,result);
        result=STREAMReadBytesToTerm(S, Tempstr, 4096, '\n');
    }

//If we read to a boundary then there will always be a \r\n on the end of the file,
    fsize=(off_t) STREAMTell(FOut);
    if (fsize > 0) ftruncate(FOut->out_fd,fsize-2);

    STREAMClose(FOut);

    if (result==-1) RetVal=UPLOAD_DONE;

    Destroy(Tempstr);

    return(RetVal);
}


int UploadMultipartPost(STREAM *S, HTTPSession *Session)
{
    char *Tempstr=NULL, *Name=NULL, *FileName=NULL, *QName=NULL, *QValue=NULL, *Boundary=NULL;
    const char *ptr;
    int blen=0, UploadResult=FALSE;

//if (! (Session->Flags & SESSION_ALLOW_UPLOAD)) return;
    Boundary=MCopyStr(Boundary,"--",Session->ContentBoundary, NULL);
    blen=StrLen(Boundary);

    LogToFile(Settings.LogPath,"HANDLE UPLOAD: %s %s %d",Session->URL, Boundary, Session->ContentSize);
    Tempstr=STREAMReadLine(Tempstr,S);
    while (Tempstr)
    {
        StripTrailingWhitespace(Tempstr);
        if ((blen > 0) && (strncmp(Tempstr,Boundary,blen)==0))
        {
            //Check for end boundary
            if (strcmp(Tempstr+blen,"--")==0) break;

            if (UploadReadMultipartHeaders(S, &Name, &FileName))
            {
                if (StrValid(FileName))
                {
                    //this dance is solely to prevent creating double or triple '/' in the path
                    Tempstr=CopyStr(Tempstr, "/");
                    ptr=Session->StartDir;
                    while (*ptr=='/') ptr++;
                    Tempstr=CatStr(Tempstr, ptr);
                    Tempstr=SlashTerminateDirectoryPath(Tempstr);
                    ptr=Session->Path;
                    while (*ptr=='/') ptr++;
                    Tempstr=CatStr(Tempstr, ptr);
                    Tempstr=SlashTerminateDirectoryPath(Tempstr);
                    Tempstr=CatStr(Tempstr, FileName);

                    UploadResult=MultipartReadFile(S, Tempstr, Boundary, blen);
                    Session->Path=CopyStr(Session->Path, Tempstr);
                    if ((UploadResult==UPLOAD_DONE) || (UploadResult==UPLOAD_FAILED)) break;
                    else
                    {
                        //we must have found a content boundary in ReadMultipartHeaders,
                        //so don't read another line, deal with the content boundary
                        Tempstr=CopyStr(Tempstr, Boundary);
                        continue;
                    }
                }
                else if (StrValid(Name))
                {
                    Tempstr=STREAMReadLine(Tempstr,S);
                    StripTrailingWhitespace(Tempstr);
                    QName=HTTPQuote(QName,Name);
                    QValue=HTTPQuote(QValue,Tempstr);
                    Session->Arguments=MCatStr(Session->Arguments,"&",QName,"=",QValue,NULL);
                }
            }
        }

        Tempstr=STREAMReadLine(Tempstr,S);
    }

//Protect final argument for broken CGI implementations that read all
//data without regard to 'ContentSize'
    Session->Arguments=CatStr(Session->Arguments,"&");
    Session->ContentSize=StrLen(Session->Arguments);
    if (Session->ContentSize > 0) Session->ContentType=CopyStr(Session->ContentType,"application/x-www-form-urlencoded");



    Destroy(Boundary);
    Destroy(FileName);
    Destroy(Tempstr);
    Destroy(Name);
    Destroy(QName);
    Destroy(QValue);

    if (UploadResult==UPLOAD_DONE)
    {
        Session->Flags |= SESSION_UPLOAD_DONE;
        ProcessSessionEventTriggers(Session);
        return(TRUE);
    }

    return(FALSE);
}


void UploadSelectPage(STREAM *S, HTTPSession *Session, const char *Path)
{
    char *HTML=NULL, *Tempstr=NULL;
    int i;

    HTML=MCopyStr(HTML,"<html>\r\n<head><title>Upload files to: ",Session->URL,"</title></head>\r\n<body><form method=\"post\" enctype=\"multipart/form-data\" action=\"",Session->URL,"\">\r\n",NULL);

    HTML=MCatStr(HTML,"<p align=center>Upload files to: ",Session->URL,"</p>\r\n",NULL);
    HTML=CatStr(HTML,"<table align=center border=0><tr><th bgcolor=#AAAAFF>Select files for upload</th></tr>\r\n");
    for (i=0; i < 10; i++)
    {
        Tempstr=FormatStr(Tempstr,"<tr><td><input multiple type=file name=uploadfile:%d></td></tr>\r\n",i);
        HTML=CatStr(HTML,Tempstr);
    }
    HTML=MCatStr(HTML,"<tr><td><input type=submit value=Upload></td></tr></table>\r\n",NULL);

    HTML=MCatStr(HTML,"</form></body></html>\r\n",NULL);

    AlayaServerSendResponse(S, Session, "200 OK","text/html",HTML);

    Destroy(HTML);
    Destroy(Tempstr);
}


