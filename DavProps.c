#include "DavProps.h"
#include "MimeType.h"
#include "server.h"
#include "FileProperties.h"

const char *Props[]= {"creationdate","displayname","getcontentlanguage","getcontentlength","getcontenttype","getetag","getctag","getlastmodified","lockdiscovery","resourcetype","source","supportedlock","iscollection","ishidden","isreadonly","executable",NULL};
typedef enum {PROP_CREATE_DATE,PROP_DISPLAY_NAME,PROP_CONTENT_LANG, PROP_CONTENT_SIZE, PROP_CONTENT_TYPE,PROP_ETAG,PROP_CTAG,PROP_LASTMODIFIED,PROP_LOCK_CHECK,PROP_RESOURCE_TYPE,PROP_SOURCE,PROP_SUPPORTEDLOCK, PROP_ISCOLLECTION,PROP_ISHIDDEN, PROP_ISREADONLY, PROP_EXECUTABLE} TDavProps;





void AddStandardProps(ListNode *PropList)
{
    int i;

    for (i=0; Props[i] !=NULL; i++) ListAddNamedItem(PropList,Props[i],NULL);
}


void TagSeparateNamespace(char *Tag, char **Namespace, char **Name)
{
    const char *ptr, *ptr2;

    if (Namespace) *Namespace=CopyStr(*Namespace,"");
    *Name=CopyStr(*Name,"");
    ptr=Tag;

//if the tag starts with a / then start the name with one too
    if (*ptr=='/')
    {
        *Name=AddCharToBuffer(*Name,0,'/');
        ptr++;
    }

    ptr2=strrchr(ptr,':');
    if (ptr2)
    {
        if (Namespace) *Namespace=CopyStrLen(*Namespace,ptr,ptr2-ptr);
        ptr2++;
    }
    else ptr2=ptr;

    *Name=CatStr(*Name,ptr2);

//if Tag has format getcontenttype/ then strip '/'
    StripDirectorySlash(*Name);
}


char *DavPropsGenerateEtag(char *RetStr, const char *Target)
{
    struct stat Stat;
    char *Tempstr=NULL;

    RetStr=CopyStr(RetStr, "");
    if (stat(Target, &Stat)==-1) return(RetStr);

    Tempstr=FormatStr(Tempstr, "%s:%lu:%lu", Target, Stat.st_mtime, Stat.st_size);
    HashBytes(&RetStr, "md5", Tempstr, StrLen(Tempstr), ENCODE_BASE64);

    Destroy(Tempstr);
    return(RetStr);
}


char *DavPropsMakePath(char *Path, const char *Target, const char *Property)
{
    struct stat Stat;
    char *Tempstr=NULL;
    const char *ptr;

    stat(Target, &Stat);
    if (S_ISDIR(Stat.st_mode))
    {
        Path=MCopyStr(Path, Target, "/.alaya/", Property, NULL);
        MakeDirPath(Path, 0770);
    }
    else
    {
        ptr=strrchr(Target, '/');
        Tempstr=CopyStrLen(Tempstr, Target, ptr-Target);
        Path=MCopyStr(Path, Tempstr, "/.alaya/", Property, NULL);
    }

    Destroy(Tempstr);

    return(Path);
}



char *DavPropsGet(char *RetStr, const char *Target, const char *Property)
{
    char *Path=NULL;
    int RetVal=FALSE;
    STREAM *S;

    RetStr=CopyStr(RetStr, "");
    Path=DavPropsMakePath(Path, Target, Property);
    S=STREAMOpen(Path, "r");
    if (S)
    {
        RetStr=STREAMReadLine(RetStr, S);
        STREAMClose(S);
    }

    return(RetStr);
}


int DavPropsStore(const char *Target, const char *Property, const char *Value)
{
    char *Path=NULL;
    int RetVal=FALSE;
    STREAM *S;

    Path=DavPropsMakePath(Path, Target, Property);

    S=STREAMOpen(Path, "w");
    if (S)
    {
        STREAMWriteLine(Value, S);
        RetVal=TRUE;
        STREAMClose(S);
    }

    return(RetVal);
}




int DavPropsIncr(const char *Target, const char *Property)
{
    char *Tempstr=NULL;
    int val;
    STREAM *S;

    Tempstr=DavPropsGet(Tempstr, Target, Property);
    val=atoi(Tempstr) +1;
    Tempstr=FormatStr(Tempstr, "%d", val);
    DavPropsStore(Target, Property, Tempstr);

    Destroy(Tempstr);
    return(TRUE);
}




const char *HTTPServerParseProp(const char *XML, char *PropName, ListNode *PropList)
{
    char *Tag=NULL, *Args=NULL;
    const char *ptr;


    if (! StrValid(PropName)) return(XML);
    if (*PropName=='/') return(XML);

//if PropName has format getcontenttype/ then strip '/'
    StripDirectorySlash(PropName);

    ptr=XMLGetTag(XML,NULL,&Tag,&Args);

//if the next thing is an XML tag, then 'rewind' and add a blank prop
    if (StrValid(Tag))
    {
        ptr=XML;
        Args=CopyStr(Args,"");
    }

    StripTrailingWhitespace(Args);
    ListAddNamedItem(PropList, PropName, CopyStr(NULL,Args));

    Destroy(Args);
    Destroy(Tag);

    return(ptr);
}



void HTTPServerReadProps(STREAM *S, HTTPSession *Heads, ListNode *PropList)
{
    char *XML=NULL, *Tag=NULL, *Args=NULL,  *NS=NULL, *Tempstr=NULL;
    const char *ptr;


    HTTPServerReadBody(Heads,  &XML);

    ptr=XMLGetTag(XML, &NS, &Tag, &Args);
    while (ptr)
    {
        LogToFile(Settings.LogPath, "OF TAG: %s ", Tag);
        if (strcasecmp(Tag, "prop")==0)
        {
            ptr=XMLGetTag(ptr, &NS, &Tag, &Args);
            while (ptr)
            {
                LogToFile(Settings.LogPath, "PF TAG: %s ", Tag);
                if (strcasecmp(Tag, "/prop")==0) break;
                if (strcasecmp(Tag, "/propfind")==0) break;

                ptr=HTTPServerParseProp(ptr, Tag, PropList);

                ptr=XMLGetTag(ptr, &NS, &Tag, &Args);
            }
        }
        else if (strcasecmp(Tag, "allprop")==0) AddStandardProps(PropList);

        ptr=XMLGetTag(ptr, &NS, &Tag, &Args);
    }


    Destroy(Tag);
    Destroy(Args);
    Destroy(NS);
    Destroy(XML);
}



char *HTTPServerPropFindItemPropsXML(char *InBuff, char *ItemName, int FileType, ListNode *PropList)
{
    ListNode *Curr;
    int result;
    char *RetStr=NULL, *ValBuff=NULL;


    RetStr=InBuff;
    Curr=ListGetNext(PropList);
    while (Curr)
    {
        result=MatchTokenFromList(Curr->Tag,Props,0);

        switch (result)
        {
        case PROP_CREATE_DATE:
//<D:creationdate xmlns:D="DAV:">2008-12-18T01-47-04-0800</D:creationdate>
            ValBuff=CopyStr(ValBuff,GetDateStrFromSecs("%Y-%m-%dT%H:%M:%SZ",atoi(Curr->Item),NULL));
            RetStr=MCatStr(RetStr,"<creationdate>",ValBuff,"</creationdate>\n",NULL);
            break;

        case PROP_DISPLAY_NAME:
            ValBuff=HTTPQuote(ValBuff,ItemName);
            RetStr=MCatStr(RetStr,"<displayname>",ValBuff,"</displayname>\n",NULL);
            break;

        case PROP_CONTENT_LANG:
            RetStr=CatStr(RetStr,"<getcontentlanguage />\n");
            break;

        case PROP_CONTENT_SIZE:
            RetStr=MCatStr(RetStr,"<getcontentlength>",Curr->Item,"</getcontentlength>\n",NULL);
            break;

        case PROP_CONTENT_TYPE:
            if (FileType==FILE_DIR) RetStr=MCatStr(RetStr,"<getcontenttype>httpd/unix-directory</getcontenttype>\n",NULL);
            else RetStr=MCatStr(RetStr,"<getcontenttype>",Curr->Item,"</getcontenttype>\n",NULL);
            break;


        case PROP_CTAG:
            ValBuff=DavPropsGet(ValBuff, ItemName, "ctag");
            if (StrValid(ValBuff)) RetStr=MCatStr(RetStr,"<getctag>", ValBuff, "</getctag>\n", NULL);
            else RetStr=CatStr(RetStr, "<getctag/>\n");
            break;

        case PROP_ETAG:
            ValBuff=DavPropsGenerateEtag(ValBuff, ItemName);
            RetStr=MCatStr(RetStr,"<getetag>", ValBuff, "</getetag>\n", NULL);
            break;

        case PROP_LASTMODIFIED:
            ValBuff=CopyStr(ValBuff,GetDateStrFromSecs("%a, %d %b %Y %H:%M:%S %Z",atoi(Curr->Item),NULL));
            RetStr=MCatStr(RetStr,"<getlastmodified>",ValBuff,"</getlastmodified>\n",NULL);
            break;

        case PROP_RESOURCE_TYPE:
            if (FileType==FILE_DIR) RetStr=CatStr(RetStr,"<resourcetype><collection/></resourcetype>\n");
            else RetStr=CatStr(RetStr,"<resourcetype />\n");
            break;

        case PROP_ISCOLLECTION:
            if (FileType==FILE_DIR) RetStr=CatStr(RetStr,"<iscollection>1</iscollection>\n");
            else RetStr=CatStr(RetStr,"<iscollection>0</iscollection>\n");
            break;


        case PROP_ISHIDDEN:
            RetStr=MCatStr(RetStr,"<ishidden>",Curr->Item,"</ishidden>\n",NULL);
            break;

        case PROP_ISREADONLY:
            RetStr=MCatStr(RetStr,"<isreadonly>",Curr->Item,"</isreadonly>\n",NULL);
            break;

        case PROP_EXECUTABLE:
            RetStr=MCatStr(RetStr,"<executable>",Curr->Item,"</executable>\n",NULL);
            break;



        case PROP_SOURCE:
            RetStr=CatStr(RetStr,"<source />\n");
            break;

//case PROP_SUPPORTEDLOCK:
//break;
//case PROP_LOCK_CHECK:
//break;


        default:
            if (StrValid(Curr->Item)) RetStr=MCatStr(RetStr,"<",Curr->Tag,">",Curr->Item,"</",Curr->Tag,">\n",NULL);
            else RetStr=MCatStr(RetStr,"<",Curr->Tag," />\n",NULL);

            break;
        }

        Curr=ListGetNext(Curr);
    }

    Destroy(ValBuff);

    return(RetStr);
}


char *HTTPServerPropFindItemXML(char *InBuff, HTTPSession *Heads, char *ItemPath, int FType, ListNode *PropList)
{
    char *RetStr=NULL, *URL=NULL;


    URL=FormatURL(URL,Heads,ItemPath);
//if (S_ISDIR(FileStat.st_mode)) URL=SlashTerminateDirectoryPath(URL);
    RetStr=MCatStr(InBuff,"<response>\n<href>",URL,"</href>\n<propstat>\n<prop>\n",NULL);

    RetStr=HTTPServerPropFindItemPropsXML(RetStr, ItemPath, FType, PropList);

    RetStr=CatStr(RetStr,"</prop>\n<status>HTTP/1.1 200 OK</status>\n</propstat>\n</response>\n");

    Destroy(URL);

    return(RetStr);
}



char *HTTPServerPropFindXML(char *InBuff, HTTPSession *Heads, ListNode *PropList)
{
    glob_t DirGlob;
    char *RetStr=NULL, *Tempstr=NULL;
    int i, FileType;
    ListNode *LocalPropList=NULL;

    RetStr=CopyStr(InBuff, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<multistatus xmlns=\"DAV:\">\n");


    FileType=LoadFileProperties(Heads->Path, PropList);

    if (FileType)
    {
        RetStr=HTTPServerPropFindItemXML(RetStr, Heads, Heads->Path, FileType, PropList);
        if ((Heads->Depth > 0) && (FileType==FILE_DIR))
        {
            if (* (Heads->Path + StrLen(Heads->Path) -1) != '/') Tempstr=MCatStr(Tempstr,Heads->Path,"/*",NULL);
            else Tempstr=MCatStr(Tempstr,Heads->Path,"*",NULL);

            glob(Tempstr,0,0,&DirGlob);
            for (i=0; i < DirGlob.gl_pathc; i++)
            {
                LocalPropList=ListCreate();
                CopyVars(LocalPropList,PropList);
                FileType=LoadFileProperties(DirGlob.gl_pathv[i], LocalPropList);
                RetStr=HTTPServerPropFindItemXML(RetStr, Heads, DirGlob.gl_pathv[i], FileType, LocalPropList);
                ListDestroy(LocalPropList,Destroy);
            }
            globfree(&DirGlob);
        }
    }
    else
    {

        Tempstr=FormatURL(Tempstr,Heads,Heads->Path);
        RetStr=MCatStr(RetStr,"<response><href>",Tempstr,"</href>\n<propstat>\n<prop>\n",NULL);
        RetStr=CatStr(RetStr,"</prop>\n<status>HTTP/1.1 404 Not Found</status>\n</propstat>\n</response>\n");

    }

    RetStr=CatStr(RetStr,"</multistatus>\n");


    Destroy(Tempstr);

    return(RetStr);
}



void HTTPServerPropFind(STREAM *S, HTTPSession *Heads)
{
    char *Tempstr=NULL, *XML=NULL;
    ListNode *PropList;


    LogToFile(Settings.LogPath,"PROPFIND: %s %d",Heads->Path, Heads->ContentSize);
    PropList=ListCreate();
    if (Heads->ContentSize > 0) HTTPServerReadProps(S, Heads, PropList);
    else
    {
        ListAddNamedItem(PropList,"displayname",NULL);
        ListAddNamedItem(PropList,"resourcetype",NULL);
        ListAddNamedItem(PropList,"getcontenttype",NULL);
        ListAddNamedItem(PropList,"getcontentlength",NULL);
        ListAddNamedItem(PropList,"getlastmodified",NULL);
    }

    XML=HTTPServerPropFindXML(XML,Heads,PropList);

    HTTPServerSendResponse(S, Heads, "207 OK","text/xml",XML);
    if (Settings.Flags & FLAG_LOG_MORE_VERBOSE) LogToFile(Settings.LogPath,"PROPFIND RESPONSE FOR %s\n%s",Heads->Path,XML);

    ListDestroy(PropList,Destroy);
    STREAMClose(S);

    Destroy(Tempstr);
    Destroy(XML);
}



void HTTPServerPropPatch(STREAM *S,HTTPSession *Heads)
{
    char *Tempstr=NULL, *XML=NULL;
    ListNode *PropList, *Curr;


    PropList=ListCreate();
    if (Heads->ContentSize > 0)
    {
        HTTPServerReadProps(S, Heads, PropList);
        SetProperties(Heads->Path, PropList);
        Curr=ListGetNext(PropList);
        while (Curr)
        {
            Curr=ListGetNext(Curr);
        }
    }

    XML=CopyStr(XML, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<multistatus xmlns=\"DAV:\">\n");
    Tempstr=FormatURL(Tempstr,Heads,Heads->Path);
    XML=MCatStr(XML,"<response>\n<href>",Tempstr,"</href>\n",NULL);

    Curr=ListGetNext(PropList);
    while (Curr)
    {
        XML=MCatStr(XML,"<propstat><prop>",Curr->Tag,"</prop><status>",(char *)Curr->Item,"</status></propstat>\n",NULL);

        Curr=ListGetNext(Curr);
    }

    XML=CatStr(XML,"</response></multistatus>\n");

    HTTPServerSendResponse(S, Heads, "207 OK","text/xml",XML);

    ListDestroy(PropList,Destroy);

    STREAMClose(S);
    Destroy(Tempstr);
    Destroy(XML);
}

void FakeFunc()
{
    CompressBytes(NULL,NULL,NULL, 0, 5);
}


