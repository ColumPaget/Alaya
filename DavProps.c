#include "DavProps.h"
#include "MimeType.h"
#include "server.h"
#include "FileProperties.h"

const char *Props[]={"creationdate","displayname","getcontentlanguage","getcontentlength","getcontenttype","getetag","getlastmodified","lockdiscovery","resourcetype","source","supportedlock","iscollection","ishidden","isreadonly","executable",NULL};
typedef enum {PROP_CREATE_DATE,PROP_DISPLAY_NAME,PROP_CONTENT_LANG, PROP_CONTENT_SIZE, PROP_CONTENT_TYPE,PROP_ETAG,PROP_LASTMODIFIED,PROP_LOCK_CHECK,PROP_RESOURCE_TYPE,PROP_SOURCE,PROP_SUPPORTEDLOCK, PROP_ISCOLLECTION,PROP_ISHIDDEN, PROP_ISREADONLY, PROP_EXECUTABLE} TDavProps;





void AddStandardProps(ListNode *PropList)
{
int i;

for (i=0; Props[i] !=NULL; i++) ListAddNamedItem(PropList,Props[i],NULL);
}


void TagSeparateNamespace(char *Tag, char **Namespace, char **Name)
{
char *ptr, *ptr2;

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


char *HTTPServerParseProp(char *XML, char *PropName, ListNode *PropList)
{
char *ptr;
char *Tag=NULL, *Args=NULL;


if (! StrLen(PropName)) return(XML);
if (*PropName=='/') return(XML);

//if PropName has format getcontenttype/ then strip '/'
StripDirectorySlash(PropName);

ptr=HtmlGetTag(XML,&Tag,&Args);

//if the next thing is an XML tag, then 'rewind' and add a blank prop
if (StrLen(Tag)!=0)
{
	ptr=XML;
	Args=CopyStr(Args,"");
}

StripTrailingWhitespace(Args);
ListAddNamedItem(PropList, PropName, CopyStr(NULL,Args));

DestroyString(Args);
DestroyString(Tag);

return(ptr);
}



void HTTPServerReadProps(STREAM *S, HTTPSession *Heads, ListNode *PropList)
{
char *XML=NULL, *Tag=NULL, *Args=NULL,  *Data=NULL, *Tempstr=NULL;
char *ptr;


if (Heads->ContentSize > 0) 
{
XML=SetStrLen(XML,Heads->ContentSize+10);
STREAMReadBytes(S,XML,Heads->ContentSize);
}
else
{
	Tempstr=STREAMReadLine(Tempstr,S);

	while (Tempstr)
	{
		XML=CatStr(XML,Tempstr);
		Tempstr=STREAMReadLine(Tempstr,S);
	}

}


ptr=HtmlGetTag(XML,&Tempstr,&Args);
while (ptr)
{
TagSeparateNamespace(Tempstr, NULL, &Tag);

if (strcasecmp(Tag,"prop")==0)
{
	ptr=HtmlGetTag(ptr,&Tempstr,&Args);
	while (ptr)
	{
		TagSeparateNamespace(Tempstr, NULL, &Tag);
		if (strcasecmp(Tag,"/prop")==0) break;
		if (strcasecmp(Tag,"/propfind")==0) break;
		
		ptr=HTTPServerParseProp(ptr,Tag,PropList);

		ptr=HtmlGetTag(ptr,&Tempstr,&Args);
	}
}
else if (strcasecmp(Tag,"allprop")==0) AddStandardProps(PropList);

ptr=HtmlGetTag(ptr,&Tempstr,&Args);
}


DestroyString(Tag);
DestroyString(Args);
DestroyString(Data);
DestroyString(XML);
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

case PROP_ETAG:
RetStr=CatStr(RetStr,"<getetag />\n");
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
if (StrLen(Curr->Item)) RetStr=MCatStr(RetStr,"<",Curr->Tag,">",Curr->Item,"</",Curr->Tag,">\n",NULL);
else RetStr=MCatStr(RetStr,"<",Curr->Tag," />\n",NULL);

break;
}

Curr=ListGetNext(Curr);
}

DestroyString(ValBuff);

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

DestroyString(URL);

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
			ListDestroy(LocalPropList,DestroyString);
		}
		globfree(&DirGlob);
	}
}
else 
{
	
	Tempstr=FormatURL(Tempstr,Heads,Heads->Path);
	RetStr=MCatStr(RetStr,"<href>",Tempstr,"</href>\n<propstat>\n<prop>\n",NULL);
	RetStr=CatStr(RetStr,"</prop>\n<status>HTTP/1.1 404 Not Found</status>\n</propstat>\n<response>\n");

}

RetStr=CatStr(RetStr,"</multistatus>\n");


DestroyString(Tempstr);

return(RetStr);
}



void HTTPServerPropFind(STREAM *S,HTTPSession *Heads)
{
char *Tempstr=NULL, *XML=NULL;
ListNode *PropList;


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


ListDestroy(PropList,DestroyString);
STREAMClose(S);

DestroyString(Tempstr);
DestroyString(XML);
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

ListDestroy(PropList,DestroyString);

STREAMClose(S);
DestroyString(Tempstr);
DestroyString(XML);
}

void FakeFunc()
{
CompressBytes(NULL,NULL,NULL, 0, 5);
}


