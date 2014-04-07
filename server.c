#include "server.h"
#include "Authenticate.h"
#include "MimeType.h"
#include "DavProps.h"
#include "directory_listing.h"
#include "ID3.h"
#include "upload.h"
#include "proxy.h"

char *HTTPMethods[]={"HEAD","GET","POST","PUT","DELETE","MKCOL","PROPFIND","PROPPATCH","MOVE","COPY","OPTIONS","CONNECT",NULL};

char *HeaderStrings[]={"Authorization","Proxy-Authorization","Host","Destination","Content-Type","Content-Length","Depth","Overwrite","User-Agent","Cookie","If-Modified-Since","Accept-Encoding","Icy-MetaData","Referer",NULL};
typedef enum {HEAD_AUTH, HEAD_PROXYAUTH, HEAD_HOST, HEAD_DEST, HEAD_CONTENT_TYPE, HEAD_CONTENT_LENGTH, HEAD_DEPTH, HEAD_OVERWRITE, HEAD_AGENT, HEAD_COOKIE, HEAD_IFMOD_SINCE, HEAD_ACCEPT_ENCODING, HEAD_ICECAST,HEAD_REFERER} THeaders;



char *HTMLQuote(char *RetBuff, char *Str)
{
char *RetStr=NULL, *Token=NULL, *ptr;
int olen=0, ilen;

RetStr=CopyStr(RetStr,"");
ilen=StrLen(Str);

for (ptr=Str; ptr < (Str+ilen); ptr++)
{

switch (*ptr)
{
case '&': RetStr=CatStr(RetStr,"&amp;");
case '<': RetStr=CatStr(RetStr,"&lt;");
case '>': RetStr=CatStr(RetStr,"&gt;");

default:
		 RetStr=AddCharToStr(RetStr,*ptr); 
break; 
}

}

DestroyString(Token);
return(RetStr);
}





HTTPSession *HTTPSessionCreate()
{
HTTPSession *Session;

Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

//Must set all these to "" otherwise nulls can cause trouble later
Session->Protocol=CopyStr(Session->Protocol,"HTTP/1.1");
Session->ServerName=CopyStr(Session->ServerName,"");
Session->UserAgent=CopyStr(Session->UserAgent,"");
Session->UserName=CopyStr(Session->UserName,"");
Session->ContentType=CopyStr(Session->ContentType,"");
Session->Host=CopyStr(Session->Host,"");
Session->Path=CopyStr(Session->Path,"");
Session->Arguments=CopyStr(Session->Arguments,"");
Session->ClientHost=CopyStr(Session->ClientHost,"");
Session->ClientIP=CopyStr(Session->ClientIP,"");
Session->ClientReferrer=CopyStr(Session->ClientReferrer,"");
Session->StartDir=CopyStr(Session->StartDir,"");
Session->Depth=1;
Session->Headers=ListCreate();

return(Session);
}

void DestroyHTTPSession(void *p_Trans)
{
HTTPSession *Trans;

if (! p_Trans) return;
Trans=(HTTPSession *) p_Trans;

DestroyString(Trans->Protocol);
DestroyString(Trans->Method);
DestroyString(Trans->ResponseCode);
DestroyString(Trans->URL);
DestroyString(Trans->Path);
DestroyString(Trans->Arguments);
DestroyString(Trans->Destination);
DestroyString(Trans->ContentType);
DestroyString(Trans->ContentBoundary);
DestroyString(Trans->UserName);
DestroyString(Trans->Password);
DestroyString(Trans->RealUser);
DestroyString(Trans->HomeDir);
DestroyString(Trans->AuthType);
DestroyString(Trans->Host);
DestroyString(Trans->ClientIP);
DestroyString(Trans->ClientHost);
DestroyString(Trans->ClientReferrer);
DestroyString(Trans->UserAgent);
DestroyString(Trans->ServerName);
DestroyString(Trans->SearchPath);
DestroyString(Trans->UserSettings);
DestroyString(Trans->StartDir);

ListDestroy(Trans->Headers,DestroyString);
free(Trans);
}


int HTTPServerDecideToCompress(HTTPSession *Session, char *Path)
{
//If client hasn't asked for it (Accept-Encoding) then don't
if (! Session) return(FALSE);
if (! (Session->Flags & HTTP_ENCODE_GZIP)) return(FALSE);

if (IsProxyMethod(Session->MethodID)) return(FALSE);
if (Settings.Flags & FLAG_COMPRESS) return(TRUE);
if ((Settings.Flags & FLAG_PARTIAL_COMPRESS) && (! Path)) return(TRUE);

return(FALSE);
}




void HTTPServerHandleAuthHeader(HTTPSession *Heads,int HeaderType, char *Type, char *Data)
{
char *Tempstr=NULL, *Name=NULL, *Value=NULL, *ptr;
char *nonce=NULL, *cnonce=NULL, *request_count=NULL, *qop=NULL, *algo=NULL, *uri=NULL;
int len;

if (strcmp(Type,"Basic")==0)
{
	Tempstr=DecodeBase64(Tempstr, &len, Data);
	ptr=GetToken(Tempstr,":",&Heads->UserName,0);
	Heads->Password=CopyStr(Heads->Password,ptr);
}
else if (strcmp(Type,"Digest")==0)
{
	uri=CopyStr(uri,"");
	algo=CopyStr(algo,"");
	ptr=GetNameValuePair(Data,",","=",&Name,&Value);
	while (ptr)
	{
		if (StrLen(Name) && StrLen(Value))
		{
		StripLeadingWhitespace(Name);
		StripLeadingWhitespace(Value);
		if (strcmp(Name,"username")==0) Heads->UserName=CopyStr(Heads->UserName,Value);
		if (strcmp(Name,"response")==0) Heads->Password=CopyStr(Heads->Password,Value);
		if (strcmp(Name,"nonce")==0) nonce=CopyStr(nonce,Value);
		if (strcmp(Name,"cnonce")==0) cnonce=CopyStr(cnonce,Value);
		if (strcmp(Name,"nc")==0) request_count=CopyStr(request_count,Value);
		if (strcmp(Name,"qop")==0) qop=CopyStr(qop,Value);
		if (strcmp(Name,"uri")==0) uri=CopyStr(uri,Value);
		if (strcmp(Name,"algorithm")==0) algo=CopyStr(algo,Value);
		}
		
	ptr=GetNameValuePair(ptr,",","=",&Name,&Value);
	}

// server nonce (nonce), request counter (nc), client nonce (cnonce), quality of protection code (qop) and HA2 result is calculated. The result is the "response" value provided by the client.

if (StrLen(qop)) Heads->AuthDetails=MCopyStr(Heads->AuthDetails,uri,":",algo,":",nonce,":",request_count,":",cnonce,":",qop, NULL);
else Heads->AuthDetails=CopyStr(Heads->AuthDetails,nonce);

}

DestroyString(algo);
DestroyString(uri);
DestroyString(nonce);
DestroyString(cnonce);
DestroyString(request_count);
DestroyString(qop);
DestroyString(Name);
DestroyString(Value);
DestroyString(Tempstr);
}


void HTTPServerParsePostContentType(HTTPSession *Session, char *Data)
{
char *ptr, *Name=NULL, *Value=NULL;

ptr=GetToken(Data,";",&Session->ContentType,0);
while (isspace(*ptr)) ptr++;

ptr=GetNameValuePair(ptr,";","=",&Name,&Value);
while (ptr)
{
	if (strcmp(Name,"boundary")==0) Session->ContentBoundary=MCopyStr(Session->ContentBoundary,"--",Value,NULL);
	ptr=GetNameValuePair(ptr,";","=",&Name,&Value);
}

DestroyString(Name);
DestroyString(Value);
}


void HTTPServerReadHeaders(HTTPSession *Heads, STREAM *S)
{
char *Tempstr=NULL, *Token=NULL, *ptr, *tmp_ptr;
ListNode *Curr;
int val;


Tempstr=STREAMReadLine(Tempstr,S);

GetSockDetails(S->in_fd,&Heads->ServerName,&Heads->ServerPort,&Heads->ClientIP,&val);
if ((Settings.Flags & FLAG_LOOKUP_CLIENT) && StrLen(Heads->ClientIP)) Heads->ClientHost=CopyStr(Heads->ClientHost,IPStrToHostName(Heads->ClientIP));

LogToFile(Settings.LogPath,"");
//Log first line of the response
LogToFile(Settings.LogPath,"NEW REQUEST: %s (%s) %s",Heads->ClientHost,Heads->ClientIP,Tempstr);

ptr=GetToken(Tempstr,"\\S",&Heads->Method,0);
Heads->MethodID=MatchTokenFromList(Heads->Method,HTTPMethods,0);

ptr=GetToken(ptr,"\\S",&Token,0);
tmp_ptr=Token;

//Clip out arguments from URL
tmp_ptr=strchr(Token,'?');
if (tmp_ptr)
{
	*tmp_ptr='\0';
	tmp_ptr++;
//	Heads->Arguments=HTTPUnQuote(Heads->Arguments,tmp_ptr);

	//Don't unquote arguments here, one of them might contain '&'
	Heads->Arguments=CopyStr(Heads->Arguments,tmp_ptr);
}


//URL with arguments removed is the 'true' URL
Heads->URL=HTTPUnQuote(Heads->URL,Token);
if (StrLen(Heads->URL)==0) Heads->URL=CopyStr(Heads->URL,"/");


StripTrailingWhitespace(Heads->URL);
Tempstr=STREAMReadLine(Tempstr,S);

if (StrLen(Tempstr))
{
	StripTrailingWhitespace(Tempstr);
	StripLeadingWhitespace(Tempstr);
}

tmp_ptr=Heads->URL;
while (*tmp_ptr=='/') tmp_ptr++;

if 
(
	(strncasecmp(tmp_ptr,"http:",5)==0) ||
	(strncasecmp(tmp_ptr,"https:",6)==0)
)
{
	if (Heads->MethodID==METHOD_GET) 
	{
		Heads->Method=CopyStr(Heads->Method,"RGET");
		Heads->MethodID=METHOD_RGET;
	}

	if (Heads->MethodID==METHOD_POST)
	{
		Heads->Method=CopyStr(Heads->Method,"RPOST");
		Heads->MethodID=METHOD_RPOST;
	}
}


if (*tmp_ptr=='/') Heads->Path=CopyStr(Heads->Path,tmp_ptr);
else Heads->Path=MCopyStr(Heads->Path,"/",tmp_ptr,NULL);


while (StrLen(Tempstr) )
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"<< %s",Tempstr);
	ptr=GetToken(Tempstr,":",&Token,0);

	while (isspace(*ptr)) ptr++;
	val=MatchTokenFromList(Token,HeaderStrings,0);
	ListAddNamedItem(Heads->Headers,Token,CopyStr(NULL,ptr));

	switch (val)
	{
	case HEAD_PROXYAUTH:
			if (IsProxyMethod(Heads->MethodID))
			{
			ptr=GetToken(ptr,"\\S",&Token,0);
			HTTPServerHandleAuthHeader(Heads,val,Token,ptr);
			Heads->Flags |= FLAG_HAS_AUTH;
			}
	break;

	case HEAD_AUTH:
			if (IsProxyMethod(Heads->MethodID))
			{
				Heads->RemoteAuthenticate=CopyStr(Heads->RemoteAuthenticate,ptr);
			}

			if (StrLen(Heads->UserName)==0)
			{
				ptr=GetToken(ptr,"\\S",&Token,0);
				HTTPServerHandleAuthHeader(Heads,val,Token,ptr);
				Heads->Flags |= FLAG_HAS_AUTH;
			}
		break;

	case HEAD_HOST:
		Heads->Host=CopyStr(Heads->Host,ptr);
		ptr=strchr(Heads->Host,':');
		if (! ptr) 
		{
			Token=FormatStr(Token,":%d",Settings.Port);
			Heads->Host=CatStr(Heads->Host,Token);
		}
		break;

	case HEAD_DEST:
		Heads->Destination=HTTPUnQuote(Heads->Destination,ptr);
		break;

	case HEAD_CONTENT_TYPE:
		HTTPServerParsePostContentType(Heads, ptr);
		break;

	case HEAD_CONTENT_LENGTH:
		Heads->ContentSize=atoi(ptr);
		break;

	case HEAD_DEPTH:
		if (strcasecmp(ptr,"infinity")==0) Heads->Depth=INT_MAX;
		else Heads->Depth=atoi(ptr);
		break;

	case HEAD_OVERWRITE:
		if (*ptr=='T') Heads->Flags |= HTTP_OVERWRITE;
		break;

	case HEAD_AGENT:
		Heads->UserAgent=CopyStr(Heads->UserAgent,ptr);
		Curr=ListGetNext(Settings.UserAgents);
		while (Curr)
		{
		if (fnmatch(Curr->Tag,Heads->UserAgent,0)==0) 
		{
			ParseConfigItemList((char *) Curr->Item);
		}
		Curr=ListGetNext(Curr);
		}
		break;

	case HEAD_COOKIE:
			if (StrLen(Heads->Cookies)) Heads->Cookies=MCopyStr(Heads->Cookies,"; ",ptr,NULL);
			else Heads->Cookies=CopyStr(Heads->Cookies,ptr);
		break;

	case HEAD_REFERER:
		Heads->ClientReferrer=CopyStr(Heads->ClientReferrer,ptr);
		break;

	case HEAD_ACCEPT_ENCODING:
		ptr=GetToken(ptr,",",&Token,0);
		while (ptr)
		{
			if (strcmp(Token,"gzip")==0) Heads->Flags|=HTTP_ENCODE_GZIP;
			if (strcmp(Token,"x-gzip")==0) Heads->Flags|=HTTP_ENCODE_GZIP | HTTP_ENCODE_XGZIP;
		ptr=GetToken(ptr,",",&Token,0);
		}
		break;

		case HEAD_ICECAST:
			if (atoi(ptr)) Heads->Flags |= HTTP_ICECAST;
		break;

		case HEAD_IFMOD_SINCE:
			Heads->IfModifiedSince=DateStrToSecs("%a, %d %b %Y %H:%M:%S %Z",ptr,NULL);
		break;
	}

Tempstr=STREAMReadLine(Tempstr,S);
StripTrailingWhitespace(Tempstr);
StripLeadingWhitespace(Tempstr);
}


	if (strstr(Heads->Arguments,"AccessToken")) Heads->Flags |= FLAG_HAS_AUTH | FLAG_ACCESS_TOKEN;

DestroyString(Tempstr);
DestroyString(Token);
}


void HTTPServerSendHeader(STREAM *S, char *Header, char *Value)
{
char *Tempstr=NULL;

Tempstr=MCopyStr(Tempstr,Header,": ",Value,"\r\n",NULL);
STREAMWriteLine(Tempstr,S);
if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,">> %s",Tempstr);
DestroyString(Tempstr);
}


void HTTPServerSendHeaders(STREAM *S, HTTPSession *Session, int Flags)
{
char *Tempstr=NULL;
ListNode *Curr;

Tempstr=MCopyStr(Tempstr,Session->Protocol," ",Session->ResponseCode,"\r\n",NULL);
STREAMWriteLine(Tempstr,S);
if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,">> %s",Tempstr);

HTTPServerSendHeader(S,"Date",GetDateStr("%a, %d %b %Y %H:%M:%S %Z",NULL));
Tempstr=MCopyStr(Tempstr,"alaya/",Version,NULL);
HTTPServerSendHeader(S, "Server", Tempstr);

if (Session->LastModified > 0) HTTPServerSendHeader(S,"Last-Modified",GetDateStrFromSecs("%a, %d %b %Y %H:%M:%S %Z",Session->LastModified,NULL));

if (Flags & HEADERS_AUTH) 
{
	if (Settings.Flags & FLAG_DIGEST_AUTH) Tempstr=FormatStr(Tempstr,"Digest realm=\"%s\", qop=\"auth\", nonce=\"%x\"", Settings.AuthRealm, rand());
	else Tempstr=MCopyStr(Tempstr,"Basic realm=\"",Settings.AuthRealm,"\"",NULL);

	if (IsProxyMethod(Session->MethodID) ) HTTPServerSendHeader(S,"Proxy-Authenticate",Tempstr);
	else
	{
		if (Settings.Flags & FLAG_DIGEST_AUTH)
		{
			Tempstr=FormatStr(Tempstr,"Digest realm=\"%s\", qop=\"auth\", nonce=\"%x\"", Settings.AuthRealm, rand());
			HTTPServerSendHeader(S,"WWW-Authenticate",Tempstr);
		}

		Tempstr=MCopyStr(Tempstr,"Basic realm=\"",Settings.AuthRealm,"\"",NULL);
		HTTPServerSendHeader(S,"WWW-Authenticate",Tempstr);
	}
}

//Special headers passed in for this transaction
Curr=ListGetNext(Session->Headers);
while (Curr)
{
	HTTPServerSendHeader(S, Curr->Tag, (char *) Curr->Item);
	Curr=ListGetNext(Curr);
}


//Custom headers defined in the config file
Curr=ListGetNext(Settings.CustomHeaders);
while (Curr)
{
	HTTPServerSendHeader(S, Curr->Tag, (char *) Curr->Item);
	Curr=ListGetNext(Curr);
}

if (Session->Flags & FLAG_NOCACHE)
{
	HTTPServerSendHeader(S, "Cache-Control", "no-cache");
	HTTPServerSendHeader(S, "Pragma", "no-cache");
}

HTTPServerSendHeader(S, "Connection", "close");
//If we are running a CGI script, then the script will handle all headers relating to content
if (! (Flags & HEADERS_CGI)) 
{
	HTTPServerSendHeader(S, "DAV", "1");
	if (StrLen(Session->ContentType)) HTTPServerSendHeader(S,"Content-Type",Session->ContentType);
	if (Session->ContentSize > 0)
	{
		Tempstr=FormatStr(Tempstr,"%d",Session->ContentSize);
		HTTPServerSendHeader(S,"Content-Length",Tempstr);
	}
	
	//some clients use 'x-gzip' rather than just 'gzip'
	if (Session->Flags & HTTP_ENCODE_XGZIP) HTTPServerSendHeader(S,"Content-Encoding","x-gzip");
	else if (Session->Flags & HTTP_ENCODE_GZIP) HTTPServerSendHeader(S,"Content-Encoding", "gzip");
	
	
	//Blank line to end headers
	STREAMWriteLine("\r\n",S);
}

DestroyString(Tempstr);
}


//'Heads' here is the Request headers, it's used to pass information about
//what's been requested by the client
void HTTPServerSendResponse(STREAM *S, HTTPSession *Heads, char *ResponseLine, char *ContentType, char *Body)
{
STREAM *Doc;
HTTPSession *Response;
char *Tempstr=NULL;

Response=HTTPSessionCreate();
Response->ResponseCode=CopyStr(Response->ResponseCode,ResponseLine);
if (strncmp(ResponseLine,"302",3)==0) SetVar(Response->Headers,"Location",Body);
else Response->ContentSize=StrLen(Body);
Response->ContentType=CopyStr(Response->ContentType,ContentType);
if (Heads)
{
	Response->MethodID=Heads->MethodID;
	Response->LastModified=Heads->LastModified;
}

if (HTTPServerDecideToCompress(Heads,NULL))
{
  Response->Flags |= HTTP_ENCODE_GZIP;
	Tempstr=SetStrLen(Tempstr,Response->ContentSize *2); 
  Response->ContentSize=CompressBytes(&Tempstr, "gzip",Body, StrLen(Body), 5);
}
else Tempstr=CopyStr(Tempstr,Body);

HTTPServerSendHeaders(S, Response,0);
STREAMWriteBytes(S,Tempstr,Response->ContentSize);

DestroyHTTPSession(Response);

DestroyString(Tempstr);
}


void HTTPServerSendHTML(STREAM *S, HTTPSession *Heads, char *Title, char *Body)
{
char *Tempstr=NULL;

Tempstr=FormatStr(Tempstr,"<html><body><h1>%s</h1>%s</body></html>",Title,Body);
HTTPServerSendResponse(S, Heads, Title, "text/html",Body);

DestroyString(Tempstr);
}



void SendICYMessage(STREAM *Output, const char *ICYMessage)
{
uint8_t len;
char *Tempstr=NULL;

	len=StrLen(ICYMessage);
	if (len > 0) len=(len / 16) + 1;
	Tempstr=SetStrLen(Tempstr,len * 16);
	memset(Tempstr,0,len * 16);
	strcpy(Tempstr,ICYMessage);
	STREAMWriteBytes(Output,&len,1);
	STREAMWriteBytes(Output,Tempstr,len * 16);

DestroyString(Tempstr);
}


HTTPSession *NormalFileSendSessionCreate(char *Path, ListNode *Vars)
{
HTTPSession *Headers;

Headers=HTTPSessionCreate();
Headers->ResponseCode=CopyStr(Headers->ResponseCode,"200 OK");
Headers->ContentType=CopyStr(Headers->ContentType,GetVar(Vars,"ContentType"));
Headers->LastModified=atoi(GetVar(Vars,"MTime-secs"));
Headers->ContentSize=atoi(GetVar(Vars,"FileSize"));


return(Headers);
}


HTTPSession *MediaItemCreateSendSession(char *Path, int ClientFlags, int IcyInterval, ListNode *Vars)
{
HTTPSession *Response;
char *Tempstr=NULL;

Response=NormalFileSendSessionCreate(Path, Vars);
/*
if (ClientFlags & HTTP_ICECAST) 
{
	Response->Flags |= HTTP_ICECAST;
	Response->Protocol=CopyStr(Response->Protocol,"ICY");
	Tempstr=FormatStr(Tempstr,"%d",IcyInterval);
	SetVar(Response->Headers,"icy-metaint",Tempstr);
}
*/

DestroyString(Tempstr);

return(Response);
}




HTTPSession *FileSendCreateSession(char *Path, int ClientFlags, ListNode *Vars, int ICYInterval)
{
		HTTPSession *Session;

		if (ClientFlags & HTTP_ICECAST) Session=MediaItemCreateSendSession(Path, ClientFlags, ICYInterval, Vars);
		else Session=NormalFileSendSessionCreate(Path, Vars);
		if (HTTPServerDecideToCompress(Session,Path))
		{
			Session->ContentSize=0;
			Session->Flags|=HTTP_ENCODE_GZIP;
		}

		return(Session);
}



void IcecastSendData(STREAM *Input, STREAM *Output, int ICYInterval)
{
char *ICYMessage=NULL, *Tempstr=NULL;
int BuffSize=4096, BytesRead=0, len, result;
ListNode *Vars;

	Vars=ListCreate();
	SetVar(Vars, "Title",GetBasename(Input->Path));
	MediaReadDetails(Input,Vars);

	ICYMessage=SubstituteVarsInString(ICYMessage,"StreamTitle='$(Title)'; StreamArtist='$(Artist)';",Vars,0);
	LogToFile(Settings.LogPath,"Open: %s, message: %s",Input->Path,ICYMessage);
	Tempstr=SetStrLen(Tempstr,BuffSize);
	while (TRUE) 
	{
		len=ICYInterval-BytesRead;
		if (len > BuffSize) len=BuffSize;
		result=STREAMReadBytes(Input,Tempstr,len);
		if (result==EOF) break;

		BytesRead+=result;
		STREAMWriteBytes(Output,Tempstr,result);

		if (BytesRead==ICYInterval)
		{
			LogToFile(Settings.LogPath,"SEND ICY: %s",ICYMessage);
			BytesRead=0;
			SendICYMessage(Output, ICYMessage);
			//Don't send it again.
			ICYMessage=CopyStr(ICYMessage,"");
		}	
	}

ListDestroy(Vars,DestroyString);
DestroyString(ICYMessage);
DestroyString(Tempstr);
}


void HTTPServerHandleStream(STREAM *Output,HTTPSession *Session, char *SearchPath, int SendData)
{
char *Tempstr=NULL;
HTTPSession *Response;
ListNode *Vars;
STREAM *S;
glob_t Glob;
int i;


Vars=ListCreate();
SetVar(Vars,"ContentType","audio/mpeg");
Response=MediaItemCreateSendSession("", Session->Flags, 0, Vars);
HTTPServerSendHeaders(Output, Response, FALSE);
STREAMFlush(Output);

Tempstr=MCopyStr(Tempstr,SearchPath,"/*",NULL);
glob(Tempstr,0,0,&Glob);

LogToFile(Settings.LogPath,"Stream from Dir: %s, %d files",SearchPath,Glob.gl_pathc);

for (i=0; i < Glob.gl_pathc; i++)
{
	S=STREAMOpenFile(Glob.gl_pathv[i],O_RDONLY);
	if (S)
	{
		IcecastSendData(S, Output, 4096000);
		STREAMClose(S);
	}
}

globfree(&Glob);
DestroyString(Tempstr);
ListDestroy(Vars,DestroyString);
}


void HTTPServerSendFile(STREAM *S, HTTPSession *Session, char *Path, ListNode *Vars, int SendData)
{
STREAM *Doc;
HTTPSession *ResponseHeaders;
char *Buffer=NULL, *Tempstr=NULL;
int BuffSize=4096, result;
int ICYInterval=4096000;

	Doc=STREAMOpenFile(Path, O_RDONLY);
	if (! Doc) 
	{
			HTTPServerSendHTML(S, Session, "403 Forbidden","You don't have permission for that.");
			LogToFile(Settings.LogPath,"%s@%s (%s) 403 Forbidden: %s", Session->UserName,Session->ClientHost,Session->ClientIP,Session->Path);
	}
	else
	{
		if (Session)
		{
			LogToFile(Settings.LogPath,"%s@%s (%s) downloading %s (%s bytes)",Session->UserName,Session->ClientHost,Session->ClientIP,Path,GetVar(Vars,"FileSize"));
		}

		ResponseHeaders=FileSendCreateSession(Path, Session->Flags, Vars, ICYInterval);
		HTTPServerSendHeaders(S, ResponseHeaders,0);

		if (ResponseHeaders->Flags & HTTP_ENCODE_GZIP) STREAMAddStandardDataProcessor(S,"compression","gzip","CompressionLevel=1");

		
		if (SendData)
		{
		if (Session->Flags & HTTP_ICECAST) IcecastSendData(Doc, S, ICYInterval);
		else STREAMSendFile(Doc, S, 0);
		}

		STREAMClose(Doc);
		DestroyHTTPSession(ResponseHeaders);
	}

DestroyString(Buffer);
DestroyString(Tempstr);
}





void HTTPServerSendDocument(STREAM *S, HTTPSession *Session, char *Path, int SendData)
{
int result;
ListNode *Vars;

Vars=ListCreate();

//Do not accept any paths containing '..', as these can be used to
//access documents outside of the trusted path
if (strstr(Path,"../"))
{
	LogToFile(Settings.LogPath,"ERR: '..' found in %s",Path);
	 HTTPServerSendHTML(S, Session, "403 Forbidden","'..' pattern found in URL");
	LogToFile(Settings.LogPath,"%s@%s (%s) 403 Forbidden: '..' found in URL %s", Session->UserName,Session->ClientHost,Session->ClientIP,Path);
}
else
{
		result=ExamineFile(Path, FALSE, Vars);
		if (result==FILE_NOSUCH) 
		{
			HTTPServerSendHTML(S, Session, "404 Not Found","Couldn't find that document.");
			LogToFile(Settings.LogPath,"%s@%s (%s) 404 Not Found: %s", Session->UserName,Session->ClientHost,Session->ClientIP,Path);
		}
		else
		{
		//Set 'LastModified' so we can use it if the server sends 'If-Modified-Since'
	  Session->LastModified=atoi(GetVar(Vars,"MTime-secs"));

		//If we are asking for details of a file then we treat that as a directory function
		if ((result==FILE_DIR) || (strstr(Session->Arguments,"format="))) HTTPServerSendDirectory(S,Session,Path,Vars);
		else HTTPServerSendFile(S, Session, Path, Vars, SendData);
		}

}

ListDestroy(Vars,DestroyString);
}



//This function checks the Paths configured in the server for virtual 
//documents like cgi scripts or streams, or for directories to which we
//are allowed access from outside chroot
void HTTPServerFindAndSendDocument(STREAM *S, HTTPSession *Session, int SendData)
{
ListNode *Curr=NULL, *Matching=NULL, *Default=NULL;
TPathItem *PI=NULL;
char *Path=NULL, *Tempstr=NULL, *ptr;
int len;


	Curr=ListGetNext(Settings.VPaths);
	while (Curr)
	{
		if (StrLen(Curr->Tag) < 2) Default=Curr;
		else if (strncmp(Session->Path,Curr->Tag,StrLen(Curr->Tag))==0) break;
		Curr=ListGetNext(Curr);
	}

	//If Curr is set then we found a VPath
	if (! Curr) Curr=Default;


	if (Curr)
	{
	PI=(TPathItem *) Curr->Item;
		
		LogToFile(Settings.LogPath,"APPLYING VPATH: %d [%s] -> [%s]",PI->Type,Curr->Tag,PI->Path);
		switch (PI->Type)
		{
			case PATHTYPE_CGI:
			LogToFile(Settings.LogPath,"CGI: %s %s",GetBasename(Session->Path), PI->Path);
			ChrootProcessRequest(S, Session, "EXEC", GetBasename(Session->Path), PI->Path);
			break;

			case PATHTYPE_EXTFILE:
			HTTPServerHandleVPath(S,Session,PI,SendData);
			break;

			case PATHTYPE_STREAM:
			HTTPServerHandleStream(S,Session,PI->Path,SendData);
			break;

			case PATHTYPE_LOGOUT:
			Session->Path=FormatStr(Session->Path,"%d-%d-%d",getpid(),time(NULL),rand());
			HTTPServerHandleRegister(Session, LOGIN_CHANGE);
			Path=FormatURL(Path, Session, "/");
			Path=MCatStr(Path,"?Logout=",Session->Path,NULL);
			HTTPServerSendResponse(S, Session, "302", "", Path);
			break;

			case PATHTYPE_URL:
      ChrootProcessRequest(S, Session, "PROXY", PI->Path, "");
			break;

			case PATHTYPE_PROXY:
			if (StrLen(Session->UserName)) 
			{
				Path=MCopyStr(Path,Session->UserName,":",Session->Password,NULL);
				Tempstr=EncodeBase64(Tempstr, Path, StrLen(Path));
				Session->RemoteAuthenticate=MCopyStr(Session->RemoteAuthenticate,"Basic ",Tempstr,NULL);	
			}
      Path=MCopyStr(Path,PI->Path,Session->Path+StrLen(PI->URL),NULL);
      ChrootProcessRequest(S, Session, "PROXY", Path, "");
			break;
		}
	}
	else 
	{
		ptr=Session->StartDir;
		if (*ptr=='.') ptr++;
		if (strcmp(ptr,"/")==0) Path=CopyStr(Path,Session->Path);
		else Path=MCopyStr(Path,ptr,Session->Path,NULL);

		HTTPServerSendDocument(S, Session, Path, SendData);
	}

DestroyString(Tempstr);
DestroyString(Path);
}


void HTTPServerRecieveURL(STREAM *S,HTTPSession *Heads)
{
STREAM *Doc;
struct stat FileStat;
char *Buffer=NULL, *Tempstr=NULL;
int BuffSize=4096, result, total=0;


Doc=STREAMOpenFile(Heads->Path, O_CREAT | O_TRUNC | O_WRONLY);

if (! Doc) 
{
	HTTPServerSendHTML(S, Heads, "403 Forbidden","Can't open document for write.");
	LogToFile(Settings.LogPath,"%s@%s (%s) 403 Forbidden: '..' cannot open %s", Heads->UserName,Heads->ClientHost,Heads->ClientIP,Heads->Path);
}
else
{
	fchmod(Doc->in_fd,0660); 

	Buffer=SetStrLen(Buffer,BuffSize);
	total=STREAMSendFile(S,Doc,Heads->ContentSize);
	STREAMClose(Doc);

	stat(Heads->Path,&FileStat);
	LogToFile(Settings.LogPath,"%s@%s (%s) uploaded %s (%d bytes)",Heads->UserName,Heads->ClientHost,Heads->ClientIP,Heads->Path,FileStat.st_size);
	HTTPServerSendHTML(S, Heads, "201 Created","");
}


DestroyString(Tempstr);
DestroyString(Buffer);
}



void HTTPServerMkDir(STREAM *S,HTTPSession *Heads)
{
int result;

result=mkdir(Heads->Path, 0770);
if (result==0) HTTPServerSendHTML(S, Heads, "201 Created","");
else switch (errno)
{

	case EEXIST:
	HTTPServerSendHTML(S, Heads, "405 Method Not Allowed (exists)","");
	break;

	case ENOENT:
	case ENOTDIR:
	HTTPServerSendHTML(S, Heads, "409 Conflict","");
	break;

	case ENOSPC:
	HTTPServerSendHTML(S, Heads, "507 Insufficient Storage","");
	break;

	default:
	HTTPServerSendHTML(S, Heads, "403 Forbidden","You don't have permission for that.");
	break;

}

}

int HTTPServerDeleteCollection(HTTPSession *Session,char *Path)
{
struct stat FileStat;
glob_t myGlob;
int result, i;
char *Tempstr=NULL, *ptr;


LogToFile(Settings.LogPath,"%s@%s (%s) DeleteCollection: %s",Session->UserName,Session->ClientHost,Session->ClientIP,Path);


Tempstr=MCopyStr(Tempstr,Path,"/*",NULL);
glob(Tempstr,0,0,&myGlob);
for (i=0; i < myGlob.gl_pathc; i++)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"%s@%s (%s) DeleteSubItem: %s",Session->UserName,Session->ClientHost,Session->ClientIP,myGlob.gl_pathv[i]);

	ptr=myGlob.gl_pathv[i];
	if ((strcmp(ptr,".") !=0) && (strcmp(ptr,"..") !=0)) 
	{
	stat(ptr,&FileStat);
	if (S_ISDIR(FileStat.st_mode)) HTTPServerDeleteCollection(Session,ptr);
	else unlink(ptr);
	}

}

DestroyString(Tempstr);
globfree(&myGlob);
result=rmdir(Path);

return(result);
}


void HTTPServerDelete(STREAM *S,HTTPSession *Heads)
{
int result;
struct stat FileStat;

stat(Heads->Path,&FileStat);
if (S_ISDIR(FileStat.st_mode)) result=HTTPServerDeleteCollection(Heads,Heads->Path);
else result=unlink(Heads->Path);

if (result==0) HTTPServerSendHTML(S, Heads, "200 Deleted","");
else switch (errno)
{

	case ENOENT:
	case ENOTDIR:
	HTTPServerSendHTML(S, Heads, "404 No such item","");
	break;

	case EISDIR:
	HTTPServerSendHTML(S, Heads, "409 Conflict","");
	break;

	default:
	HTTPServerSendHTML(S, Heads, "403 Forbidden","You don't have permission for that.");
	break;

}


}





void HTTPServerCopy(STREAM *S,HTTPSession *Heads)
{
int result=-1;
char *Tempstr=NULL, *Host=NULL, *Destination=NULL, *ptr;
char *User=NULL, *Password=NULL, *FromPath=NULL, *ToPath=NULL;

LogToFile(Settings.LogPath,"HTTP COPY: [%s] [%s]",Heads->URL,Heads->Destination);

result=CopyURL(Heads, Heads->URL, Heads->Destination);

switch (result)
{
	case 0:
		 HTTPServerSendHTML(S, Heads, "201 Created","");
	break;

	case ENOENT:
	case ENOTDIR:
	HTTPServerSendHTML(S, Heads, "404 No such item","");
	break;

	case EISDIR:
	HTTPServerSendHTML(S, Heads, "409 Conflict","");
	break;

	case EEXIST:
	HTTPServerSendHTML(S, Heads, "412 Precondition failed. File exists, but 'Overwrite' set to false","");
	break;

	default:
	HTTPServerSendHTML(S, Heads, "403 Forbidden","You don't have permission for that.");
	break;

}


DestroyString(Host);
DestroyString(Tempstr);
DestroyString(Destination);
}



void HTTPServerMove(STREAM *S,HTTPSession *Heads)
{
int result;
char *Tempstr=NULL, *Host=NULL, *Destination=NULL, *ptr;

Tempstr=CopyStr(Tempstr,Heads->Destination);
ptr=Tempstr;
if (strncmp(ptr,"http:",5)==0) ptr+=5;
if (strncmp(ptr,"https:",6)==0) ptr+=6;
while (*ptr=='/') ptr++;

ptr=GetToken(ptr,"/",&Host,0);

Destination=MCopyStr(Destination,Heads->StartDir,ptr,NULL);
result=rename(Heads->Path,Destination);



if (result==0) HTTPServerSendHTML(S, Heads, "201 Moved","");
else switch (errno)
{

	case ENOENT:
	case ENOTDIR:
	HTTPServerSendHTML(S, Heads, "404 No such item","");
	break;

	case EISDIR:
	HTTPServerSendHTML(S, Heads, "409 Conflict","");
	break;


	default:
	HTTPServerSendHTML(S, Heads, "403 Forbidden","You don't have permission for that.");
	break;

}


DestroyString(Host);
DestroyString(Tempstr);
DestroyString(Destination);
}


void HTTPServerOptions(STREAM *S,HTTPSession *ClientHeads)
{
int result;
char *Tempstr=NULL, *ptr;
HTTPSession *Heads;

STREAMWriteLine("HTTP/1.1 200 OK\r\n",S);
Tempstr=CopyStr(Tempstr,GetDateStr("Date: %a, %d %b %Y %H:%M:%S %Z\r\n",NULL));
STREAMWriteLine(Tempstr,S);
Tempstr=MCopyStr(Tempstr, "Server: Alaya/",Version,"\r\n",NULL);
STREAMWriteLine(Tempstr,S);
STREAMWriteLine("Content-Length: 0\r\n",S);
STREAMWriteLine("Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH\r\n",S);
STREAMWriteLine("Allow: OPTIONS, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH\r\n",S);
STREAMWriteLine("DASL:\r\n",S);
STREAMWriteLine("DAV: 1\r\n",S);

STREAMWriteLine("Connection: close\r\n\r\n",S);

DestroyString(Tempstr);
}




void HTTPServerDemandAuth(STREAM *S, HTTPSession *Session)
{
HTTPSession *Response;

Response=HTTPSessionCreate();
if (IsProxyMethod(Session->MethodID)) Response->ResponseCode=CopyStr(Response->ResponseCode,"407 UNAUTHORIZED");
else Response->ResponseCode=CopyStr(Response->ResponseCode,"401 UNAUTHORIZED");
Response->MethodID=Session->MethodID;
HTTPServerSendHeaders(S, Response, HEADERS_AUTH);
DestroyHTTPSession(Response);
}



void HTTPServerSetUserContext(HTTPSession *Session)
{
char *ChrootDir=NULL, *Tempstr=NULL;

Session->StartDir=CopyStr(Session->StartDir,Settings.DefaultDir);
ChrootDir=CopyStr(ChrootDir,Settings.DefaultDir);

if (IsProxyMethod(Session->MethodID))
{
//Do not chroot for proxy commands
}
else 
{
	if (Settings.Flags & FLAG_CHHOME) ChrootDir=CopyStr(ChrootDir,Session->HomeDir);

	if (chdir(ChrootDir) !=0) 
	{
		//If we cannot chdir to the home dir, try the DefaultDir
		ChrootDir=CopyStr(ChrootDir,Settings.DefaultDir);
		chdir(ChrootDir);
	}
	chroot(".");
	Session->StartDir=CopyStr(Session->StartDir,"/");
}

/*
/Not working yet
else if (Settings.Flags & FLAG_CHSHARE) 
{
	chdir(Settings.DefaultDir);
	chroot(".");
	if (strncmp(Session->StartDir,Settings.DefaultDir,StrLen(Settings.DefaultDir))==0)
	{
		Tempstr=MCopyStr(Tempstr,"/",Session->StartDir+StrLen(Settings.DefaultDir),NULL);
		chdir(Tempstr);
		Session->StartDir=CopyStr(Session->StartDir,Tempstr);
	}
}
*/

Session->StartDir=SlashTerminateDirectoryPath(Session->StartDir);

LogToFile(Settings.LogPath,"User Context: Chroot: %s, StartDir: %s, UserID: %d, GroupID %d,",ChrootDir, Session->StartDir,Session->RealUserUID,Session->GroupID);

if (Session->GroupID > 0) setgid(Session->GroupID);
else if (Settings.DefaultGroupID > 0) setgid(Settings.DefaultGroupID);

DropCapabilities(CAPS_LEVEL_CHROOTED);

if (setresuid(Session->RealUserUID,Session->RealUserUID,Session->RealUserUID)==0)
{
//  RetVal=TRUE;
}

//drop everything! (In case someting went wrong with setresuid) 
DropCapabilities(CAPS_LEVEL_SESSION);

DestroyString(Tempstr);
DestroyString(ChrootDir);
}


int ActivateSSL(STREAM *S,ListNode *Keys)
{
ListNode *Curr;

Curr=ListGetNext(Keys);
while (Curr)
{
STREAMSetValue(S,Curr->Tag,(char *) Curr->Item);
Curr=ListGetNext(Curr);
}

DoSSLServerNegotiation(S,0);
}


int HTTPMethodAllowed(HTTPSession *Session) 
{
char *Token=NULL, *ptr;

if (StrLen(Settings.HttpMethods)==0) return(TRUE);

ptr=GetToken(Settings.HttpMethods,",",&Token,0);
while (ptr)
{
if (strcmp(Token,Session->Method)==0) 
{
DestroyString(Token);
return(TRUE);
}

ptr=GetToken(ptr,",",&Token,0);
}

DestroyString(Token);
return(FALSE);
}




int HTTPServerAuthenticate(HTTPSession *Session)
{
	char *Name=NULL, *Value=NULL, *ptr;
	char *Salt=NULL, *AccessToken=NULL;
	int result=FALSE;
	
	//This handles someone clicking a 'logout' button
	if (! HTTPServerHandleRegister(Session, LOGIN_CHECK_ALLOWED)) 
	{
			LogToFile(Settings.LogPath,"REG AUTH");
			return(FALSE);
	}

	//Consider AccessToken Authentication for this URL!
	if (Session->Flags & FLAG_ACCESS_TOKEN)
	{
		ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
		while (ptr)
		{
			//Put salt in User settings, it will get overwritten during 'Authenticate'
			if (strcasecmp(Name,"Salt")==0) Session->UserSettings=CopyStr(Session->UserSettings,Value);
			if (strcasecmp(Name,"User")==0) Session->UserName=CopyStr(Session->UserName,Value);
			if (strcasecmp(Name,"AccessToken")==0) Session->Password=CopyStr(Session->Password,Value);
			ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
		}
	}

	if ((! result) && (Session->Flags & FLAG_HAS_AUTH))
	{
		if (StrLen(Session->UserName) && Authenticate(Session)) result=TRUE;
		if (result) HTTPServerHandleRegister(Session, LOGGED_IN);
		else HTTPServerHandleRegister(Session, LOGIN_FAIL);
	}

	DestroyString(Salt);
	DestroyString(Name);
	DestroyString(Value);
	DestroyString(AccessToken);

	return(result);
}



int HTTPServerProcessActions(STREAM *S, HTTPSession *Session)
{
typedef enum{ACT_NONE, ACT_GET, ACT_DEL, ACT_RENAME, ACT_EDIT, ACT_MKDIR} TServerActs;
char *QName=NULL, *QValue=NULL, *Name=NULL, *Value=NULL, *ptr;
char *Arg1=NULL, *Arg2=NULL;
int Action=ACT_NONE;
int result=FALSE;


	//QName and QValue will be HTTP quoted, so arguments must be 
	//dquoted after unpacking from the URL
	ptr=GetNameValuePair(Session->Arguments,"&","=",&QName,&QValue);
	while (ptr)
	{
		Name=HTTPUnQuote(Name,QName);
		Value=HTTPUnQuote(Value,QValue);
		if (strncasecmp(Name,"edit:",5)==0)
		{
			Action=ACT_EDIT;
			Arg1=CopyStr(Arg1,Name+5);
		}

		if (strncasecmp(Name,"renm:",5)==0) 
		{
			Action=ACT_RENAME;
			Arg1=CopyStr(Arg1,Name+5);
		}

		if (strncasecmp(Name,"mkdir:",6)==0) 
		{
			Action=ACT_MKDIR;
			Arg1=CopyStr(Arg1,Name+6);
		}
		
		if (strncasecmp(Name,"get:",4)==0) 
		{
			Action=ACT_GET;
			Arg1=CopyStr(Arg1,Name+4);
		}

		if (strncasecmp(Name,"del:",4)==0) 
		{
			Action=ACT_DEL;
			Arg1=CopyStr(Arg1,Name+4);
		}

		if (strcasecmp(Name,"renameto")==0) Arg2=CopyStr(Arg2,Value);
		if (strcasecmp(Name,"mkdir")==0) Arg2=CopyStr(Arg2,Value);

		ptr=GetNameValuePair(ptr,"&","=",&QName,&QValue);
	}


	switch (Action)
	{
		case ACT_EDIT:
		result=TRUE;
		Value=MCopyStr(Value,Arg1,"?format=edit",NULL);
		Session->LastModified=0;
		HTTPServerSendResponse(S, Session, "302", "", Value);
		result=TRUE;
		break;
	
	  case ACT_DEL:
		result=TRUE;
		Value=MCopyStr(Value,Arg1,"?format=delete",NULL);
		Session->LastModified=0;
		HTTPServerSendResponse(S, Session, "302", "", Value);
		break;

	  case ACT_RENAME: 
		if (StrLen(Arg2))
		{
			Value=MCopyStr(Value,Arg1,"?format=rename&renameto=",Arg2,NULL);
			Session->LastModified=0;
			HTTPServerSendResponse(S, Session, "302", "", Value);
			result=TRUE;
		}
		break;

	  case ACT_MKDIR: 
		if (StrLen(Arg2))
		{
			Value=MCopyStr(Value,Arg1,"?format=mkdir&mkdir=",Arg2,NULL);
			Session->LastModified=0;
			HTTPServerSendResponse(S, Session, "302", "", Value);
			result=TRUE;
		}
		break;

		case ACT_GET:
		HTTPServerSendResponse(S, Session, "302", "", Arg1);
		result=TRUE;
		break;
	}

DestroyString(QName);
DestroyString(QValue);
DestroyString(Name);
DestroyString(Value);
DestroyString(Arg1);
DestroyString(Arg2);

return(result);
}


void HTTPServerHandlePost(STREAM *S, HTTPSession *Session)
{
char *Tempstr=NULL;

if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"HANDLE POST: [%s]",Session->ContentType);

//disallow any 'Get' style arguments previously read. Post sends arguments on stdin
Session->Arguments=CopyStr(Session->Arguments,"");

if (strcmp(Session->ContentType,"application/x-www-form-urlencoded")==0)
{
	if (Session->ContentSize > 0)
	{
		Session->Arguments=SetStrLen(Session->Arguments,Session->ContentSize);
		STREAMReadBytes(S,Session->Arguments,Session->ContentSize);
	}
	else
	{
		Tempstr=STREAMReadLine(Tempstr,S);
		while (Tempstr)
		{
			Session->Arguments=CatStr(Session->Arguments,Tempstr);
			Tempstr=STREAMReadLine(Tempstr,S);
		}
	}
}
else HTTPServerHandleMultipartPost(S, Session);

LogToFile(Settings.LogPath,"POST: %s",Session->Arguments);
DestroyString(Tempstr);
}



void HTTPServerHandleConnection(HTTPSession *Session)
{
char *Tempstr=NULL, *Method=NULL, *URL=NULL, *ptr;
int val, AuthOkay=TRUE, result;
int NoOfConnections;
time_t LastTime, Delay=0;

STREAMSetFlushType(Session->S,FLUSH_FULL,4096);
if (Settings.Flags & FLAG_SSL) ActivateSSL(Session->S,Settings.SSLKeys);

HTTPServerReadHeaders(Session,Session->S);
Session->StartDir=CopyStr(Session->StartDir,Settings.DefaultDir);

		

if (Settings.Flags & FLAG_REQUIRE_AUTH)
{
	AuthOkay=FALSE;

	if (HTTPServerAuthenticate(Session))
	{
		LogToFile(Settings.LogPath,"AUTHENTICATE: %s against %s %s\n",Session->UserName,Settings.AuthPath,Settings.AuthMethods);
		AuthOkay=TRUE;
		if (StrLen(Session->UserSettings)) ParseConfigItemList(Session->UserSettings);
	}
	else
	{
		HTTPServerDemandAuth(Session->S, Session);
		LogToFile(Settings.LogPath,"AUTHENTICATE FAIL: %s against %s\n",Session->UserName,Settings.AuthPath);
	}
}




if (! HTTPMethodAllowed(Session))
{
	HTTPServerSendHTML(Session->S, Session, "503 Not implemented","HTTP method disallowed or not implemented.");
	LogToFile(Settings.LogPath,"%s@%s (%s) 503 Not Implemented. %s %s", Session->UserName,Session->ClientHost,Session->ClientIP,Session->Method,Session->Path);
}
else if (AuthOkay)
{
HTTPServerSetUserContext(Session);

StripTrailingWhitespace(Session->Path);

switch (Session->MethodID)
{
	case METHOD_POST:
		HTTPServerHandlePost(Session->S,Session);
		HTTPServerFindAndSendDocument(Session->S,Session,TRUE);
	break;

	case METHOD_GET:
		result=HTTPServerProcessActions(Session->S,Session);
		if (! result) HTTPServerFindAndSendDocument(Session->S,Session,TRUE);
		break;

	case METHOD_RGET:
	case METHOD_RPOST:
		HTTPProxyRGETURL(Session->S,Session);
		break;

	case METHOD_HEAD:
		HTTPServerFindAndSendDocument(Session->S,Session,FALSE);
		break;

	case METHOD_PUT:
		HTTPServerRecieveURL(Session->S,Session);
		break;

	case METHOD_MKCOL:
		HTTPServerMkDir(Session->S,Session);
		break;

	case METHOD_DELETE:
		HTTPServerDelete(Session->S,Session);
		break;

	case METHOD_MOVE:
		HTTPServerMove(Session->S,Session);
		break;

	case METHOD_COPY:
		HTTPServerCopy(Session->S,Session);
		break;

	case METHOD_PROPFIND:
		HTTPServerPropFind(Session->S,Session);
		break;

	case METHOD_PROPPATCH:
		HTTPServerPropPatch(Session->S,Session);
		break;

	case METHOD_OPTIONS:
		HTTPServerOptions(Session->S,Session);
		break;

	case METHOD_CONNECT:
		HTTPProxyConnect(Session->S,Session);
		break;


	default:
	HTTPServerSendHTML(Session->S, Session, "503 Not implemented","HTTP method disallowed or not implemented.");
	LogToFile(Settings.LogPath,"%s@%s (%s) 503 Not Implemented. %s %s", Session->UserName,Session->ClientHost,Session->ClientIP,Session->Method,Session->Path);
	break;
}
}

STREAMClose(Session->S);
LogToFile(Settings.LogPath,"TRANSACTION COMPLETE: %s %s for %s@%s (%s)",Session->Method, Session->Path, Session->UserName,Session->ClientHost,Session->ClientIP);

DestroyHTTPSession(Session);
}



