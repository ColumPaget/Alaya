#include "ChrootHelper.h"
#include "server.h"
#include "proxy.h"

//These functions relate to requests for data from outside of the current
//path and possibly outside of chroot. These scripts/documents are served 
//through a request passed to the 'master' alaya parent process


extern STREAM *ParentProcessPipe;


void AlayaLog(char *Msg)
{
char *Tempstr=NULL;
     
if (ParentProcessPipe)
{
  Tempstr=MCopyStr(Tempstr,"LOG ",Msg, "'\n",NULL);
  STREAMWriteLine(Tempstr,ParentProcessPipe);
  STREAMFlush(ParentProcessPipe);
}
else LogToFile(Settings.LogPath,Msg);


DestroyString(Tempstr);
}


void CleanStr(char *Data)
{
char *BadChars=";|`&";
char *ptr;


for (ptr=Data; *ptr !='\0'; ptr++)
{
	if (strchr(BadChars,*ptr)) *ptr='?';
	else if (! isprint(*ptr)) *ptr='?';
}
}


//Sanitize is more than 'Clean', it clears out any HTML string
char *SanitizeStr(char *Buffer, char *Data)
{
char *TagNamespace=NULL, *TagType=NULL, *TagData=NULL, *ptr;
char *RetStr=NULL, *Tempstr=NULL;

ptr=XMLGetTag(Data, &TagNamespace, &TagType, &TagData);
while (ptr)
{
	if (StrLen(TagType)==0) Tempstr=CatStr(Tempstr,TagData);
	else
	{
		if (
				ListFindNamedItem(Settings.SanitizeArgumentsAllowedTags,TagType) ||
				((*TagType=='/') && ListFindNamedItem(Settings.SanitizeArgumentsAllowedTags,TagType+1))
			)
		{
			if (StrLen(TagNamespace)) Tempstr=MCatStr(Tempstr,"<",TagNamespace,":",TagType,NULL);
			else Tempstr=MCatStr(Tempstr,"<",TagType,NULL);
			if (StrLen(TagData)) Tempstr=MCatStr(Tempstr," ",TagData,NULL);
			Tempstr=CatStr(Tempstr,">");
		}
	}


ptr=XMLGetTag(ptr, &TagNamespace, &TagType, &TagData);
}

RetStr=HTTPQuote(Buffer,Tempstr);

DestroyString(TagNamespace);
DestroyString(Tempstr);
DestroyString(TagType);
DestroyString(TagData);


return(RetStr);
}


char *SanitizeQueryString(char *Buffer, char *Data)
{
char *Name=NULL, *Value=NULL, *Token=NULL, *ptr;
char *RetStr=NULL;

RetStr=CopyStr(Buffer,"");
ptr=GetNameValuePair(Data,"&","=",&Name,&Value);
while (ptr)
{
	Token=HTTPUnQuote(Token, Value);
	StripTrailingWhitespace(Token);
	Value=SanitizeStr(Value,Token);

	if (RetStr && (*RetStr != '\0')) RetStr=MCatStr(RetStr,"&",Name,"=",Value,NULL);
	else RetStr=MCatStr(RetStr,Name,"=",Value,NULL);
	ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
}



DestroyString(Name);
DestroyString(Value);
DestroyString(Token);

return(RetStr);
}



//This function cleans certain bad strings out of environment variables, 
//including the shellshock ()
void SetEnvironmentVariable(const char *Name, const char *Value)
{
char *Tempstr=NULL, *ptr;
char *ForbiddenStrings[]={"() {","`",NULL};
int i;

Tempstr=CopyStr(Tempstr, Value);
for (i=0; ForbiddenStrings[i] !=NULL; i++)
{
	ptr=strstr(Tempstr, ForbiddenStrings[i]);
	while (ptr)
	{
		memset(ptr,' ',StrLen(ForbiddenStrings[i]));
		ptr=strstr(ptr, ForbiddenStrings[i]);
	}
}

setenv(Name, Tempstr, TRUE);

LogToFile(Settings.LogPath,"ENV: %s: %s", Name, Tempstr);

DestroyString(Tempstr);
}



HTTPSession *ParseSessionInfo(char *Data)
{
HTTPSession *Response=NULL;
char *Name=NULL, *Value=NULL, *Tempstr=NULL, *ptr;

	Response=HTTPSessionCreate();
	Response->ContentType=CopyStr(Response->ContentType,"");
	Response->ContentSize=0;
	Response->LastModified=0;

	ptr=GetNameValuePair(Data," ","=",&Name,&Tempstr);
	while (ptr)
	{
		Value=DeQuoteStr(Value,Tempstr);


		if (strcmp(Name,"User")==0) Response->UserName=CopyStr(Response->UserName,Value);
		else if (strcmp(Name,"Host")==0) Response->Host=CopyStr(Response->Host,Value);
		else if (strcmp(Name,"UserAgent")==0) Response->UserAgent=CopyStr(Response->UserAgent,Value);
		else if (strcmp(Name,"Method")==0) Response->Method=CopyStr(Response->Method,Value);
		else if (strcmp(Name,"ContentType")==0) Response->ContentType=CopyStr(Response->ContentType,Value);
		else if (strcmp(Name,"SearchPath")==0) Response->SearchPath=DeQuoteStr(Response->SearchPath,Value);
		else if (strcmp(Name,"Path")==0) Response->Path=DeQuoteStr(Response->Path,Value);
		else if (strcmp(Name,"URL")==0) Response->URL=DeQuoteStr(Response->URL,Value);
		else if (strcmp(Name,"Arguments")==0) Response->Arguments=SanitizeQueryString(Response->Arguments,Value);
		else if (strcmp(Name,"ServerName")==0) Response->ServerName=CopyStr(Response->ServerName,Value);
		else if (strcmp(Name,"ServerPort")==0) Response->ServerPort=atoi(Value);
		else if (strcmp(Name,"ClientIP")==0) Response->ClientIP=CopyStr(Response->ClientIP,Value);
		else if (strcmp(Name,"ClientMAC")==0) Response->ClientMAC=CopyStr(Response->ClientMAC,Value);
		else if (strcmp(Name,"ContentLength")==0) Response->ContentSize=atoi(Value);
		else if (strcmp(Name,"StartDir")==0) Response->StartDir=DeQuoteStr(Response->StartDir,Value);
		else if (strcmp(Name,"ClientReferrer")==0) Response->ClientReferrer=DeQuoteStr(Response->ClientReferrer,Value);
		else if (strcmp(Name,"RemoteAuthenticate")==0) Response->RemoteAuthenticate=CopyStr(Response->RemoteAuthenticate,Value);
		else if (strcmp(Name,"Cipher")==0) Response->Cipher=CopyStr(Response->Cipher,Value);
		else if (strcmp(Name,"Cookies")==0) Response->Cookies=CopyStr(Response->Cookies,Value);
		else if (strcmp(Name,"KeepAlive")==0) Response->Flags |= SESSION_KEEP_ALIVE;

		ptr=GetNameValuePair(ptr," ","=",&Name,&Tempstr);
	}



DestroyString(Name);
DestroyString(Value);
DestroyString(Tempstr);

return(Response);
}


void SetupEnvironment(HTTPSession *Session)
{
char *Tempstr=NULL, *ptr;

	SetEnvironmentVariable("GATEWAY_INTERFACE","CGI/1.1");
	SetEnvironmentVariable("REMOTE_USER",Session->UserName);
	SetEnvironmentVariable("REMOTE_HOST",Session->ClientHost);
	SetEnvironmentVariable("REMOTE_ADDR",Session->ClientIP);
	SetEnvironmentVariable("REMOTE_MAC",Session->ClientMAC);
	SetEnvironmentVariable("SERVER_NAME",Session->ServerName);
	Tempstr=FormatStr(Tempstr,"%d",Session->ServerPort);
	SetEnvironmentVariable("SERVER_PORT",Tempstr);
	Tempstr=FormatStr(Tempstr,"%d",Session->ContentSize);
	SetEnvironmentVariable("CONTENT_LENGTH",Tempstr);


	SetEnvironmentVariable("CONTENT_TYPE",Session->ContentType);
	ptr=strrchr(Session->Path,'/');
	if (ptr) ptr++;
	else ptr=Session->Path;
	SetEnvironmentVariable("SCRIPT_NAME",ptr);
	SetEnvironmentVariable("QUERY_STRING",Session->Arguments);
	SetEnvironmentVariable("HTTP_USER_AGENT",Session->UserAgent);
	SetEnvironmentVariable("HTTP_REFERER",Session->ClientReferrer);
	SetEnvironmentVariable("HTTP_COOKIES",Session->Cookies);
	SetEnvironmentVariable("REQUEST_METHOD",Session->Method);
	SetEnvironmentVariable("REQUEST_URI",Session->URL);
	SetEnvironmentVariable("SERVER_PROTOCOL","HTTP/1.1");
	if (StrLen(Session->Cipher)) SetEnvironmentVariable("SLL",Session->Cipher);

DestroyString(Tempstr);
}


char *FindScriptHandlerForScript(char *RetStr, char *ScriptPath)
{
char *Handler=NULL, *ptr;
ListNode *Curr;

ptr=strrchr(ScriptPath,'.');

Handler=CopyStr(RetStr,"");
if (ptr)
{
	Curr=ListGetNext(Settings.ScriptHandlers);
	while (Curr)
	{
		if (
				(strcmp(Curr->Tag,ptr)==0) ||
				(strcmp(Curr->Tag,ptr+1)==0)
			) 
		{
			Handler=CopyStr(Handler,(char *) Curr->Item);
			break;
		}
		Curr=ListGetNext(Curr);
	}
}

return(Handler);
}




int CheckScriptIntegrity(char *ScriptPath)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *Hash=NULL, *FileHash=NULL, *ptr;
int result, len;

if (! ScriptPath) return(FALSE);
if (! (Settings.Flags & FLAG_CHECK_SCRIPTS)) return(TRUE);


S=STREAMOpenFile(Settings.ScriptHashFile,SF_RDONLY);
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		StripTrailingWhitespace(Tempstr);
		ptr=GetToken(Tempstr," ",&Token,0);
		while (ptr && isspace(*ptr)) ptr++;

		if (ptr && (strcmp(ptr,ScriptPath)==0))
		{
		Hash=CopyStr(Hash,Token);
		len=StrLen(Hash);
		switch (len)
		{
			case 32: //MD5
				HashFile(&FileHash, "md5", ScriptPath, ENCODE_HEX);
			break;

			case 40: //SHA1
				HashFile(&FileHash, "sha1", ScriptPath, ENCODE_HEX);
			break;

			case 64: //SHA256
				HashFile(&FileHash, "sha256", ScriptPath, ENCODE_HEX);
			break;

			case 128: //SHA512
				HashFile(&FileHash, "sha512", ScriptPath, ENCODE_HEX);
			break;
		}
		}

		Tempstr=STREAMReadLine(Tempstr,S);
	
	}
STREAMClose(S);
}


if (StrLen(FileHash) && StrLen(Hash) && (strcmp(FileHash,Hash)==0) ) result=TRUE;
else 
{
	LogToFile(Settings.LogPath,"ERROR: Not running script '%s'. Script failed integrity check.",ScriptPath);
	result=FALSE;
}

DestroyString(FileHash);
DestroyString(Tempstr);
DestroyString(Token);
DestroyString(Hash);

return(result);
}



int HandleExecRequest(STREAM *ClientCon, char *Data)
{
char *Tempstr=NULL, *Name=NULL, *Value=NULL;
char *ScriptPath=NULL;
int result, i;
HTTPSession *Response;

	//We will never read from this stream again. Any further data will be read
	//by the process we spawn off
	ClientCon->State |= SS_EMBARGOED;
	Response=ParseSessionInfo(Data);
	CleanStr(Response->Path);
	CleanStr(Response->SearchPath);
	CleanStr(Response->StartDir);
	ScriptPath=FindFileInPath(ScriptPath,Response->Path,Response->SearchPath);
	LogToFile(Settings.LogPath,"Script: Found=[%s] SearchPath=[%s] ScriptName=[%s] Arguments=[%s]",ScriptPath,Response->SearchPath,Response->Path,Response->Arguments);

	if (access(ScriptPath,F_OK) !=0)
	{
			HTTPServerSendHTML(ClientCon, Response, "404 Not Found","Couldn't find that script.");
			LogToFile(Settings.LogPath,"No such script: %s in path %s = %s",Response->Path,Response->SearchPath,ScriptPath);
	}
	else if (
					(access(ScriptPath,X_OK) !=0) || 
					(! CheckScriptIntegrity(ScriptPath))
			)
	{
			HTTPServerSendHTML(ClientCon, Response, "403 Forbidden","You don't have permission for that.");
			LogToFile(Settings.LogPath,"Cannot execute script: %s",ScriptPath);
	}
	else
	{
		STREAMFlush(ClientCon);
		result=fork();
		if (result==0)
		{
			//do this so that when we exec the script, anything output goes to the client
			close(0);
			dup(ClientCon->in_fd);
			close(1);
			dup(ClientCon->out_fd);


      //Switch to Cgi/Default user. ALAYA WILL NOT RUN SCRIPTS AS ROOT!
      if (! SwitchUser(Settings.CgiUser))
      {
        LogToFile(Settings.LogPath,"ERROR: Failed to switch to user '%s' to execute script: %s using handler '%s'",Settings.CgiUser,ScriptPath,Tempstr);
        _exit(1);
      }

			if (geteuid()==0)
			{
				HTTPServerSendHTML(ClientCon, NULL, "403 Forbidden","Alaya will not run .cgi programs as 'root'.<br>\r\nTry setting 'Default User' in config file or command line.");
				LogToFile(Settings.LogPath, "Failed to switch user to '%s' for running a .cgi program. Will not run programs as 'root'. Set 'DefaultUser' in config file or command line.",Settings.CgiUser);
			}
			else
			{
				SetupEnvironment(Response);
	
				Response->ResponseCode=CopyStr(Response->ResponseCode,"200 OK");
				HTTPServerSendHeaders(ClientCon, Response, HEADERS_CGI);
				STREAMFlush(ClientCon);

				Tempstr=FindScriptHandlerForScript(Tempstr,ScriptPath);
				if (Tempstr) LogToFile(Settings.LogPath,"Execute script: %s using handler '%s'",ScriptPath,Tempstr);
				else LogToFile(Settings.LogPath,"Execute script: %s QUERY_STRING= '%s'",ScriptPath,getenv("QUERY_STRING"));

				//Only do this late! Otherwise logging won't work.
				for (i=3; i < 1000; i++) close(i);

				if (StrLen(Tempstr)) execl(Tempstr, Tempstr, ScriptPath,NULL);
				else execl(ScriptPath,ScriptPath,NULL);

				/*If this code gets executed, then 'execl' failed*/
				HTTPServerSendHTML(ClientCon, Response, "403 Forbidden","You don't have permission for that.");

				//Logging won't work after we've closed all the file descriptors!
				LogToFile(Settings.LogPath,"Cannot execute script: %s",ScriptPath);
		}
		_exit(0);
	}
	else
	{

	}
}


HTTPSessionDestroy(Response);
DestroyString(ScriptPath);
DestroyString(Tempstr);
DestroyString(Name);
DestroyString(Value);


//Always return false, so that pipe gets closed
return(FALSE);
}



void HandleGetFileRequest(STREAM *ClientCon, char *Data)
{
HTTPSession *Response;
char *Tempstr=NULL;
int result;


Response=ParseSessionInfo(Data);
result=fork();
if (result==0)
{
	Tempstr=FindFileInPath(Tempstr,Response->Path,Response->SearchPath);
	HTTPServerSendDocument(ClientCon, Response, Tempstr, HEADERS_SENDFILE|HEADERS_USECACHE|HEADERS_KEEPALIVE);
		
	STREAMFlush(ClientCon);
	_exit(0);
}

DestroyString(Tempstr);
}




void HandleIconRequest(STREAM *ClientCon, char *Data)
{
HTTPSession *Response;
char *Name=NULL, *Value=NULL, *ptr, *tptr;
char *Tempstr=NULL;
ListNode *Vars;
int result;

Response=ParseSessionInfo(Data);
Vars=ListCreate();
ptr=GetNameValuePair(Response->Arguments,"&","=",&Name,&Tempstr);
while (ptr)
{
	Value=HTTPUnQuote(Value,Tempstr);
	SetVar(Vars,Name,Value);
	if (strcasecmp(Name,"MimeType")==0)
	{
		tptr=GetToken(Value,"/",&Tempstr,0);
		SetVar(Vars,"MimeClass",Tempstr);
		SetVar(Vars,"MimeSub",tptr);
	}
	ptr=GetNameValuePair(ptr,"&","=",&Name,&Tempstr);
}


result=fork();
if (result==0)
{
	ptr=GetToken(Response->SearchPath,",",&Value,0);
	while (ptr)
	{
		Tempstr=SubstituteVarsInString(Tempstr,Value,Vars,0);
		if (access(Tempstr,R_OK)==0) break;
		ptr=GetToken(ptr,",",&Value,0);
	}
		
	HTTPServerSendDocument(ClientCon, Response, Tempstr, HEADERS_SENDFILE|HEADERS_USECACHE|HEADERS_KEEPALIVE);
	STREAMClose(ClientCon);
	_exit(0);
}

DestroyString(Name);
DestroyString(Value);
DestroyString(Tempstr);
}






int HandleProxyRequest(STREAM *ClientCon, char *Data)
{
HTTPSession *Response;
char *Tempstr=NULL;
int result;

Response=ParseSessionInfo(Data);
result=fork();
if (result==0)
{
	HTTPProxyRGETURL(ClientCon,Response);
	//void HTTPProxyConnect(STREAM *S,HTTPSession *ClientHeads);

		
	STREAMFlush(ClientCon);
	_exit(0);
}

DestroyString(Tempstr);

return(FALSE);
}


void HandleResolveIPRequest(STREAM *ClientCon, char *Data)
{
char *Tempstr=NULL;

//Can't use MCopyStr here because 'LookupHostIP' might return NULL,
//which would be taken as the last of the items in the string list
Tempstr=CopyStr(Tempstr,LookupHostIP(Data));
Tempstr=CatStr(Tempstr,"\n");

STREAMWriteLine(Tempstr,ClientCon);

DestroyString(Tempstr);
}


void HandleChildRegisterRequest(STREAM *S, char *Data)
{
char *Tempstr=NULL, *Host=NULL, *ptr;
int Flags=0;
time_t LastTime;

ptr=GetToken(Data,":",&Host,0);

if (*ptr=='A') Flags |= LOGIN_CHECK_ALLOWED;
if (*ptr=='I') Flags |= LOGGED_IN;
if (*ptr=='F') Flags |= LOGIN_FAIL;
if (*ptr=='C') Flags |= LOGIN_CHANGE;

ptr=GetVar(Settings.HostConnections,Host);

LastTime=time(NULL);
if (Flags & LOGIN_CHECK_ALLOWED) 
{
	if (ptr && (strcmp(ptr,"logout")==0))
	{
	SetVar(Settings.HostConnections,Host,"");
	STREAMWriteLine("logout\n",S);
	}
	else
	{
		STREAMWriteLine("okay\n",S);
	}
}
else if (Flags & LOGIN_CHANGE) 
{
	Tempstr=CopyStr(Tempstr,"logout");
	SetVar(Settings.HostConnections,Host,Tempstr);
	STREAMWriteLine("okay\n",S);
}
else
{
	if (Flags & LOGGED_IN) LastTime=0;
	Tempstr=FormatStr(Tempstr,"%ld",LastTime);
	SetVar(Settings.HostConnections,Host,Tempstr);
	STREAMWriteLine("okay\n",S);
}

STREAMFlush(S);

DestroyString(Tempstr);
DestroyString(Host);
}


void RunEventScript(STREAM *S, const char *Script)
{
	if (Spawn(Script,Settings.CgiUser,"",NULL) ==-1)
	{
        LogToFile(Settings.LogPath, "ERROR: Failed to run event script '%s'. Error was: %s",Script, strerror(errno));
	}
  else LogToFile(Settings.LogPath, "Script: '%s'. Error was: %s",Script, strerror(errno));
	STREAMWriteLine("okay\n",S);
}


int HandleChildProcessRequest(STREAM *S)
{
char *Tempstr=NULL, *Token=NULL, *ptr;
int result=TRUE;

Tempstr=STREAMReadLine(Tempstr,S);

if (! Tempstr) return(FALSE);

StripTrailingWhitespace(Tempstr);
LogToFile(Settings.LogPath, "HCPR: %s",Tempstr);

ptr=GetToken(Tempstr,"\\S",&Token,0);
if (strcmp(Token,"EXEC")==0) result=HandleExecRequest(S,ptr);
else if (strcmp(Token,"LOG")==0) LogToFile(Settings.LogPath,ptr);
else if (strcmp(Token,"GETF")==0) HandleGetFileRequest(S,ptr);
else if (strcmp(Token,"GETIP")==0) HandleResolveIPRequest(S,ptr);
else if (strcmp(Token,"REG")==0) HandleChildRegisterRequest(S,ptr);
else if (strcmp(Token,"PROXY")==0) result=HandleProxyRequest(S,ptr);
else if (strcmp(Token,"MIMEICON")==0) HandleIconRequest(S, ptr);
else if (strcmp(Token,"EVENT")==0) RunEventScript(S, ptr);
 
STREAMFlush(S);

DestroyString(Tempstr);
DestroyString(Token);

return(result);
}


int ChrootProcessRequest(STREAM *S, HTTPSession *Session, char *Type, char *Path, char *SearchPath)
{
char *Tempstr=NULL, *PortStr=NULL, *ContentLengthStr=NULL;
char *ResponseLine=NULL, *Headers=NULL, *ptr;
char *Quoted=NULL;
int KeepAlive=FALSE, RetVal=FALSE;
off_t ContentLength=0;
int PostArguments=FALSE;

if (! ParentProcessPipe) return(FALSE);
if ((strcmp(Type, "PROXY") != 0) && (strcmp(Session->Method,"POST") ==0)) PostArguments=TRUE;

PortStr=FormatStr(PortStr,"%d",Session->ServerPort);
ContentLengthStr=FormatStr(ContentLengthStr,"%d",Session->ContentSize);

//Trying to do this all as one string causes a problem!
Tempstr=MCopyStr(Tempstr,Type," Host='",Session->Host, "' ClientIP='",Session->ClientIP, "' ClientMAC='",Session->ClientMAC,"'",NULL);

Quoted=QuoteCharsInStr(Quoted,Session->URL,"'&");
Tempstr=MCatStr(Tempstr, " URL='",Quoted,"'",NULL);

Quoted=QuoteCharsInStr(Quoted,Path,"'&");
Tempstr=MCatStr(Tempstr, " Path='",Quoted,"'",NULL);

Quoted=QuoteCharsInStr(Quoted,SearchPath,"'&");
Tempstr=MCatStr(Tempstr, " SearchPath='",Quoted,"'",NULL);

Tempstr=MCatStr(Tempstr," Method=",Session->Method," UserAgent='",Session->UserAgent,"' ContentLength='",ContentLengthStr,"'",NULL);

if (StrLen(Session->ContentBoundary) > 2) Tempstr=MCatStr(Tempstr, " ContentType='",Session->ContentType, "; boundary=",Session->ContentBoundary+2, "'",NULL);
else Tempstr=MCatStr(Tempstr, " ContentType='",Session->ContentType,"'", NULL);

Tempstr=MCatStr(Tempstr," ServerName=",Session->ServerName," ServerPort=",PortStr,NULL);
if (StrLen(Session->Cipher)) Tempstr=MCatStr(Tempstr," Cipher='",Session->Cipher,"'",NULL);
if (StrLen(Session->Cookies)) Tempstr=MCatStr(Tempstr," Cookies='",Session->Cookies,"'",NULL);

Quoted=QuoteCharsInStr(Quoted,Session->StartDir,"'&");
Tempstr=MCatStr(Tempstr," StartDir='",Quoted,"'",NULL);

Quoted=QuoteCharsInStr(Quoted,Session->ClientReferrer,"'&");
Tempstr=MCatStr(Tempstr, " ClientReferrer='",Quoted,"'",NULL);

if (Session->Flags & SESSION_KEEP_ALIVE) Tempstr=CatStr(Tempstr," KeepAlive=Y");
if (StrLen(Session->UserName)) Tempstr=MCatStr(Tempstr," User='",Session->UserName,"'",NULL);
if (StrLen(Session->RemoteAuthenticate)) Tempstr=MCatStr(Tempstr," RemoteAuthenticate='",Session->RemoteAuthenticate,"'",NULL);

if (! PostArguments)
{
Quoted=QuoteCharsInStr(Quoted,Session->Arguments,"'&");
Tempstr=MCatStr(Tempstr, " Arguments='",Quoted,"'", NULL);
}

Tempstr=CatStr(Tempstr,"\n");


//if (Settings.Flags & FLAG_LOG_MORE_VERBOSE) 
LogToFile(Settings.LogPath,"REQUESTING DATA FROM OUTSIDE CHROOT: [%s]",Tempstr);
STREAMWriteLine(Tempstr,ParentProcessPipe);
STREAMFlush(ParentProcessPipe);


if (PostArguments && StrLen(Session->Arguments))
{
	//Wait till process outside of chroot responds to our request, (is ready)
	//then send it the post data
	while (STREAMCheckForBytes(ParentProcessPipe)==0) usleep(10000);
	STREAMWriteLine(Session->Arguments,ParentProcessPipe);

LogToFile(Settings.LogPath,"POST: [%s]",Session->Arguments);
	//we shouldn't need this CR-LF, as we've sent 'Content-Length' characters
	//but some CGI implementations seem to expect it, and it does no harm to
	//provide it anyway
	STREAMWriteLine("\r\n",ParentProcessPipe); 
	STREAMFlush(ParentProcessPipe);
}

//Handle Headers from CGI script
Headers=CopyStr(Headers,"");
ResponseLine=STREAMReadLine(ResponseLine,ParentProcessPipe);
StripTrailingWhitespace(ResponseLine);
if (StrLen(ResponseLine)) RetVal=TRUE;

Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
while (Tempstr)
{
	StripTrailingWhitespace(Tempstr);
	if (StrLen(Tempstr)==0) break;
	
	//Handle 'Status' header that changes the 1st Response line
	if (strncasecmp(Tempstr,"Status:",7)==0) 
	{
		ptr=Tempstr+7;
		while (isspace(*ptr) && (*ptr != '\0')) ptr++;
		ResponseLine=MCopyStr(ResponseLine, Session->Protocol, " ", ptr, NULL);
	}
	else if (strncasecmp(Tempstr,"Content-Length:",15)==0)
	{
		ptr=Tempstr+15;
		while (isspace(*ptr)) ptr++;
		ContentLength=(off_t) strtoull(ptr,NULL,10);
		Headers=MCatStr(Headers,Tempstr,"\r\n",NULL);
	}
	else if (strncasecmp(Tempstr,"Connection:",11)==0)
	{
		ptr=Tempstr+11;
		while (isspace(*ptr)) ptr++;
		if (strncasecmp(ptr,"Keep-Alive",10)==0) KeepAlive=TRUE;
		Headers=MCatStr(Headers,Tempstr,"\r\n",NULL);
	}
	else Headers=MCatStr(Headers,Tempstr,"\r\n",NULL);
	Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
}

//The second "\r\n" here will provide the blank line that marks the end
//of the headers

Tempstr=MCopyStr(Tempstr, ResponseLine,"\r\n",Headers,"\r\n",NULL);
STREAMWriteLine(Tempstr,S);

if (Settings.Flags & FLAG_LOG_MORE_VERBOSE) LogToFile(Settings.LogPath,"CGI HEADERS: [%s]",Tempstr);


//Read remaining data from CGI
STREAMSendFile(ParentProcessPipe, S, ContentLength,SENDFILE_KERNEL|SENDFILE_LOOP);
STREAMFlush(S);


//if we're running a cgi program, then it will close the session when done, so
//turn off the 'reuse session' flag
if (KeepAlive) Session->Flags |= SESSION_REUSE;
else Session->Flags &= ~(SESSION_KEEP_ALIVE | SESSION_REUSE);


DestroyString(Quoted);
DestroyString(Tempstr);
DestroyString(PortStr);
DestroyString(Headers);
DestroyString(ContentLengthStr);
DestroyString(ResponseLine);

return(RetVal);
}



void HTTPServerHandleVPath(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData)
{
char *Tempstr=NULL, *ptr;
char *Name=NULL, *Value=NULL;
char *LocalPath=NULL, *ExternalPath=NULL, *DocName=NULL;
ListNode *Vars;


Vars=ListCreate();
ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
while (ptr)
{
SetVar(Vars,Name,Value);
ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
}

DocName=SubstituteVarsInString(DocName,Session->Path+StrLen(VPath->URL),Vars,0);

ptr=GetToken(VPath->Path,":",&Tempstr,0);
while (ptr)
{
	if (*Tempstr=='/') ExternalPath=MCatStr(ExternalPath,Tempstr,":",NULL);
	else 
	{
		if (StrLen(Tempstr)==0) LocalPath=CatStr(LocalPath,"/:");
		else LocalPath=MCatStr(LocalPath,Tempstr,":",NULL);
	}
	ptr=GetToken(ptr,":",&Tempstr,0);
}

Tempstr=CopyStr(Tempstr,"");
if (StrLen(LocalPath)) Tempstr=FindFileInPath(Tempstr,DocName,LocalPath);

if (StrLen(Tempstr)) HTTPServerSendDocument(S, Session, Tempstr, HEADERS_SENDFILE|HEADERS_USECACHE|HEADERS_KEEPALIVE);
else if (StrLen(ExternalPath))
{
	LogToFile(Settings.LogPath,"%s@%s (%s) asking for external document %s in Search path %s", Session->UserName,Session->ClientHost,Session->ClientIP,DocName,ExternalPath);
	ChrootProcessRequest(S, Session, "GETF", DocName, ExternalPath);
}
//This will send '404'
else HTTPServerSendDocument(S, Session, DocName, HEADERS_SENDFILE|HEADERS_USECACHE|HEADERS_KEEPALIVE);

	DestroyString(Name);
	DestroyString(Value);
	DestroyString(DocName);
	DestroyString(Tempstr);
	DestroyString(LocalPath);
	DestroyString(ExternalPath);
}

void VPathMimeIcons(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData)
{
	LogToFile(Settings.LogPath,"%s@%s (%s) asking for external document %s in Search path %s", Session->UserName,Session->ClientHost,Session->ClientIP,"",VPath->Path);
	ChrootProcessRequest(S, Session, "MIMEICON", "", VPath->Path);
}


int HTTPServerHandleRegister(HTTPSession *Session, int Flags)
{
char *Tempstr=NULL, *Name=NULL, *Value=NULL, *ptr;
char *FlagChar="";
int result=FALSE;


	if (Flags & LOGGED_IN) FlagChar="I";
	if (Flags & LOGIN_FAIL) FlagChar="F";
	Tempstr=MCopyStr(Tempstr,"REG ",Session->ClientIP,":",FlagChar,"\n",NULL);

	//Override above tempstr if Logout value found
	if (Flags & LOGIN_CHANGE) Tempstr=MCopyStr(Tempstr,"REG ",Session->Path,":C\n",NULL);
	if (Flags & LOGIN_CHECK_ALLOWED) 
	{
		FlagChar="A";
		ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
		while (ptr)
		{
			if (Name && (strcmp(Name,"Logout")==0)) Tempstr=MCopyStr(Tempstr,"REG ",Value,":",FlagChar,"\n",NULL);
			ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
		}
	}

	
	STREAMWriteLine(Tempstr,ParentProcessPipe);
	STREAMFlush(ParentProcessPipe);

	Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
	if (strcmp(Tempstr,"okay\n")==0) result=TRUE;

DestroyString(Tempstr);
DestroyString(Name);
DestroyString(Value);

return(result);
}
