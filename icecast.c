#include "icecast.h"


static HTTPSession *IcecastCreateSession(const char *Path, HTTPSession *Request, ListNode *Vars, int ICYInterval)
{
  HTTPSession *Session;
  char *Tempstr=NULL;

  Session=HTTPSessionResponse(Request);
  Session->ResponseCode=CopyStr(Session->ResponseCode,"200 OK");
  Session->ContentType=CopyStr(Session->ContentType,GetVar(Vars,"ContentType"));
  Session->LastModified=atoi(GetVar(Vars,"MTime-secs"));
  Session->ContentSize=atoi(GetVar(Vars,"FileSize"));

  Session->Flags |= SESSION_ICECAST;
  Session->Protocol=CopyStr(Session->Protocol,"ICY");
  Tempstr=FormatStr(Tempstr,"%d",ICYInterval);
  SetVar(Session->Headers,"icy-metaint",Tempstr);

  Destroy(Tempstr);
  return(Session);
}



static void IcecastSendMessage(STREAM *Output, const char *ICYMessage)
{
uint8_t len;
char *Tempstr=NULL;

	len=StrLen(ICYMessage);
	if (len > 0) len=(len / 16) + 1;
	Tempstr=SetStrLen(Tempstr,len * 16);
	memset(Tempstr,0,len * 16);
	strcpy(Tempstr,ICYMessage);
	STREAMWriteBytes(Output,(char *) &len,1);
	STREAMWriteBytes(Output,Tempstr,len * 16);

Destroy(Tempstr);
}




static void IcecastSendData(STREAM *Input, STREAM *Output, int ICYInterval)
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
			IcecastSendMessage(Output, ICYMessage);
			//Don't send it again.
			ICYMessage=CopyStr(ICYMessage,"");
		}	
	}

ListDestroy(Vars,Destroy);
Destroy(ICYMessage);
Destroy(Tempstr);
}



void IcecastHandleStream(STREAM *Output, HTTPSession *Session, const char *SearchPath)
{
char *Tempstr=NULL;
HTTPSession *Response;
ListNode *Vars;
STREAM *S;
glob_t Glob;
int ICYInterval=4096000;
int i;


Vars=ListCreate();
SetVar(Vars,"ContentType","audio/mpeg");
Response=IcecastCreateSession("", Session, Vars, 0);
HTTPServerSendHeaders(Output, Response, FALSE);
STREAMFlush(Output);

Tempstr=MCopyStr(Tempstr,SearchPath,"/*",NULL);
glob(Tempstr,0,0,&Glob);

LogToFile(Settings.LogPath,"Stream from Dir: %s, %d files",SearchPath,Glob.gl_pathc);

for (i=0; i < Glob.gl_pathc; i++)
{
	S=STREAMFileOpen(Glob.gl_pathv[i],SF_RDONLY);
	if (S)
	{
		IcecastSendData(S, Output, 4096000);
		STREAMClose(S);
	}
}

globfree(&Glob);
Destroy(Tempstr);
ListDestroy(Vars,Destroy);
}


