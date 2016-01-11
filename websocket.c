#include "websocket.h"
#include "server.h"

//WebsocketKey is stored in 'ContentBoundary' field
//WebsocketProtocol goes in 'ContentType' field

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WEBSOCKET_FIN  1024
#define WEBSOCKET_MASK 2048
#define WEBSOCKET_CLOSE 8


typedef struct
{
#ifdef BIG_END
unsigned int Masked: 1;
unsigned int Len: 7;
unsigned int OpCode: 4;
unsigned int R3 : 1;
unsigned int R2 : 1;
unsigned int R1 : 1;
unsigned int Fin: 1;
#else
unsigned int OpCode: 4;
unsigned int R1:  1;
unsigned int R2:  1;
unsigned int R3:  1;
unsigned int Fin: 1;
unsigned int Len: 7;
unsigned int Masked: 1;
#endif

} TWSHeader;


char *WebsocketFindMatchingHelper(const char *Path, const char *Protocols)
{
ListNode *Curr;
char *ptr, *p_Proto, *Token=NULL;

Curr=ListGetNext(Settings.ScriptHandlers);
while (Curr)
{
	if (Curr->ItemType==PATHTYPE_WEBSOCKET)
	{
		//<path>:<proto>
		p_Proto=GetToken(Curr->Tag,":",&Token,0);
		if (fnmatch(Token,Path,0)==0)
		{
			ptr=GetToken(Protocols," ",&Token,0);
			while (ptr)
			{
			if (strcasecmp(p_Proto, Token)==0)
			{
				DestroyString(Token);
				return(Curr->Item);
			}
			ptr=GetToken(ptr," ",&Token,0);
			}
		}
	}

Curr=ListGetNext(Curr);
}

DestroyString(Token);
return(NULL);
}


unsigned int WebsocketReadHeader(STREAM *S, int *len, int *mask)
{
unsigned int OpCode=0;
uint16_t val;
TWSHeader Head;

STREAMReadBytes(S, (char *) &Head,2);
OpCode=Head.OpCode;

if (Head.Fin)  OpCode |= WEBSOCKET_FIN;
if (Head.Masked)  OpCode |= WEBSOCKET_MASK;
fprintf(stderr,"XX: %d %d %d %u\n",Head.Fin, Head.Masked, Head.OpCode, Head.Len);

if (Head.Len==126) 
{
STREAMReadBytes(S,&val,2);
*len=ntohs(val);
}
else *len=Head.Len;

if (OpCode & WEBSOCKET_MASK) STREAMReadBytes(S,mask,4);


return(OpCode);
}


void WebsocketReadData(STREAM *S, STREAM *Out, int len, int mask)
{
int result, data;

while (len > 0)
{
	if (len > 4) result=STREAMReadBytes(S, &data, 4);
	else result=STREAMReadBytes(S, &data, len);

	data = data ^ mask;

	STREAMWriteBytes(Out, & data, result);
	len-=result;
}

}


void WebsocketWriteData(STREAM *S, const char *Data, int len, int mask, int flags)
{
TWSHeader Head;
char *Tempstr=NULL, *ptr;
uint16_t val;

memset(&Head,0,2);
if (flags & WEBSOCKET_FIN) Head.Fin=1;

if (len > 125) Head.Len=126;
else Head.Len=len;
Head.OpCode=1;
//if (flags & WEBSOCKET_MASK) Tempstr[1] |= 0x1;

STREAMWriteBytes(S, &Head, 2);
if (len > 125) 
{
	val=htons(len);
	STREAMWriteBytes(S, &val, 2);
}

STREAMWriteBytes(S, Data, len);

DestroyString(Tempstr);
}



void WebsocketTransact(STREAM *Client, HTTPSession *Session, const char *Helper)
{
int OpCode, len, mask;
char *Tempstr=NULL;
STREAM *Prog;
ListNode *Streams, *S;

	Streams=ListCreate();
	Prog=ChrootSendRequest(Session, "WEBSOCKET", Helper, "/bin:/usr/bin");
	ListAddItem(Streams, Prog);
	ListAddItem(Streams, Client);
	do
	{
		S=STREAMSelect(Streams, NULL);

		if (S==Client)
		{
			OpCode=WebsocketReadHeader(Client, &len, &mask);
			WebsocketReadData(Client, Prog, len, mask);
			if (OpCode & WEBSOCKET_FIN) STREAMFlush(Prog);
		}

		if (S==Prog)
		{
			Tempstr=STREAMReadLine(Tempstr, Prog);
			WebsocketWriteData(Client, Tempstr, StrLen(Tempstr), 0, WEBSOCKET_FIN);
			STREAMFlush(Client);
		}
	} while((OpCode & 0xFF) != WEBSOCKET_CLOSE);
	STREAMClose(Prog);

	ListDestroy(Streams, NULL);
DestroyString(Tempstr);
}


unsigned long WebsocketProcessKeyPart(const char *Key)
{
int spaces=0, len=0;
char *Tempstr=NULL;
const char *ptr;
unsigned long long val;

for (ptr=Key; *ptr !='\0'; ptr++)
{
	switch (*ptr)
	{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			Tempstr=AddCharToBuffer(Tempstr, len, *ptr);
			len++;
		break;

		case ' ':
			spaces++;
		break;
	}
}

val=strtoll(Tempstr, NULL, 10) / spaces;

DestroyString(Tempstr);

return(val);
}



void Websocket2PartKey(STREAM *S, HTTPSession *Session, char **Key)
{
unsigned long v1, v2;
char *String=NULL;

String=SetStrLen(String,16);
v1=htonl(WebsocketProcessKeyPart(Session->ContentBoundary));
v2=htonl(WebsocketProcessKeyPart(Session->Cookies));


memcpy(String,&v1,4);
memcpy(String+4,&v2,4);
STREAMReadBytes(S, String+8,8);
HashBytes(Key, "md5", String, 16, ENCODE_BASE64);

DestroyString(String);
}



int WebsocketConnect(STREAM *S, HTTPSession *Session)
{
char *Tempstr=NULL, *Key=NULL, *Helper=NULL;
HTTPSession *Response;
int val;

Response=HTTPSessionCreate();
Response->MethodID=METHOD_WEBSOCKET;
SetVar(Response->Headers,"Sec-WebSocket-Protocol",Session->ContentType);
//SetVar(Response->Headers,"Sec-WebSocket-Origin", "file://");
Helper=CopyStr(Helper, WebsocketFindMatchingHelper(Session->Path, Session->ContentType));
if (StrLen(Helper))
{
	if (Session->MethodID==METHOD_WEBSOCKET75) 
	{
	Websocket2PartKey(S, Session, &Key);
	}
	else 
	{
	Tempstr=MCopyStr(Tempstr, Session->ContentBoundary, WEBSOCKET_GUID, NULL);
	HashBytes(&Key, "sha1", Tempstr, StrLen(Tempstr), ENCODE_BASE64);
	SetVar(Response->Headers,"Sec-WebSocket-Accept",Key);
	}

	Response->ResponseCode=CopyStr(Response->ResponseCode, "101 Switching Protocols");
	HTTPServerSendHeaders(S, Response, HEADERS_KEEPALIVE);
	STREAMWriteLine("\r\n",S);
	if (Session->MethodID==METHOD_WEBSOCKET75)
	{
	Tempstr=SetStrLen(Tempstr,40);
	val=from64tobits(Tempstr, Key);
	STREAMWriteBytes(S, Tempstr, val);
	}
	STREAMFlush(S);

	WebsocketTransact(S, Session, Helper);
}
else
{
HTTPServerSendResponse(S, Session, "404 Not Found","","");
}

HTTPSessionDestroy(Response);

DestroyString(Tempstr);
DestroyString(Helper);
DestroyString(Key);
}

