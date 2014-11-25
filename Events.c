#include "Events.h"

extern STREAM *ParentProcessPipe;

int EventHeadersMatch(char *TriggerMatch, HTTPSession *Session, char **MatchStr)
{
ListNode *Curr;

Curr=ListGetNext(Session->Headers);
while (Curr)
{
		if (fnmatch(TriggerMatch,Curr->Item,0) ==0)
		{
			*MatchStr=MCatStr(*MatchStr, "Header: ",Curr->Item,", ",NULL);
			return(TRUE);
		}

Curr=ListGetNext(Curr);
}


return(FALSE);
}



int EventTriggerMatch(ListNode *Node, HTTPSession *Session, char **MatchStr)
{
char *Token=NULL, *ptr;
int result=FALSE;

ptr=GetToken(Node->Tag,",",&Token,0);
while (ptr)
{
	if (StrLen(Session->ResponseCode))
	{
		if (Node->ItemType == EVENT_RESPONSE)
		{
			if (strncmp(Token,Session->ResponseCode,3) ==0) 
			{
				*MatchStr=MCatStr(*MatchStr, "Response: ",Session->ResponseCode,", ",NULL);
				result=TRUE;
			}
		}
	}
	else switch (Node->ItemType)
	{
			case EVENT_METHOD:
			if (strcmp(Token,Session->Method) ==0) 
			{
				*MatchStr=MCatStr(*MatchStr, "Method: ",Session->Method,", ",NULL);
				result=TRUE;
			}
			break;

			case EVENT_PATH:
			if (fnmatch(Token,Session->Path,0) ==0)
			{
				*MatchStr=MCatStr(*MatchStr, "URL: ",Session->Path,", ",NULL);
				result=TRUE;
			}
			break;
	
			case EVENT_USER:
			if (fnmatch(Token,Session->UserName,0) ==0) 
			{
				*MatchStr=MCatStr(*MatchStr, "User: ",Session->UserName,", ",NULL);
				result=TRUE;
			}
			break;
	
			case EVENT_PEERIP:
			if (fnmatch(Token,Session->ClientIP,0) ==0)
			{
				*MatchStr=MCatStr(*MatchStr, "Peer: ",Session->ClientIP,", ",NULL);
				result=TRUE;
			}
			break;

			case EVENT_BADURL:
			if (Session->Flags & HTTP_ERR_BADURL)
			{
				*MatchStr=MCatStr(*MatchStr, "Bad URL: ",Session->Path,", ",NULL);
				result=TRUE;
			}
			break;

			case EVENT_HEADER:
			if (EventHeadersMatch(Token,Session,MatchStr)) result=TRUE;
			break;
	}
	ptr=GetToken(ptr,",",&Token,0);
}


DestroyString(Token);

return(result);
}



void ProcessEventTrigger(HTTPSession *Session, char *URL, char *TriggerScript, char *ExtraInfo)
{
	char *Tempstr=NULL;

		LogToFile(Settings.LogPath, "EVENT TRIGGERED: ClientIP='%s' REQUEST='%s' TriggeredScript='%s' MatchInfo=%s",Session->ClientIP, URL, TriggerScript, ExtraInfo);
	
		if (ParentProcessPipe)
		{
			Tempstr=MCopyStr(Tempstr, "EVENT ", TriggerScript, " '", Session->ClientIP,"' '", URL, "'\n",NULL);
			STREAMWriteLine(Tempstr,ParentProcessPipe);
			STREAMFlush(ParentProcessPipe);
			Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
		}
  	else 
		{
			Tempstr=MCopyStr(Tempstr, TriggerScript, " '", Session->ClientIP,"' '", URL, "'",NULL);
			if (Spawn(Tempstr,Settings.DefaultUser,Settings.DefaultGroup,NULL) ==-1)
			{
			LogToFile(Settings.LogPath, "ERROR: Failed to run event script '%s'. Error was: %s", TriggerScript, strerror(errno));
			}
		}

	DestroyString(Tempstr);
}



int ProcessSessionEventTriggers(HTTPSession *Session)
{
ListNode *Curr;
char *Tempstr=NULL, *URL=NULL, *MatchStr=NULL;

Curr=ListGetNext(Settings.Events);
while (Curr)
{	
		Tempstr=MCopyStr(Tempstr,Session->Method," ",Session->URL,NULL);
		URL=QuoteCharsInStr(URL,Tempstr,"'$;");

	if (EventTriggerMatch(Curr, Session, &MatchStr))
	{
		ProcessEventTrigger(Session, Tempstr, Curr->Item, MatchStr);
	}
	Curr=ListGetNext(Curr);
}

DestroyString(MatchStr);
DestroyString(Tempstr);
DestroyString(URL);
}



