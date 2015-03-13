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
	switch (Node->ItemType)
	{
			case EVENT_RESPONSE:
			if (StrLen(Session->ResponseCode))
			{
			if (strncmp(Token,Session->ResponseCode,3) ==0) 
			{
				*MatchStr=MCatStr(*MatchStr, "Response: ",Session->ResponseCode,", ",NULL);
				result=TRUE;
			}
			}
			break;
		
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
			if (Session->Flags & SESSION_ERR_BADURL)
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
	int result;

		LogToFile(Settings.LogPath, "EVENT TRIGGERED: Source='%s@%s (%s)' REQUEST='%s' TriggeredScript='%s' MatchInfo='%s'",Session->UserName, Session->ClientHost, Session->ClientIP, URL, TriggerScript, ExtraInfo);
	
		if (ParentProcessPipe)
		{
			Tempstr=MCopyStr(Tempstr, "EVENT ", TriggerScript, " '", Session->ClientIP,"' '", URL, "' '", ExtraInfo, "'\n",NULL);
			STREAMWriteLine(Tempstr,ParentProcessPipe);
			STREAMFlush(ParentProcessPipe);
			Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
		}
  	else 
		{
			Tempstr=MCopyStr(Tempstr, TriggerScript, " '", Session->ClientIP,"' '", URL, "'",NULL);

			if (getuid()==0) result=Spawn(Tempstr,Settings.DefaultUser,Settings.DefaultGroup,NULL);
			else result=Spawn(Tempstr,NULL,NULL,NULL);

			if (result==-1)
			{
				LogToFile(Settings.LogPath, "ERROR: Failed to run event script '%s'. Error was: %s", TriggerScript, strerror(errno));
			}
		}

	DestroyString(Tempstr);
}



//This function will always be called by the process handling a particular session, so changes
//to values like "Settings.AuthMethods" will only effect that session
void ProcessSessionEventTriggers(HTTPSession *Session)
{
ListNode *Curr;
char *Tempstr=NULL, *URL=NULL, *MatchStr=NULL;
char *Token=NULL, *ptr;

Curr=ListGetNext(Settings.Events);
while (Curr)
{	
		Tempstr=MCopyStr(Tempstr,Session->Method," ",Session->URL,NULL);
		URL=QuoteCharsInStr(URL,Tempstr,"'$;");

	if (EventTriggerMatch(Curr, Session, &MatchStr))
	{
		ptr=GetToken((char *) Curr->Item,",",&Token,GETTOKEN_QUOTES);
		while (ptr)
		{
    	if (strcasecmp(Token,"ignore")==0)
			{
				Curr=NULL;
				break;
			}
      else if (strcasecmp(Token,"log")==0) LogToFile(Settings.LogPath,"WARN: Event Rule encountered (%s on %s).",MatchStr,Tempstr);
      else if (strcasecmp(Token,"syslog")==0) syslog(LOG_WARNING, "WARN: Event Rule encountered (%s on %s).",MatchStr,Tempstr);
			else if (strcasecmp(Token,"deny") ==0)
			{
				LogToFile(Settings.LogPath,"WARN: 'Deny' Event Rule encountered (%s on %s). Denying Authentication",MatchStr,Tempstr);
				Settings.AuthMethods=CopyStr(Settings.AuthMethods, "deny");
			}
			else ProcessEventTrigger(Session, Tempstr, Token, MatchStr);
			ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
		}
	}
	Curr=ListGetNext(Curr);
}

DestroyString(MatchStr);
DestroyString(Tempstr);
DestroyString(Token);
DestroyString(URL);
}



