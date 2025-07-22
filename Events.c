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
    char *Token=NULL;
    const char *ptr;
    int result=FALSE;

    ptr=GetToken(Node->Tag,",",&Token,0);
    while (ptr)
    {
        switch (Node->ItemType)
        {
        case EVENT_RESPONSE:
            if (StrValid(Session->ResponseCode))
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

        case EVENT_AUTH:
            if (Session->AuthFlags & FLAG_AUTH_PRESENT)
            {
                if ( (CompareStrNoCase(Token, "fail")==0) && (Session->Flags & SESSION_AUTH_FAIL) )
                {
                    *MatchStr=MCatStr(*MatchStr, "Auth Fail: ", NULL);
                    result=TRUE;
                }

                if ( (CompareStrNoCase(Token, "okay")==0) && (Session->Flags & SESSION_AUTHENTICATED) )
                {
                    *MatchStr=MCatStr(*MatchStr, "Authenticated ", NULL);
                    result=TRUE;
                }
            }
            break;


        case EVENT_HEADER:
            if (EventHeadersMatch(Token,Session,MatchStr)) result=TRUE;
            break;

        case EVENT_UPLOAD:
            if ( (Session->Flags & SESSION_UPLOAD_DONE) && (fnmatch(Token, Session->Path, 0)==0) )
            {
                *MatchStr=MCatStr(*MatchStr, "Dest: ",Session->Path,", ",NULL);
                result=TRUE;
            }
            break;
        }

        ptr=GetToken(ptr,",",&Token,0);
    }


    Destroy(Token);

    return(result);
}



void ProcessEventScript(HTTPSession *Session, const char *URL, const char *TriggerScript, const char *ExtraInfo, ListNode *Vars)
{
    char *Tempstr=NULL, *Command=NULL, *ptr;
    int result;

    LogToFile(Settings.LogPath, "EVENT TRIGGERED: Source='%s@%s (%s)' REQUEST='%s' TriggeredScript='%s' MatchInfo='%s'",Session->UserName, Session->ClientHost, Session->ClientIP, URL, TriggerScript, ExtraInfo);

    if (ParentProcessPipe)
    {
        Tempstr=MCopyStr(Tempstr, "EVENT ", TriggerScript,"\n",NULL);
        STREAMWriteLine(Tempstr,ParentProcessPipe);
        STREAMFlush(ParentProcessPipe);
        Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
    }
    else
    {
        Command=MCopyStr(Command, TriggerScript,"\n",NULL);

        if (getuid()==0)
        {
            if (StrValid(Settings.DefaultGroup)) Tempstr=MCopyStr(Tempstr,"group=",Settings.DefaultGroup,NULL);
            if (StrValid(Settings.DefaultUser)) Tempstr=MCopyStr(Tempstr,"user=",Settings.DefaultUser,NULL);
        }
        result=Spawn(Command,Tempstr);

        if (result==-1)
        {
            LogToFile(Settings.LogPath, "ERROR: Failed to run event script '%s'. Error was: %s", TriggerScript, strerror(errno));
        }
    }

    Destroy(Command);
    Destroy(Tempstr);
}



void ProcessEventTrigger(HTTPSession *Session, const char *URL, const char *Trigger, const char *ExtraInfo, ListNode *Vars)
{
    char *Type=NULL, *Token=NULL, *Tempstr=NULL, *LogStr=NULL;
    const char *ptr;

    LogToFile(Settings.LogPath,"TRIGGER: %s\n",Trigger);
    Tempstr=SubstituteVarsInString(Tempstr, Trigger, Vars, 0);
    StripTrailingWhitespace(Tempstr);
    ptr=GetToken(Tempstr,"\\S",&Type,GETTOKEN_QUOTES);

    LogStr=FormatStr(LogStr, "WARN: Event Rule encountered (%s on %s).",ExtraInfo,URL);

    if (strcasecmp(Type,"log")==0)
    {
        if (StrValid(ptr)) LogStr=CopyStr(LogStr, ptr);
        LogToFile(Settings.LogPath,"%s",LogStr);
    }
    else if (strcasecmp(Type,"logfile")==0)
    {
        ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
        if (StrValid(ptr)) LogStr=CopyStr(LogStr, ptr);
        LogToFile(Token,"%s",LogStr);
    }
    else if (strcasecmp(Type,"syslog")==0)
    {
        if (StrValid(ptr)) LogStr=CopyStr(LogStr, ptr);
        syslog(LOG_WARNING, "%s from %s@%s",LogStr, Session->UserName, Session->ClientIP);
    }
    else if (strcasecmp(Type,"deny") ==0)
    {
        if (StrValid(ptr)) LogStr=CopyStr(LogStr, ptr);
        LogToFile(Settings.LogPath,"WARN: 'Deny' Event Rule encountered (%s on %s). Denying Authentication",ExtraInfo,URL);
        Settings.AuthMethods=CopyStr(Settings.AuthMethods, "deny");
        Session->Flags &= ~SESSION_AUTHENTICATED;
    }
    else ProcessEventScript(Session, URL, Tempstr, ExtraInfo, Vars);

    Destroy(Type);
    Destroy(Token);
    Destroy(LogStr);
    Destroy(Tempstr);
}


//This function will always be called by the process handling a particular session, so changes
//to values like "Settings.AuthMethods" will only effect that session
void ProcessSessionEventTriggers(HTTPSession *Session)
{
    ListNode *Curr;
    char *Tempstr=NULL, *URL=NULL, *MatchStr=NULL;
    char *Token=NULL;
    const char *ptr;
    ListNode *Vars;

    Vars=ListCreate();
    SetVar(Vars,"URL",Session->URL);
    SetVar(Vars,"Path",Session->Path);
    SetVar(Vars,"Method",Session->Method);
    SetVar(Vars,"UserName",Session->UserName);
    SetVar(Vars,"ClientIP",Session->ClientIP);
    SetVar(Vars,"UserAgent",Session->UserAgent);
    Curr=ListGetNext(Settings.Events);
    while (Curr)
    {
        Tempstr=MCopyStr(Tempstr,Session->Method," ",Session->URL,NULL);
        URL=QuoteCharsInStr(URL,Tempstr,"'$;`");

        if (EventTriggerMatch(Curr, Session, &MatchStr))
        {
            SetVar(Vars,"Match",MatchStr);

            //get actions for event. There are a comma-separated list. process each one thorugh ProcessEventTrigger
            ptr=GetToken((char *) Curr->Item,",",&Token,GETTOKEN_QUOTES);
            while (ptr)
            {
                //if we hit an ignore, don't continue
                if (strcasecmp(Token,"ignore")==0)
                {
                    Curr=NULL;
                    break;
                }
                ProcessEventTrigger(Session, Tempstr, Token, MatchStr, Vars);


                ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
            }
        }
        Curr=ListGetNext(Curr);
    }

    ListDestroy(Vars,Destroy);
    Destroy(MatchStr);
    Destroy(Tempstr);
    Destroy(Token);
    Destroy(URL);
}



