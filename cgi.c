#include "cgi.h"
#include "server.h"

int CGIExecProgram(STREAM *ClientCon, HTTPSession *Session, const char *ScriptPath)
{
    char *Tempstr=NULL;
    int i;

    if (StrValid(Session->Group) && (! SwitchGroup(Session->Group)))
    {
        LogToFile(Settings.LogPath,"WARN: Failed to switch to group '%s' to execute script: %s", Session->Group, ScriptPath);
    }


    //Switch user. ALAYA WILL NOT RUN SCRIPTS AS ROOT!
    if ((geteuid()==0) && (! SwitchUser(Session->RealUser)))
    {
        LogToFile(Settings.LogPath,"ERROR: Failed to switch to user '%s' to execute script: %s", Session->RealUser, ScriptPath);
        return(FALSE);
    }

    if (geteuid()==0)
    {
        HTTPServerSendHTML(ClientCon, NULL, "403 Forbidden","Alaya will not run .cgi programs as 'root'.<br>\r\nTry setting 'Default User' in config file or command line.");
        LogToFile(Settings.LogPath, "Failed to switch user to '%s' for running a .cgi program. Will not run programs as 'root'. Set 'DefaultUser' in config file or command line.", Session->RealUser);
    }
    else
    {
        Session->ResponseCode=CopyStr(Session->ResponseCode,"200 OK");
        HTTPServerSendHeaders(ClientCon, Session, HEADERS_CGI);
        STREAMFlush(ClientCon);

        SetupEnvironment(Session, ScriptPath);
        Tempstr=FindScriptHandlerForScript(Tempstr,ScriptPath);
        if (Tempstr) LogToFile(Settings.LogPath,"Execute script: %s using handler '%s'",ScriptPath,Tempstr);
        else LogToFile(Settings.LogPath,"Execute script: %s QUERY_STRING= '%s'",ScriptPath,getenv("QUERY_STRING"));

        //Only do this late! Otherwise logging won't work.
        for (i=3; i < 1000; i++) close(i);

        if (StrValid(Tempstr)) execl(Tempstr, Tempstr, ScriptPath,NULL);
        else execl(ScriptPath,ScriptPath,NULL);

        /*If this code gets executed, then 'execl' failed*/
        HTTPServerSendHTML(ClientCon, Session, "403 Forbidden","You don't have permission for that.");

        //Logging won't work after we've closed all the file descriptors!
        LogToFile(Settings.LogPath,"Cannot execute script: %s",ScriptPath);
    }

    //if we get there then, for whatever reason, our script didn't run
    Destroy(Tempstr);
    return(FALSE);
}



