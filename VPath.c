
/**********************************************************************
This module relates to 'Virtual Paths' or 'VPaths. These are URLs that
trigger special processing, and are often used to allow access to some
directories outside of a chroot jail.  For instance, a VPath of type 
'Path' creates a virtual directory that maps to a real directory, and 
that real directory can be outside of chroot. A VPath of type 'cgi' 
creates a search path of directories whose contents are treated as 
programs or scripts to be run. Again, these directories can be outside 
of chroot. Finally some values, like cache time, can be set on a VPath.
**********************************************************************/



#include "VPath.h"
#include "server.h"



char *HTTPServerSubstituteArgs(char *RetStr, const char *Template, HTTPSession *Session)
{
ListNode *Vars;
char *Name=NULL, *Value=NULL, *ptr;


Vars=ListCreate();
ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
while (ptr)
{
SetVar(Vars,Name,Value);
ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
}

RetStr=SubstituteVarsInString(RetStr, Template, Vars, 0);

ListDestroy(Vars, DestroyString);
DestroyString(Name);
DestroyString(Value);


return(RetStr);
}


void VPathHandleFilePath(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData)
{
char *Tempstr=NULL, *ptr;
char *LocalPath=NULL, *ExternalPath=NULL, *DocName=NULL;

//Document name here is whatever part of the Path is *beyond* the VPath component
LogToFile(Settings.LogPath,"SA: [%s] [%s]", Session->URL, VPath->URL);
DocName=HTTPServerSubstituteArgs(DocName, Session->Path+StrLen(VPath->URL), Session);


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
	LogToFile(Settings.LogPath,"%s@%s (%s) asking for external document %s in Search path %s  %d", Session->UserName,Session->ClientHost,Session->ClientIP,DocName,ExternalPath,Session->Flags & SESSION_KEEP_ALIVE);
	ChrootProcessRequest(S, Session, "GETF", DocName, ExternalPath);
}
//This will send '404'
else HTTPServerSendDocument(S, Session, DocName, HEADERS_SENDFILE|HEADERS_USECACHE|HEADERS_KEEPALIVE);

DestroyString(DocName);
DestroyString(Tempstr);
DestroyString(LocalPath);
DestroyString(ExternalPath);
}



void VPathMimeIcons(STREAM *S,HTTPSession *Session, TPathItem *VPath, int SendData)
{
	LogToFile(Settings.LogPath,"%s@%s (%s) asking for external document %s in Search path %s", Session->UserName,Session->ClientHost,Session->ClientIP,"",VPath->Path);
	if (VPath->CacheTime) Session->CacheTime=VPath->CacheTime;
	ChrootProcessRequest(S, Session, "MIMEICON", "", VPath->Path);
}




//This function checks the Paths configured in the server for virtual 
//documents like cgi scripts or streams, or for directories to which we
//are allowed access from outside chroot
int VPathProcess(STREAM *S, HTTPSession *Session, int Flags)
{
ListNode *Curr=NULL, *Default=NULL;
TPathItem *PI=NULL;
char *Path=NULL, *Tempstr=NULL, *ptr;
HTTPSession *VPathSession=NULL;
int result=FALSE;

	
LogToFile(Settings.LogPath,"VP: %d ",Session->Flags & SESSION_KEEP_ALIVE);
	Curr=ListGetNext(Settings.VPaths);
	while (Curr)
	{
		if (StrLen(Curr->Tag) < 2) Default=Curr;
		else if (strncmp(Session->Path,Curr->Tag,StrLen(Curr->Tag))==0) break;
		Curr=ListGetNext(Curr);
	}

	//If Curr is set then we found a VPath
	if (! Curr) Curr=Default;

	if (! Curr) return(FALSE);

	if (Curr)
	{
		VPathSession=HTTPSessionClone(Session);
		PI=(TPathItem *) Curr->Item;
		result=TRUE;

		//Some things are configureable on a VPath basis. Set those up.
		if (PI->CacheTime) VPathSession->CacheTime=PI->CacheTime;
		if (StrLen(PI->User)) VPathSession->RealUser=CopyStr(VPathSession->RealUser, PI->User);
		if (StrLen(PI->Group)) VPathSession->Group=CopyStr(VPathSession->Group, PI->Group);

	

		if (Flags & HEADERS_POST) HTTPServerHandlePost(S,Session,PI->Type);
		LogToFile(Settings.LogPath,"APPLYING VPATH: %d [%s] -> [%s]",PI->Type,Curr->Tag,PI->Path);
		switch (PI->Type)
		{
			case PATHTYPE_CGI:
			LogToFile(Settings.LogPath,"CGI EXEC REQUEST: Script='%s' Path='%s'",GetBasename(Session->Path), PI->Path);
			ChrootProcessRequest(S, VPathSession, "EXEC", GetBasename(VPathSession->Path), PI->Path);
			break;

			case PATHTYPE_EXTFILE:
			VPathHandleFilePath(S,VPathSession,PI,Flags);
			break;

			case PATHTYPE_STREAM:
			HTTPServerHandleStream(S,VPathSession,PI->Path,Flags);
			break;

			case PATHTYPE_LOGOUT:
			VPathSession->Path=FormatStr(VPathSession->Path,"%d-%d-%d",getpid(),time(NULL),rand());
			HTTPServerHandleRegister(VPathSession, LOGIN_CHANGE);
			Path=FormatURL(Path, VPathSession, "/");
			Path=MCatStr(Path,"?Logout=",VPathSession->Path,NULL);
			VPathSession->Flags &= ~SESSION_KEEP_ALIVE; 
			HTTPServerSendResponse(S, VPathSession, "302", "", Path);
			break;

			case PATHTYPE_URL:
			ChrootProcessRequest(S, VPathSession, "PROXY", PI->Path, "");
			break;

			case PATHTYPE_PROXY:
			if (StrLen(VPathSession->UserName)) 
			{
				Path=MCopyStr(Path,VPathSession->UserName,":",VPathSession->Password,NULL);
				Tempstr=EncodeBytes(Tempstr, Path, StrLen(Path), ENCODE_BASE64);
				VPathSession->RemoteAuthenticate=MCopyStr(VPathSession->RemoteAuthenticate,"Basic ",Tempstr,NULL);	
			}
			Path=MCopyStr(Path,PI->Path,VPathSession->Path+StrLen(PI->URL),NULL);
			ChrootProcessRequest(S, VPathSession, "PROXY", Path, "");
			break;

			case PATHTYPE_MIMEICONS:
			VPathMimeIcons(S,VPathSession, PI, Flags);
			break;

			default:
				//We didn't find a VPATH to handle this, so return false
			 result=FALSE;
			break;
		}

//		HTTPSessionDestroy(VPathSession);
	}


DestroyString(Tempstr);
DestroyString(Path);

return(result);
}

