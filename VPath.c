
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

void VPathParse(ListNode *List, const char *PathType, const char *Data)
{
const char *PathTypes[]={"Files","Cgi","Websocket","Stream","Logout","Proxy","MimeIcons","FileType",NULL};
char *URL=NULL, *Path=NULL, *Tempstr=NULL;
char *User=NULL, *Group=NULL, *Password=NULL;
const char *ptr;
TPathItem *PI=NULL;
int Type, Flags=0;
unsigned int CacheTime=0;

Type=MatchTokenFromList(PathType,PathTypes,0);
if (Type > -1)
{
  ptr=GetToken(Data,",",&Tempstr,0);

  StripLeadingWhitespace(Tempstr);
  if (*Tempstr !='/') URL=MCopyStr(URL,"/",Tempstr,NULL);
  else URL=CopyStr(URL,Tempstr);


  ptr=GetToken(ptr,",",&Tempstr,0);
  while (ptr)
  {
  StripLeadingWhitespace(Tempstr);
  if (strncasecmp(Tempstr,"cache=",6)==0) CacheTime=atoi(Tempstr+6);
  else if (strncasecmp(Tempstr,"user=",5)==0) User=CopyStr(User, Tempstr+5);
  else if (strncasecmp(Tempstr,"pass=",5)==0) Password=CopyStr(Password, Tempstr+5);
  else if (strncasecmp(Tempstr,"passwd=",7)==0) Password=CopyStr(Password, Tempstr+7);
  else if (strncasecmp(Tempstr,"password=",9)==0) Password=CopyStr(Password, Tempstr+9);
  else if (strncasecmp(Tempstr,"group=",6)==0) Group=CopyStr(Group, Tempstr+6);
  else if ( (strncasecmp(Tempstr,"exec=",5)==0) && YesNoTrueFalse(Tempstr+5)) Flags |= PATHITEM_EXEC;
  else if ( (strncasecmp(Tempstr,"upload=",7)==0) && YesNoTrueFalse(Tempstr+7)) Flags |= PATHITEM_UPLOAD;
  else if ( (strncasecmp(Tempstr,"uploads=",8)==0) && YesNoTrueFalse(Tempstr+8)) Flags |= PATHITEM_UPLOAD;
  else if (strncasecmp(Tempstr,"compress=",9)==0)
  {
    if (YesNoTrueFalse(Tempstr+9)) Flags |= PATHITEM_COMPRESS;
    else Flags |= PATHITEM_NO_COMPRESS;
  }
  else
  {
    if (StrLen(Path)) Path=MCatStr(Path, ":", Tempstr,NULL);
    else Path=CopyStr(Path, Tempstr);
  }
  ptr=GetToken(ptr,",",&Tempstr,0);
  }


  PI=PathItemCreate(Type, URL, Path);
  PI->Flags=Flags;
  PI->CacheTime=CacheTime;
  PI->User=CopyStr(PI->User, User);
  PI->Password=CopyStr(PI->Password, Password);
  PI->Group=CopyStr(PI->Group, Group);
  switch (PI->Type)
  {
    case PATHTYPE_LOGOUT: Settings.Flags |= FLAG_LOGOUT_AVAILABLE; break;
    case PATHTYPE_FILETYPE:
      ptr=PI->URL;
      if (*ptr=='/') ptr++;
      PI->Path=CopyStr(PI->Path, ptr);
    break;
  }
  ListAddNamedItem(List,PI->URL,PI);
}
else LogToFile(Settings.LogPath,"ERROR: Unknown Path type '%s' in Config File",Tempstr);


DestroyString(Tempstr);
DestroyString(Password);
DestroyString(Group);
DestroyString(User);
DestroyString(Path);
DestroyString(URL);
}



TPathItem *VPathFind(int Type, char *Match)
{
TPathItem *VPath=NULL, *Default=NULL;
ListNode *Curr;

Curr=ListGetNext(Settings.VPaths);
while (Curr)
{
	VPath=(TPathItem *) Curr->Item;

	switch (VPath->Type)
	{
	case PATHTYPE_MIMEICONS: if (Type==VPath->Type) return(VPath); break;
	case PATHTYPE_FILETYPE:  if ((Type==VPath->Type) && (fnmatch(Curr->Tag, Match, 0)==0)) return(VPath); break;
	default:
	if (StrLen(Curr->Tag) < 2) Default=VPath;
	if (
			StrLen(Match) && (strncmp(Match, Curr->Tag, StrLen(Curr->Tag))==0)
		) return(VPath);
	break;
	}
	Curr=ListGetNext(Curr);
}

return(Default);
}


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
	if (strcmp(Session->Method,"POST")==0)
	{
		if (VPath->Flags & PATHITEM_UPLOAD)
		{
		LogToFile(Settings.LogPath,"%s@%s (%s) uploading to %s in VPATH %s", Session->UserName,Session->ClientHost,Session->ClientIP,DocName,ExternalPath);
		ChrootProcessRequest(S, Session, "POST", DocName, ExternalPath);
		}
		else 
		{
			LogToFile(Settings.LogPath,"%s@%s (%s) uploading DENIED to %s in VPATH %s", Session->UserName,Session->ClientHost,Session->ClientIP,DocName,ExternalPath);
			HTTPServerSendHTML(S, Session, "403 Forbidden","Uploads not allowed to this path.");
		}
	}
	else
	{
	LogToFile(Settings.LogPath,"%s@%s (%s) asking for external document %s in Search path %s", Session->UserName,Session->ClientHost,Session->ClientIP,DocName,ExternalPath);
	ChrootProcessRequest(S, Session, "GETF", DocName, ExternalPath);
	}
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
		VPathSession->Flags &= ~SESSION_UPLOAD;
		if (PI->Flags & PATHITEM_UPLOAD) VPathSession->Flags |= SESSION_UPLOAD;
	

//		if (Flags & HEADERS_POST) HTTPServerHandlePost(S,Session,PI->Type);
		LogToFile(Settings.LogPath,"APPLYING VPATH: %d [%s] -> [%s] %d",PI->Type,Curr->Tag,PI->Path,VPathSession->Flags & SESSION_UPLOAD);
		switch (PI->Type)
		{
			case PATHTYPE_CGI:
			LogToFile(Settings.LogPath,"CGI EXEC REQUEST: Script='%s' Path='%s'",GetBasename(Session->Path), PI->Path);
			ChrootProcessRequest(S, VPathSession, "EXEC", GetBasename(VPathSession->Path), PI->Path);
			//Don't reuse this session after CGI. CGI program will not send a 'Content-Length'
	    Session->Flags &= ~SESSION_REUSE;
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
			VPathSession->Flags &= ~SESSION_KEEPALIVE; 
			HTTPServerSendResponse(S, VPathSession, "302", "", Path);
			break;

			case PATHTYPE_URL:
			ChrootProcessRequest(S, VPathSession, "PROXY", PI->Path, "");
			break;

			case PATHTYPE_PROXY:
			if (StrLen(VPathSession->UserName)) 
			{
				//We don't normally copy Password into VPATH, so we need to get it from 'Session'
				if (StrLen(PI->Password)) VPathSession->Password=CopyStr(VPathSession->Password, Session->Password);
				else VPathSession->Password=CopyStr(VPathSession->Password, Session->Password);
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

