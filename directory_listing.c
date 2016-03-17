#include "directory_listing.h"
#include "server.h"
#include "common.h"
#include "MimeType.h"
#include "Authenticate.h"
#include "upload.h"
#include "FileDetailsPage.h"
#include "FileProperties.h"
#include "AccessTokens.h"

//These are defined like flags, but masked an used like an enumberated type
//This is because I'm combining other flags into the same int 
#define SORT_TYPE_MASK 0xFF 
#define SORT_TYPE 1
#define SORT_NAME 2
#define SORT_TIME 3
#define SORT_SIZE 4
#define SORT_RTYPE 5
#define SORT_RNAME 6
#define SORT_RTIME 7
#define SORT_RSIZE 8
#define SELECT_ALL 512

const char *DirActionTypes[]={"html","csv","m3u","rss","pack","upload","edit","delete","delete-selected","rename","mkdir","saveprops","editaccesstoken",NULL};
typedef enum {ACTION_HTML,ACTION_CSV,ACTION_M3U,ACTION_RSS,ACTION_PACK,ACTION_UPLOAD,ACTION_EDIT,ACTION_DELETE,ACTION_DELETE_SELECTED,ACTION_RENAME, ACTION_MKDIR, ACTION_SAVEPROPS, ACTION_EDIT_ACCESSTOKEN} TDIRFORMAT;


time_t Now;

int InFileTypeList(char *FilePath, char *FileTypes)
{
char *Token=NULL, *ptr, *extn;
int result=FALSE;


extn=strrchr(FilePath,'.');
if (extn)
{
	ptr=GetToken(FileTypes,",",&Token,0);
	while (ptr)
	{
		if (strcasecmp(Token,extn)==0) 
		{
			result=TRUE;
			break;
		}
	ptr=GetToken(ptr,",",&Token,0);
	}

}

DestroyString(Token);

return(result);
}





int FilesSortNameCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

return(strcmp(I1->Name,I2->Name));
}


int FilesRSortNameCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

return(strcmp(I2->Name,I1->Name));
}


int FilesSortTimeCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

if (I1->Mtime < I2->Mtime) return(-1);
if (I1->Mtime > I2->Mtime) return(1);
return(0);
}


int FilesRSortTimeCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

if (I1->Mtime > I2->Mtime) return(-1);
if (I1->Mtime < I2->Mtime) return(1);
return(0);
}



int FilesSortSizeCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

if (I1->Size < I2->Size) return(-1);
if (I1->Size > I2->Size) return(1);
return(0);
}


int FilesRSortSizeCmp(const void *p1, const void *p2)
{
TPathItem *I1, *I2;

I1=*(TPathItem **) p1;
I2=*(TPathItem **) p2;

if (I1->Size > I2->Size) return(-1);
if (I1->Size < I2->Size) return(1);
return(0);
}


//yes, '***', three levels of pointer! It's an array of pointers that
//has to be passed into the function as a pointer
int LoadDir(char *Path, HTTPSession *Session, int Flags, TPathItem ***fl_ptr)
{
char *Tempstr=NULL, *URL=NULL, *Dir=NULL;
glob_t Glob;
struct stat Stat;
TPathItem *File, **Files;
ListNode *Curr;
int i, val, fcount=0;

Tempstr=MCopyStr(Tempstr,Path,"/*",NULL);
glob(Tempstr,0,0,&Glob);


Dir=CopyStr(Dir,Session->URL);
Dir=SlashTerminateDirectoryPath(Dir);
//Allocate As Many Items As glob found, plus VPaths, plus one for '..'

val=Glob.gl_pathc+1;
if (Settings.DirListFlags & DIR_SHOW_VPATHS) val+=ListSize(Settings.VPaths);

*fl_ptr=(TPathItem **) calloc(val , sizeof(TPathItem *));
Files=*fl_ptr;

//if we are at '/' then don't offer a parent directory
if (StrLen(Path) > 1)
{
Tempstr=ParentDirectory(Tempstr, Session->URL);
URL=FormatURL(URL,Session,Tempstr);
Files[0]=PathItemCreate(PATHTYPE_DIR,Tempstr,"..");
fcount++;
}


//LoadVPaths if in top-level dir
if (Settings.DirListFlags & DIR_SHOW_VPATHS) 
{
	if (strcmp(Path,Session->StartDir)==0)
	{
		Curr=ListGetNext(Settings.VPaths);
		while (Curr)
		{	
			File=(TPathItem *) Curr->Item;
			if ((File->Type==PATHTYPE_EXTFILE) && (strcmp(File->URL,"/") !=0)) 
			{
				Files[fcount]=PathItemCreate(PATHTYPE_DIR,File->URL,File->URL);
				fcount++;
			}
		Curr=ListGetNext(Curr);
		}
	}
}

for (i=0; i < Glob.gl_pathc; i++)
{
  stat(Glob.gl_pathv[i],&Stat);
  Tempstr=MCopyStr(Tempstr,Dir,GetBasename(Glob.gl_pathv[i]),NULL);
	URL=FormatURL(URL,Session,Tempstr);
  if (S_ISDIR(Stat.st_mode)) File=PathItemCreate(PATHTYPE_DIR,URL,Glob.gl_pathv[i]);
  else File=PathItemCreate(PATHTYPE_FILE,URL,Glob.gl_pathv[i]);
  File->Mtime=Stat.st_mtime;
  File->Size=Stat.st_size;
  Files[fcount]=File;
	fcount++;
}


switch (Flags & SORT_TYPE_MASK)
{
case SORT_SIZE: qsort(Files,fcount,sizeof(TPathItem *),FilesSortSizeCmp); break;
case SORT_RSIZE: qsort(Files,fcount,sizeof(TPathItem *),FilesRSortSizeCmp); break;
case SORT_TIME: qsort(Files,fcount,sizeof(TPathItem *),FilesSortTimeCmp); break;
case SORT_RTIME: qsort(Files,fcount,sizeof(TPathItem *),FilesRSortTimeCmp); break;
case SORT_NAME: qsort(Files,fcount,sizeof(TPathItem *),FilesSortNameCmp); break;
case SORT_RNAME: qsort(Files,fcount,sizeof(TPathItem *),FilesRSortNameCmp); break;
}


globfree(&Glob);
DestroyString(Dir);
DestroyString(URL);
DestroyString(Tempstr);

//i will equal 'Glob.pathc' at end of loop, we also added '..' so return i+1 
return(fcount);
}


char *FormatFileType(char *RetStr, TPathItem *File, ListNode *Vars, const char *MimeIconsURL)
{
char *Tempstr=NULL, *URL=NULL, *ptr;
TFileMagic *FM;
ListNode *Curr;
TPathItem *PathItem;

RetStr=CopyStr(RetStr, "???");

//Book a content type against file so that things outside this function can use it
if (File->Type==PATHTYPE_DIR) File->ContentType=CopyStr(File->ContentType, "DIR");
else
{
	FM=GetFileTypeInfo(File->Name);
	if (! FM) File->ContentType=CopyStr(File->ContentType, "FILE");
	else File->ContentType=CopyStr(File->ContentType, FM->ContentType);
}

RetStr=CopyStr(RetStr,File->ContentType);

ptr=GetVar(Vars,"Thumbnail");
if (StrLen(ptr))
{
	RetStr=CopyStr(RetStr, ptr);
}
else if ((Settings.DirListFlags & DIR_MIMEICONS) && MimeIconsURL)
{
	ptr=strrchr(File->Name,'.');
	if (ptr) ptr++;

	if (File->Type==PATHTYPE_DIR) URL=MCopyStr(URL,MimeIconsURL,"?Type=folder&MimeType=inode/directory&FileExtn=",NULL);
	else URL=MCopyStr(URL,MimeIconsURL,"?MimeType=",RetStr,"&FileExtn=",ptr,NULL);
	Tempstr=MCopyStr(Tempstr,"<img src=\"",URL,"\" alt=\"",RetStr,"\">",NULL);
	RetStr=CopyStr(RetStr, Tempstr);
}

DestroyString(Tempstr);
DestroyString(URL);

return(RetStr);
}


char *FormatFancyDirComment(char *RetStr, ListNode *Vars)
{
ListNode *Curr;
const char *NonDisplayingValues[]={"executable","FileSize","CTime-Secs","MTime-Secs","IsExecutable","getcontentlength","getcontenttype","getlastmodified","creationdate",NULL};
const char *ptr;

RetStr=CopyStr(RetStr, "");
Curr=ListGetNext(Vars);
while (Curr)
{
	if (MatchTokenFromList(Curr->Tag, NonDisplayingValues,0)==-1) 
	{
		ptr=Curr->Tag;
		if (strncmp(ptr,"Media-",6)==0) ptr+=6;
		RetStr=MCatStr(RetStr,ptr, ":", Curr->Item, " ", NULL);
	}
	Curr=ListGetNext(Curr);
}

return(RetStr);
}


char *FormatFancyDirItem(char *RetStr, int count, TPathItem *File, const char *MimeIconsURL, int Flags)
{
char *Tempstr=NULL, *FileType=NULL, *DateStr=NULL, *DisplayName=NULL, *Interact=NULL;
char *Comment=NULL, *CheckBox=NULL, *ptr;
char *bgcolor;
ListNode *Vars;

	
	Vars=ListCreate();
	LoadFileProperties(File->Path, Vars);

/*
	ptr=GetVar(Vars,"comment");
	if (StrLen(ptr)) 
	{
		Comment=MCopyStr(Comment," title=\"",ptr,"\" ",NULL);
	}
	else Comment=CopyStr(Comment,"");
*/

	Comment=FormatFancyDirComment(Comment, Vars);

		if ((count % 2)==0) bgcolor="#FFFFFF";
		else bgcolor="#CCCCCC";

		if ((Now - File->Mtime) < 60)
		{
			DateStr=FormatStr(DateStr,"<font color=red>%d seconds ago</font>",Now - File->Mtime);
		}
		else DateStr=CopyStr(DateStr,GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",File->Mtime,NULL));

		FileType=FormatFileType(FileType, File, Vars, MimeIconsURL);
		//Okay, start building the actual table row
		RetStr=MCatStr(RetStr, "<tr bgcolor=\"",bgcolor,"\">",NULL);
		Interact=CopyStr(Interact,"");
		CheckBox=CopyStr(CheckBox,"");

		if (strcmp(File->Name,"..")==0) 
		{
			DisplayName=CopyStr(DisplayName,".. (Parent Directory)");
			CheckBox=CopyStr(CheckBox,"<td align=\"center\">&nbsp;</td>");
		}
		else 
		{
			if (Settings.DisplayNameLen && (StrLen(File->Name) > Settings.DisplayNameLen)) 
			{
			DisplayName=CopyStrLen(DisplayName,File->Name,Settings.DisplayNameLen);
			DisplayName=CatStr(DisplayName,"...");
			}
			else DisplayName=CopyStr(DisplayName,File->Name);


		if (Settings.DirListFlags & DIR_INTERACTIVE)
		{
			if (Flags & SELECT_ALL) CheckBox=MCatStr(CheckBox,"<td align=\"center\"><input type=\"checkbox\" name=\"selected\" value=\"",File->Name,"\" checked /></td>",NULL);
			else CheckBox=MCatStr(CheckBox,"<td align=\"center\"><input type=\"checkbox\" name=\"selected\" value=\"",File->Name,"\" /></td>",NULL);

			//Interaction string will be added to end of line
			Interact=MCatStr(Interact,"<input type='submit' name='edit:",File->URL,"' value='Edit' /> ",NULL);
			Interact=MCatStr(Interact,"<input type='submit' name='del:",File->URL,"' value='Del' /> ",NULL);
			
			//one day, but not yet
			//if (strncasecmp(File->ContentType,"audio/",6)==0) Interact=MCatStr(Interact,"<input type=\"button\" onclick=\"javascript: addaudio('",File->URL,"');\" value=\"Play\" /> ",NULL);
		}
		}

		Tempstr=FormatStr(Tempstr,"%s<td title=\"%s\">%s</td><td><a href=\"%s\" title=\"%s\">%s</a></td><td align=right> &nbsp; %s</td><td align=right> &nbsp; %s</td><td align=center>%s</td>",CheckBox,Comment,FileType,File->URL, File->Path, DisplayName, DateStr, GetHumanReadableDataQty((double) File->Size,0), Interact);

		//Append it all to our output
		RetStr=MCatStr(RetStr,Tempstr,"</tr>\r\n",NULL);

		DestroyString(DisplayName);
		DestroyString(FileType);
		DestroyString(Interact);
		DestroyString(Comment);
		DestroyString(Tempstr);
		DestroyString(DateStr);

	ListDestroy(Vars,DestroyString);

return(RetStr);
}


char *GetLogoutPath()
{
TPathItem *File;
ListNode *Curr;

Curr=ListGetNext(Settings.VPaths);
while (Curr)
{
	File=(TPathItem *) Curr->Item;
	if (File->Type==PATHTYPE_LOGOUT) return(File->URL);

Curr=ListGetNext(Curr);
}

return("");
}


char *DisplayPackAction(char *HTML, HTTPSession *Session)
{
char *Name=NULL, *Value=NULL, *ptr;

//if (Flags & DIR_TARBALLS) 
if (StrLen(Settings.PackFormats))
{
ptr=GetNameValuePair(Settings.PackFormats,",",":",&Name,&Value);

HTML=CatStr(HTML,"<td align=center colspan='2' bgcolor='skyblue'>Download as <select name=\"PackType\">");
while (ptr)
{
	HTML=MCatStr(HTML,"<option value=\"",Name,"\">",Name,NULL);
	ptr=GetNameValuePair(ptr,",",":",&Name,&Value);
}

HTML=MCatStr(HTML,"</select><input type=submit name='pack:",Session->URL,"' value='Pack'></td>",NULL);
}

return(HTML);
}



char *DisplayDirActions(char *Buffer, HTTPSession *Session, int Flags)
{
char *HTML=NULL;

if (Flags & DIR_INTERACTIVE)
{
HTML=MCatStr(HTML, "<script>function setCheckboxes(OnOrOff){ var i; var checkboxes=document.getElementsByName('selected'); for (i=0; i < checkboxes.length; i++) { if (OnOrOff==1) checkboxes[i].checked=true; else checkboxes[i].checked=false; } return(false); }</script>",NULL);
HTML=CatStr(Buffer,"<table align=center>\r\n");

	HTML=CatStr(HTML,"<tr>");
	if (Flags & DIR_TARBALLS) HTML=DisplayPackAction(HTML, Session);
	if ((Flags & DIR_HASMEDIA) && (Flags & DIR_MEDIA_EXT))
	{
		HTML=MCatStr(HTML,"<td bgcolor=\"#FFAAFF\"><input type=submit name='m3u:",Session->URL,"' value='M3U Playlist'></td>",NULL);

		/* One day, but not yet
		HTML=MCatStr(HTML,"<audio id=\"audioplayer\" controls autoplay></audio>",NULL);
		HTML=MCatStr(HTML,"<script>function addaudio(url){document.getElementById('audioplayer').src=url;}</script></td>",NULL);
		*/

	}
	HTML=CatStr(HTML,"</tr>");

	if (Session->Flags & SESSION_UPLOAD) 
	{
	HTML=CatStr(HTML,"<tr>");
	HTML=MCatStr(HTML,"<td align=center bgcolor='pink'><input type=submit name='upload:",Session->URL,"' value='Upload Files'></td>",NULL);
	HTML=MCatStr(HTML,"<td align=center bgcolor='yellow'><input type=submit name='mkdir:",Session->URL,"' value='MkDir'><input type=text name=mkdir></td>",NULL);
	HTML=MCatStr(HTML,"<td align=center bgcolor='red'><input type=submit name='delete-selected:",Session->URL,"' value='Delete Selected'></td>",NULL);
	HTML=CatStr(HTML,"</tr>");
	}

	HTML=CatStr(HTML,"</table>");
}

return(HTML);
}


char *FinalizeDirListHTML(char *Buffer, HTTPSession *Session, const char *Path, const char *DirItemsHtml, const char *MimeIconsURL, int Flags)
{
char *HTML=NULL;

	HTML=MCopyStr(Buffer,"<html>\r\n<head><title>",Session->URL,"</title></head>\r\n<body>\r\n",NULL);

	if ((Flags & DIR_FANCY))
	{
		if (Flags & DIR_INTERACTIVE) HTML=CatStr(HTML,"<form>\r\n");

		HTML=CatStr(HTML,"<table align=center border=0><tr>\n");
		if (Settings.Flags & FLAG_SSL) HTML=MCatStr(HTML,"<td><font color=green size=-1>SECURE<br/>",Session->Cipher,"</font></td>\n",NULL);
		else HTML=MCatStr(HTML,"<td><font color=red size=-1>Unencrypted<br/>Connection</font></td>\n",NULL);

		HTML=MCatStr(HTML,"<td><b>",Session->URL,"</b> at ",Session->Host, " <i>",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",Now,NULL),"</i><br/>",NULL);

		HTML=DisplayDirActions(HTML,Session,Flags);
		HTML=CatStr(HTML,"</td>\n");


		HTML=MCatStr(HTML,"<td>User: ",Session->UserName,"<br/>",NULL);
		if (Settings.Flags & FLAG_LOGOUT_AVAILABLE) HTML=MCatStr(HTML,"<a href=\"",GetLogoutPath(),"\">( Logout )</a>",NULL);
		HTML=CatStr(HTML,"</td></tr></table>\n");
	}
	HTML=MCatStr(HTML,DirItemsHtml,"<br />&nbsp;<br />",NULL);
	if (Flags & DIR_INTERACTIVE) HTML=CatStr(HTML,"</form>\r\n");
	HTML=CatStr(HTML,"</body></html>\r\n");

return(HTML);
}

char *FancyHeading(char *Buffer,const char *Name, int SortType, const char *CurrURL, int Flags)
{
char *SortName="";
int CurrSortType=0;

CurrSortType=Flags & SORT_TYPE_MASK;
switch (SortType)
{
case SORT_TYPE:
case SORT_RTYPE:
	if (CurrSortType == SORT_RTYPE) SortName="type";
	else SortName="rtype";
break;

case SORT_SIZE:
case SORT_RSIZE:
	if (CurrSortType == SORT_RSIZE) SortName="size";
	else SortName="rsize";
break;

case SORT_TIME:
case SORT_RTIME:
	if (CurrSortType == SORT_RTIME) SortName="time";
	else SortName="rtime";
break;

case SORT_NAME:
case SORT_RNAME:
	if (CurrSortType == SORT_RNAME) SortName="name";
	else SortName="rname";
break;
}

return(MCatStr(Buffer,"<th><a href=\"",CurrURL,"?sort=",SortName,"\">",Name,"</a></th>",NULL));
}



void HTTPServerSendDirList(STREAM *S, HTTPSession *Session, char *Path, int Flags, int NoOfFiles, TPathItem **Files)
{
char *HTML=NULL, *Tempstr=NULL;
int i, HasMedia=FALSE;
int FileCount=0, DirCount=0, ByteCount=0;
TPathItem *PI;
const char *p_MimeIconsURL=NULL;

//The title headers for the directory are added in 'FinalizeDirListHTML' believe it or not

PI=VPathFind(PATHTYPE_MIMEICONS, NULL);
if (PI) p_MimeIconsURL=PI->URL;

if (Settings.DirListFlags & DIR_FANCY) 
{
HTML=CatStr(HTML,"<table align=center width=90%% border=0>\r\n");

Tempstr=CopyStr(Tempstr,Session->URL);
HTML=CatStr(HTML,"<tr bgcolor=\"#AAAAFF\">");

//This one is for checkbox
if (Settings.DirListFlags & DIR_INTERACTIVE) HTML=MCatStr(HTML,"<th align=center><a href=\"",Session->URL,"?format=html&all-selected=true\" onclick=\"setCheckboxes(1); return(false);\">all</a> - <a href=\"",Session->URL,"\" onclick=\"setCheckboxes(0); return(false);\">none</a></th>",NULL);
HTML=FancyHeading(HTML,"Type",SORT_TYPE,Tempstr,Flags);
HTML=FancyHeading(HTML,"Name",SORT_NAME,Tempstr,Flags);
HTML=FancyHeading(HTML,"Last Modified",SORT_TIME,Tempstr,Flags);
HTML=FancyHeading(HTML,"Size",SORT_SIZE,Tempstr,Flags);

//this one is for action buttons
if (Settings.DirListFlags & DIR_INTERACTIVE) HTML=CatStr(HTML,"<td> &nbsp; </td>");
HTML=CatStr(HTML,"</tr>\r\n");
}

for (i=0; i < NoOfFiles; i++)
{
	if (Settings.DirListFlags & DIR_FANCY) 
	{
		HTML=FormatFancyDirItem(HTML,i,Files[i],p_MimeIconsURL, Flags);
		if (InFileTypeList(Files[i]->Path,Settings.M3UFileTypes)) HasMedia=DIR_HASMEDIA;
		if (Files[i]->Type==PATHTYPE_DIR) DirCount++;
		else
		{
			FileCount++;
			ByteCount+=Files[i]->Size;
		}
	}
	else 
	{
		HTML=MCatStr(HTML,"<a href=\"",Files[i]->URL,"\">",Files[i]->Name,"</a><br>\r\n",NULL);
	}
}


if (Settings.DirListFlags & DIR_FANCY) 
{
	if (Settings.DirListFlags & DIR_INTERACTIVE) i=6;
	else i=4;

	//DirCount-1 here because we will have counted '..'
	if (DirCount > 0) DirCount--;

	Tempstr=FormatStr(Tempstr,"<tr bgcolor=\"#AAAAFF\"><td align=center colspan=%d>%d Files and %d Subdirectories, %s bytes total</td></tr>",i,FileCount,DirCount,GetHumanReadableDataQty((double) ByteCount,0));
	HTML=MCatStr(HTML,Tempstr,"</table>\r\n",NULL);
}


Tempstr=FinalizeDirListHTML(Tempstr, Session, Path, HTML, p_MimeIconsURL, HasMedia | Settings.DirListFlags);
HTTPServerSendResponse(S, Session, "200 OK","text/html",Tempstr);

DestroyString(Tempstr);
DestroyString(HTML);
}




void HTTPServerSendM3U(STREAM *S, HTTPSession *Session, char *Path, int NoOfFiles, TPathItem **Files)
{
char *Tempstr=NULL, *M3U=NULL, *URL=NULL, *Salt=NULL, *AccessToken=NULL, *ptr;
ListNode *Vars;
STREAM *F;
int i;

M3U=CopyStr(M3U,"#EXTM3U\n");

for (i=0; i < NoOfFiles; i++)
{
	if (InFileTypeList(Files[i]->Path,Settings.M3UFileTypes))
	{

		//Examine file for Artist/title information
		Vars=ListCreate();
		F=STREAMOpenFile(Files[i]->Path, SF_RDONLY);
		MediaReadDetails(F, Vars);
		STREAMClose(F);
		ptr=GetVar(Vars, "Media-title");
		if (StrLen(ptr))
		{
			//#EXTINF - extra info - length (seconds), title
			Tempstr=CopyStr(Tempstr, GetVar(Vars, "Media-artist"));
			if (! StrLen(Tempstr)) Tempstr=CopyStr(Tempstr,"unknown-artist");
			M3U=MCatStr(M3U,"#EXTINF: -1, ", Tempstr, "-", GetVar(Vars,"Media-title"),"\n",NULL);
		}

		//Actually supply the URL
		M3U=CatStr(M3U,Files[i]->URL);

		//if we are supporting access token authentication, supply that
		if (AuthenticateExamineMethods(Settings.AuthMethods, FALSE) & AUTH_ACCESSTOKEN)
		{
			GenerateRandomBytes(&Salt,24,ENCODE_HEX);
			AccessToken=MakeAccessToken(AccessToken, Salt, Session->UserName, Session->ClientIP, Files[i]->URL);
			M3U=MCatStr(M3U,"?AccessToken=",AccessToken,"&Salt=",Salt,"&User=",Session->UserName,"\n",NULL);
		}
		ListDestroy(Vars,DestroyString);
		M3U=CatStr(M3U,"\n");
	}	
}

Tempstr=MCopyStr(Tempstr,Path,".m3u",NULL);
SetVar(Session->Headers,"Content-disposition",Tempstr);
HTTPServerSendResponse(S, Session, "200 OK","audio/x-mpegurl",M3U);

DestroyString(AccessToken);
DestroyString(Tempstr);
DestroyString(Salt);
DestroyString(URL);
DestroyString(M3U);
}


void HTTPServerSendCSV(STREAM *S, HTTPSession *Session, char *Path, int NoOfFiles, TPathItem **Files)
{
char *Tempstr=NULL, *SizeStr=NULL, *CSV=NULL;
struct stat Stat;
int i;

CSV=CopyStr(CSV,"File Name,URL,Last Modified,Size\r\n");

for (i=0; i < NoOfFiles; i++)
{
		stat(Files[i]->Path,&Stat);
		SizeStr=FormatStr(SizeStr,"%d",Stat.st_size);
		CSV=MCatStr(CSV,"\"",GetBasename(Files[i]->Path),"\", \"",Files[i]->URL,"\", \"",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",Stat.st_mtime,NULL),"\", \"",SizeStr,"\"\r\n",NULL);
}

Tempstr=MCopyStr(Tempstr,Path,".csv",NULL);
SetVar(Session->Headers,"Content-disposition",Tempstr);
HTTPServerSendResponse(S, Session, "200 OK","text/csv",CSV);

DestroyString(Tempstr);
DestroyString(SizeStr);
DestroyString(CSV);
}


int HTTPServerSendPackedDir(STREAM *S, HTTPSession *Session, const char *Dir)
{
char *Tempstr=NULL, *DirName=NULL, *FileName=NULL, *ptr;
char *Extn=NULL, *PackType=NULL, *Name=NULL, *Value=NULL;
char *PackList=NULL;
TFileMagic *FM;
HTTPSession *Response;
STREAM *Pipe;

	chdir(Dir);
	//unset session reuse, because we will close session to indicate end of package
	Session->Flags &= ~SESSION_REUSE;

	//do this so we can strcmp it
	PackList=CopyStr(PackList,"");

	Response=HTTPSessionCreate();
	Response->ResponseCode=CopyStr(Response->ResponseCode,"200 OK");

	ptr=GetNameValuePair(Session->Arguments, "&","=",&Name,&Value);
	while (ptr)
	{
		if ( StrLen(Name) )
		{
		if	(strcasecmp(Name,"packtype")==0)
		{
			PackType=CopyStr(PackType,Value);
			Extn=MCopyStr(Extn, ".", Value, NULL);
			FM=GetFileMagicForFile(Extn, NULL);
			Response->ContentType=CopyStr(Response->ContentType, FM->ContentType);
		}
		else if (strcasecmp(Name,"selected")==0) 
		{
			if (strcmp(PackList," *") !=0) PackList=MCatStr(PackList, " ", Value, NULL);
		}
		}
		
	ptr=GetNameValuePair(ptr, "&","=",&Name,&Value);
	}

	if (StrLen(PackList)==0) PackList=CopyStr(PackList, " *");
	DirName=CopyStr(DirName,Dir);
	StripDirectorySlash(DirName);
	ptr=GetBasename(DirName);

	if (! StrLen(ptr)) ptr="rootdir";

	FileName=MCopyStr(FileName,Session->Host,"-",Session->UserName,"-",ptr,Extn,NULL);
	strrep(FileName,' ','_');

	Tempstr=MCopyStr(Tempstr,"attachment; filename=",FileName,NULL);
	SetVar(Response->Headers,"Content-disposition",Tempstr);

	ptr=GetNameValuePair(Settings.PackFormats, ",",":", &Name, &Value);
	while (ptr)
	{
	if (strcasecmp(Name, PackType)==0)
	{
		if (strcasecmp(Value,"internal")==0)
		{
			if (strcasecmp(Name,"tar")==0) 
			{
				HTTPServerSendHeaders(S, Response, 0); 
				TarFiles(S, PackList);
			}
		}
		else
		{
		HTTPServerSendHeaders(S, Response, 0); 
		Tempstr=MCopyStr(Tempstr,Value,PackList,NULL);
		Pipe=STREAMSpawnCommand(Tempstr, COMMS_BY_PIPE);
		STREAMSendFile(Pipe, S, 0, SENDFILE_KERNEL| SENDFILE_LOOP);
		STREAMClose(Pipe);
		}
	}
	ptr=GetNameValuePair(ptr, ",",":", &Name, &Value);
	}

	STREAMFlush(S);

DestroyString(FileName);
DestroyString(Tempstr);
DestroyString(DirName);
DestroyString(PackList);
DestroyString(PackType);
DestroyString(Name);
DestroyString(Value);
DestroyString(Extn);


//This true means 'please close the connection' as our tarballs/zips are transferred using
//connection: close to indicate end of transfer
return(STREAM_CLOSED);
}





//Searches for an Index file, and sends it if it exits. Returns FALSE if not
int DirectoryTryIndex(STREAM *S, HTTPSession *Session, char *Path)
{
char *Tempstr=NULL, *Token=NULL, *ptr;
int DirSent=FALSE;

ptr=GetToken(Settings.IndexFiles,",",&Token,0);
while (ptr)
{
	Tempstr=MCopyStr(Tempstr,Path,Token,NULL);
	if (Settings.Flags & FLAG_LOG_MORE_VERBOSE) LogToFile(Settings.LogPath,"Checking for index page: [%s]\n",Tempstr);

	if (access(Tempstr,F_OK)==0) 
	{
		Session->Path=CopyStr(Session->Path,Tempstr);
		HTTPServerSendDocument(S, Session, Tempstr, HEADERS_SENDFILE | HEADERS_KEEPALIVE);
		DirSent=TRUE;
		break;
	}
ptr=GetToken(ptr,",",&Token,0);
}

if (Settings.Flags & FLAG_LOG_VERBOSE)
{
	if (DirSent) LogToFile(Settings.LogPath,"Sent index page: [%s] for dir [%s]\n",Tempstr,Path);
	else LogToFile(Settings.LogPath,"Failed to find index page for dir: [%s]\n",Path);
}

DestroyString(Tempstr);
DestroyString(Token);

return(DirSent);
}


int RequestedListingType(HTTPSession *Session, int *Flags)
{
char *Name=NULL, *Value=NULL, *ptr;
int Action=ACTION_HTML;

if (! (Settings.DirListFlags & DIR_SHOWFILES)) return(DIR_REJECT);

	ptr=GetNameValuePair(Session->Arguments,"&","=",&Name,&Value);
	while (ptr)
	{
		if ( StrLen(Name) && StrLen(Value))
		{
			if (strcmp(Name,"format")==0) Action=MatchTokenFromList(Value,DirActionTypes,0);
			else if (strcmp(Name,"sort")==0)
			{
				if (strcmp(Value,"size")==0) *Flags=SORT_SIZE;
				else if (strcmp(Value,"rsize")==0) *Flags=SORT_RSIZE;
				else if (strcmp(Value,"time")==0) *Flags=SORT_TIME;
				else if (strcmp(Value,"rtime")==0) *Flags=SORT_RTIME;
				else if (strcmp(Value,"name")==0) *Flags=SORT_NAME;
				else if (strcmp(Value,"rname")==0) *Flags=SORT_RNAME;
				//if (strcmp(Value,"rss")==0) *SortFlags=DIR_RSS;
			}
			else if (strcmp(Name,"all-selected")==0) *Flags|=SELECT_ALL;
		}
	ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
	}

DestroyString(Name);
DestroyString(Value);

return(Action);
}



void HTTPServerSendToParentDir(STREAM *S, HTTPSession *Session)
{
	char *Path=NULL, *Tempstr=NULL;

			Path=ParentDirectory(Path,Session->URL);
			Tempstr=FormatURL(Tempstr,Session,Path);
      HTTPServerSendResponse(S, Session, "302", "", Tempstr);

		DestroyString(Tempstr);
		DestroyString(Path);
}




void DirectoryDeleteItem(STREAM *S, HTTPSession *Session, const char *Path)
{
	      if (unlink(Path)!=0) 
				{
						//maybe it's a directory?
						if (rmdir(Path)==0) LogToFile(Settings.LogPath,"Deleted Directory: [%s]",Path);
 	     			else LogToFile(Settings.LogPath,"ERROR: Failed to Delete Item: [%s]",Path);
				}
				else LogToFile(Settings.LogPath,"Deleted File: [%s]",Path);
			//File deleted, send them to the parent directory
}


void DirectoryDeleteSelected(STREAM *S, HTTPSession *Session, const char *Dir)
{
char *Name=NULL, *Value=NULL, *Path=NULL, *ptr;

	LogToFile(Settings.LogPath,"DeleteSelected: [%s]\n",Session->Arguments);
	ptr=GetNameValuePair(Session->Arguments, "&","=",&Name,&Value);
	while (ptr)
	{
		if ( StrLen(Name) )
		{
		if (strcasecmp(Name,"selected")==0) 
		{
			Path=MCopyStr(Path,Dir,"/",Value,NULL);
			DirectoryDeleteItem(S, Session, Path);
		}
		}
	ptr=GetNameValuePair(ptr, "&","=",&Name,&Value);
	}

DestroyString(Value);
DestroyString(Name);
DestroyString(Path);
}



int HTTPServerSendDirectory(STREAM *S, HTTPSession *Session, char *Path, ListNode *Vars)
{
int DirSent=FALSE;
char *Tempstr=NULL, *Token=NULL, *ptr;
int Flags=0, Format, max=0;
TPathItem **Files;
int result=FALSE;


//Maybe we can get out of sending the directory. Check 'IfModifiedSince'
if ((Session->IfModifiedSince > 0) && (Session->LastModified > 0) && (Session->LastModified <= Session->IfModifiedSince))
{
//		HTTPServerSendHTML(S, Session, "304 Not Modified","");
//		return;
}

	//Get Time for uses like showing 'recent files'
	time(&Now);

	if (HTTPServerDecideToCompress(Session,NULL)) Session->Flags |= SESSION_ENCODE_GZIP;

	if (Settings.DirListFlags & DIR_INDEX_FILES)
	{
		DirSent=DirectoryTryIndex(S, Session, Path);
	}

	if (! DirSent) 
	{
		Format=RequestedListingType(Session,&Flags);
		switch (Format)
		{
			case ACTION_HTML:
			case ACTION_M3U:
			case ACTION_CSV:
				max+=LoadDir(Path, Session, Flags, &Files);
				
				switch (Format)
				{
					case ACTION_M3U: HTTPServerSendM3U(S,Session,Path,max,Files); break;
					case ACTION_CSV: HTTPServerSendCSV(S,Session,Path,max,Files); break;
					case ACTION_HTML: HTTPServerSendDirList(S,Session,Path,Flags,max,Files); break;
				}
			break;

			//TAR doesn't send a list of files, it sends the actual files, so it doesn't need to use
			//LoadDir in order to handle VPaths etc.
			case ACTION_PACK: result=HTTPServerSendPackedDir(S,Session,Path); break;
			case ACTION_UPLOAD: UploadSelectPage(S,Session,Path); break;
			case ACTION_EDIT: DirectoryItemEdit(S,Session,Path,0); break;
			case ACTION_EDIT_ACCESSTOKEN: DirectoryItemEdit(S,Session,Path, FDETAILS_ACCESSTOKEN); break;
			case ACTION_MKDIR: 
				Token=SessionGetArgument(Token, Session, "mkdir");
				Tempstr=CopyStr(Tempstr,Path);
				Tempstr=SlashTerminateDirectoryPath(Tempstr);
				Tempstr=CatStr(Tempstr,Token);	
				LogToFile(Settings.LogPath,"MKDIR: [%s] [%s] [%s]\n",Path,Token,Tempstr);
				mkdir(Tempstr, 0770); 
      	HTTPServerSendResponse(S, Session, "302", "", Session->URL);
			break;

			case ACTION_DELETE:
				DirectoryDeleteItem(S, Session, Path);
				HTTPServerSendToParentDir(S, Session);
			break;

			case ACTION_DELETE_SELECTED:
				DirectoryDeleteSelected(S, Session, Path);
      	HTTPServerSendResponse(S, Session, "302", "", Session->URL);
			break;

			case ACTION_RENAME:
				Token=SessionGetArgument(Token, Session, "renameto");
				Tempstr=CopyStr(Tempstr,Path);
				ptr=strrchr(Tempstr,'/');
				if (ptr) *ptr='\0';
				Tempstr=SlashTerminateDirectoryPath(Tempstr);
				Tempstr=CatStr(Tempstr,Token);	
	      if (rename(Path,Tempstr) !=0)
				{
					LogToFile(Settings.LogPath,"ERROR: Failed to rename: [%s] to [%s]. Error was: %s",Path,Tempstr,strerror(errno));
				}
   			else LogToFile(Settings.LogPath,"Renamed Item: [%s] to [%s]",Path,Tempstr);

				HTTPServerSendToParentDir(S, Session);
			break;

			case ACTION_SAVEPROPS:
				LogToFile(Settings.LogPath,"SAVEPROPS: [%s]\n",Path);
				FileDetailsSaveProps(S, Session, Path);
				Tempstr=MCopyStr(Tempstr,Session->URL,"?format=edit",NULL);
      	HTTPServerSendResponse(S, Session, "302", "", Tempstr);
			break;


			default: HTTPServerSendHTML(S, Session, "403 Index Listing Forbidden","This server is not configured to list directories."); break;
		}
	}

DestroyString(Tempstr);
DestroyString(Token);

return(result);
}
