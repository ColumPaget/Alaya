#include "directory_listing.h"
#include "server.h"
#include "common.h"
#include "MimeType.h"
#include "upload.h"



//These are defined like flags, but used like an enumberated type
//This is because I might want to use them in combintation with other
//actual flags in future
#define SORT_TYPE_MASK 0xFF 
#define SORT_TYPE 1
#define SORT_NAME 2
#define SORT_TIME 3
#define SORT_SIZE 4
#define SORT_RTYPE 5
#define SORT_RNAME 6
#define SORT_RTIME 7
#define SORT_RSIZE 8

char *DirActionTypes[]={"html","csv","m3u","rss","tar","tgz","tbz","txz","upload","edit","delete","rename","mkdir-query","mkdir","saveprops",NULL};
typedef enum {ACTION_HTML,ACTION_CSV,ACTION_M3U,ACTION_RSS,ACTION_TAR,ACTION_TGZ,ACTION_TBZ,ACTION_TXZ,ACTION_UPLOAD,ACTION_EDIT,ACTION_DELETE,ACTION_RENAME, ACTION_MKDIRQUERY, ACTION_MKDIR, ACTION_SAVEPROPS} TDIRFORMAT;


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
char *Tempstr=NULL, *URL=NULL, *Dir=NULL, *ptr;
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

Tempstr=ParentDirectory(Tempstr, Session->URL);
URL=FormatURL(URL,Session,Tempstr);
Files[0]=PathItemCreate(PATHTYPE_DIR,Tempstr,"..");
fcount++;



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


char *FormatFileType(char *RetStr, TPathItem *File)
{
char *FileType=NULL, *Tempstr=NULL, *URL=NULL, *ptr;
TFileMagic *FM;
ListNode *Curr;
TPathItem *PathItem;

    if (File->Type==PATHTYPE_DIR)
    {
      FileType=CopyStr(FileType,"DIR");
    }
    else
    {
      FM=GetFileTypeInfo(File->Name);
      if (! FM)
      {
        FileType=CopyStr(FileType,"FILE");
      }
      else FileType=CopyStr(FileType,FM->ContentType);
    }



    if (Settings.DirListFlags & DIR_MIMEICONS)
    {
      Curr=ListGetNext(Settings.VPaths);
      while (Curr)
      {
        PathItem=(TPathItem *) Curr->Item;
        if (PathItem->Type == PATHTYPE_MIMEICONS)
        {
					ptr=strrchr(File->Name,'.');
					if (ptr) ptr++;

					if (File->Type==PATHTYPE_DIR) URL=MCopyStr(URL,PathItem->URL,"?MimeType=inode/directory&FileType=folder&FileExtn=",NULL);
					else URL=MCopyStr(URL,PathItem->URL,"?MimeType=",FileType,"&FileExtn=",ptr,NULL);
          Tempstr=MCopyStr(Tempstr,"<img src=\"",URL,"\" alt=\"",FileType,"\">",NULL);
					FileType=CopyStr(FileType,Tempstr);
          break;
        }
        Curr=ListGetNext(Curr);
      }
    }

DestroyString(Tempstr);
DestroyString(URL);

return(FileType);
}




char *FormatFancyDirItem(char *Buffer, int count, TPathItem *File)
{
char *Tempstr=NULL, *FileType=NULL, *DateStr=NULL, *DisplayName=NULL, *RetStr=NULL, *Interact=NULL;
char *Comment=NULL, *ptr;
char *bgcolor;
TFileMagic *FM;
ListNode *Vars;

	Vars=ListCreate();
	LoadFileProperties(File->Path, Vars);

	ptr=GetVar(Vars,"comment");
	if (StrLen(ptr)) Comment=MCopyStr(Comment," title=\"",ptr,"\" ",NULL);
	else Comment=CopyStr(Comment,"");

		if ((count % 2)==0) bgcolor="#FFFFFF";
		else bgcolor="#CCCCCC";

		if ((Now - File->Mtime) < 60)
		{
			DateStr=FormatStr(DateStr,"<font color=red>%d seconds ago</font>",Now - File->Mtime);
		}
		else DateStr=CopyStr(DateStr,GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",File->Mtime,NULL));

		if (strcmp(File->Name,"..")==0) DisplayName=CopyStr(DisplayName,".. (Parent Directory)");
		else if (Settings.DisplayNameLen && (StrLen(File->Name) > Settings.DisplayNameLen)) 
		{
			DisplayName=CopyStrLen(DisplayName,File->Name,Settings.DisplayNameLen);
			DisplayName=CatStr(DisplayName,"...");
		}
		else DisplayName=CopyStr(DisplayName,File->Name);

		FileType=FormatFileType(FileType, File);

		if (Settings.DirListFlags & DIR_INTERACTIVE) 
		{
			Interact=MCopyStr(Interact,"<td><input type='submit' name='edit:",File->URL,"' value='Edit' /></td>",NULL);
		}
		else Interact=CopyStr(Interact,"");

		Tempstr=FormatStr(Tempstr,"<tr bgcolor=\"%s\"><td>%s</td><td><a href=\"%s\" %s >%s</a></td><td align=right> &nbsp; %s</td><td align=right> &nbsp; %s</td>%s</tr>\r\n",bgcolor,FileType,File->URL,Comment, DisplayName,DateStr,GetHumanReadableDataQty((double) File->Size,0),Interact);

		RetStr=CatStr(Buffer,Tempstr);

		DestroyString(Tempstr);
		DestroyString(FileType);
		DestroyString(DateStr);
		DestroyString(DisplayName);
		DestroyString(Interact);
		DestroyString(Comment);

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


char *DisplayDirActions(char *Buffer, HTTPSession *Session, int Flags)
{
char *HTML=NULL, *Tempstr=NULL;
int PackTypeCount=3;

if (Flags & (DIR_TARBALLS | DIR_INTERACTIVE))
{
HTML=CatStr(Buffer,"<table align=center><tr>\r\n");
if (Flags & DIR_TARBALLS) HTML=MCatStr(HTML,"<td bgcolor='skyblue'><a href=\"",Session->URL,"?format=tar\">Download Directory in TAR format</a></td>\r\n",NULL);
if (Flags & DIR_INTERACTIVE) 
{
	HTML=MCatStr(HTML,"<td bgcolor='pink'><a href=\"",Session->URL,"?format=upload\">Upload Files</a></td>\r\n",NULL);
	HTML=MCatStr(HTML,"<td bgcolor='yellow'><a href=\"",Session->URL,"?format=mkdir-query\">MkDir</a></td>\r\n",NULL);
}
if (Settings.Flags & FLAG_LOGOUT_AVAILABLE) HTML=MCatStr(HTML,"<td bgcolor='#AAFFAA'><a href=\"",GetLogoutPath(),"\">Logout</a></td>\r\n",NULL);
HTML=CatStr(HTML,"</tr></table>");
}

return(HTML);
}


char *FinalizeDirListHTML(char *Buffer, HTTPSession *Session, char *Path, char *DirItemsHtml, int Flags)
{
char *HTML=NULL;

	HTML=MCopyStr(Buffer,"<html>\r\n<head><title>Index of ",Session->URL,"</title></head>\r\n<body>\r\n",NULL);
	if (Settings.Flags & FLAG_SSL) HTML=MCatStr(HTML,"<p align=center><font color=green>SECURE SESSION: Encrypted with ",Session->Cipher,"</font></p>\n",NULL);

	if ((Flags & DIR_FANCY))
	{
		if (Flags & DIR_INTERACTIVE) HTML=CatStr(HTML,"<form>\r\n");
		HTML=MCatStr(HTML,"<p align=center>Index of ",Session->URL," @",Session->Host, " ",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",Now,NULL)," User: ",Session->UserName,NULL);

		HTML=DisplayDirActions(HTML,Session,Flags);


 		if ((Flags & DIR_HASMEDIA) && (Flags & DIR_MEDIA_EXT)) HTML=MCatStr(HTML,"<a href=\"",Session->URL,"?format=m3u\">","<br />Playlist of Media in this Directory","</a></p>\r\n",NULL);
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
char *ptr;
char *HTML=NULL, *Tempstr=NULL;
int i, max, HasMedia=FALSE;
int FileCount=0, DirCount=0, ByteCount=0;


if (Settings.DirListFlags & DIR_FANCY) 
{
HTML=CatStr(HTML,"<table align=center width=90%% border=0>\r\n");

Tempstr=CopyStr(Tempstr,Session->URL);
HTML=CatStr(HTML,"<tr bgcolor=\"#AAAAFF\">");

HTML=FancyHeading(HTML,"Type",SORT_TYPE,Tempstr,Flags);
HTML=FancyHeading(HTML,"Name",SORT_NAME,Tempstr,Flags);
HTML=FancyHeading(HTML,"Last Modified",SORT_TIME,Tempstr,Flags);
HTML=FancyHeading(HTML,"Size",SORT_SIZE,Tempstr,Flags);

if (Settings.DirListFlags & DIR_INTERACTIVE) HTML=CatStr(HTML,"<td> &nbsp; </td>");
HTML=CatStr(HTML,"</tr>\r\n");
}

for (i=0; i < NoOfFiles; i++)
{
	if (Settings.DirListFlags & DIR_FANCY) 
	{
		HTML=FormatFancyDirItem(HTML,i,Files[i]);
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
	if (Settings.DirListFlags & DIR_INTERACTIVE) i=5;
	else i=4;

	//DirCount-1 here because we will have counted '..'
	if (DirCount > 0) DirCount--;

	Tempstr=FormatStr(Tempstr,"<tr bgcolor=\"#AAAAFF\"><td align=center colspan=%d>%d Files and %d Subdirectories, %s bytes total</td></tr>",i,FileCount,DirCount,GetHumanReadableDataQty((double) ByteCount,0));
	HTML=MCatStr(HTML,Tempstr,"</table>\r\n",NULL);
}


Tempstr=FinalizeDirListHTML(Tempstr, Session, Path, HTML, HasMedia | Settings.DirListFlags);
HTTPServerSendResponse(S, Session, "200 OK","text/html",Tempstr);

DestroyString(Tempstr);
DestroyString(HTML);
}




void HTTPServerSendM3U(STREAM *S, HTTPSession *Session, char *Path, int NoOfFiles, TPathItem **Files)
{
char *Tempstr=NULL, *M3U=NULL, *URL=NULL, *Salt=NULL, *AccessToken=NULL;
int i;

M3U=CopyStr(M3U,"#EXTM3U\n");
//#EXTINF - extra info - length (seconds), title

for (i=0; i < NoOfFiles; i++)
{
	if (InFileTypeList(Files[i]->Path,Settings.M3UFileTypes))
	{
		GenerateRandomBytes(&Salt,24,ENCODE_HEX);
		AccessToken=MakeAccessToken(AccessToken, Salt, Session->UserName, "GET", Session->ClientIP, Files[i]->URL);
		M3U=MCatStr(M3U,Files[i]->URL,"?AccessToken=",AccessToken,"&Salt=",Salt,"&User=",Session->UserName,"\n",NULL);
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


void HTTPServerSendPackedDir(STREAM *S, HTTPSession *Session,char *Dir)
{
char *Tempstr=NULL, *DirName=NULL, *FileName=NULL, *ptr;
HTTPSession *Response;
int result;

	LogToFile(Settings.LogPath,"Sending Tar Pack of [%s]",Dir);
	chdir(Dir);

	Response=HTTPSessionCreate();
	Response->ResponseCode=CopyStr(Response->ResponseCode,"200 OK");
	Response->ContentType=CopyStr(Response->ContentType,"application/x-tar");

	DirName=CopyStr(DirName,Dir);
	StripDirectorySlash(DirName);
	ptr=basename(DirName);

	if (! StrLen(ptr)) ptr="rootdir";

	FileName=MCopyStr(FileName,Session->Host,"-",Session->UserName,"-",ptr,".tar",NULL);
	strrep(FileName,' ','_');

	Tempstr=MCopyStr(Tempstr,"attachment; filename=",FileName,NULL);
	SetVar(Response->Headers,"Content-disposition",Tempstr);
	HTTPServerSendHeaders(S, Response, HEADERS_KEEPALIVE); 

	TarFiles(S," *");
	STREAMFlush(S);

DestroyString(FileName);
DestroyString(Tempstr);
DestroyString(DirName);
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
		}
	ptr=GetNameValuePair(ptr,"&","=",&Name,&Value);
	}

DestroyString(Name);
DestroyString(Value);

return(Action);
}



void DirectoryMkDirQuery(STREAM *S, HTTPSession *Session, char *Path)
{
char *HTML=NULL, *Tempstr=NULL, *URL=NULL, *ptr;
ListNode *Vars;
int val, FType;


HTML=MCopyStr(HTML,"<html>\r\n<head><title>MkDir in ",Session->URL,"</title></head>\r\n<body>\r\n<form>\r\n",NULL);

HTML=MCatStr(HTML,"<p align=center>MkDir in ",Session->URL,"</p>\r\n",NULL);
Tempstr=FormatURL(Tempstr,Session,Session->URL);
HTML=CatStr(HTML,"<table align=center width=90%% border=0>");
HTML=MCatStr(HTML,"<tr bgcolor=#CCCCFF><td>Dir Name:</td><td><input type=text name='mkdir' /><input type=submit name='mkdir:",Tempstr,"' value='Commit' /></td></tr>",NULL);

HTML=CatStr(HTML,"</table>");
HTML=CatStr(HTML,"</form></body></html>");

HTTPServerSendResponse(S, Session, "200 OKAY", "text/html",HTML);

DestroyString(Tempstr);
DestroyString(HTML);
ListDestroy(Vars,DestroyString);
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




void HTTPServerSendDirectory(STREAM *S, HTTPSession *Session, char *InPath, ListNode *Vars)
{
int DirSent=FALSE;
char *Tempstr=NULL, *Path=NULL, *Token=NULL, *ptr;
int Flags=0, Format, max=0;
TPathItem **Files;


//Maybe we can get out of sending the directory. Check 'IfModifiedSince'
if ((Session->IfModifiedSince > 0) && (Session->LastModified > 0) && (Session->LastModified <= Session->IfModifiedSince))
{
		HTTPServerSendHTML(S, Session, "304 Not Modified","");
		return;
}

	//Get Time for uses like showing 'recent files'
	time(&Now);
	Path=CopyStr(Path,InPath);

	if (HTTPServerDecideToCompress(Session,NULL)) Session->Flags |= HTTP_ENCODE_GZIP;

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
			case ACTION_TAR: HTTPServerSendPackedDir(S,Session,Path); break;
			case ACTION_UPLOAD: HtmlUploadPage(S,Session,Path); break;
			case ACTION_EDIT: DirectoryItemEdit(S,Session,Path); break;
			case ACTION_MKDIRQUERY: DirectoryMkDirQuery(S,Session,Path); break;
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
	      if (unlink(Path)!=0) 
				{
						//maybe it's a directory?
						if (rmdir(Path)==0) LogToFile(Settings.LogPath,"Deleted Directory: [%s]",Path);
 	     			else LogToFile(Settings.LogPath,"ERROR: Failed to Delete Item: [%s]",Path);
				}
				else LogToFile(Settings.LogPath,"Deleted File: [%s]",Path);
			//File deleted, send them to the parent directory
				HTTPServerSendToParentDir(S, Session);
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
DestroyString(Path);
}
