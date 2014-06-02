#include "directory_listing.h"
#include "server.h"
#include "common.h"
#include "MimeType.h"
#include "FileProperties.h"


char *FormatFileProperties(char *HTML, int FType, char *Path, ListNode *Vars)
{
ListNode *Curr;
char *Tempstr=NULL, *ptr;
char *IgnoreFields[]={"FileSize","ContentType","CTime-Secs","MTime-Secs", "IsExecutable", "creationdate", "getlastmodified", "getcontentlength", "getcontenttype", "executable","comment",NULL};

	if (FType != FILE_DIR) 
	{
		ptr=GetVar(Vars,"FileSize");
		if (ptr) HTML=MCatStr(HTML,"<tr><td>Size</td><td>", GetHumanReadableDataQty(strtod(ptr, NULL),0), " - (",ptr," bytes)","</td></tr>",NULL);
	}

	ptr=GetVar(Vars,"MTime-Secs");
	if (ptr)
	{
		HTML=MCatStr(HTML,"<tr><td>Modify Time</td><td>",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",atoi(ptr),NULL),"</td></tr>",NULL);
	}

	ptr=GetVar(Vars,"CTime-Secs");
	if (ptr)
	{
		HTML=MCatStr(HTML,"<tr><td>Create Time</td><td>",GetDateStrFromSecs("%Y/%m/%d %H:%M:%S",atoi(ptr),NULL),"</td></tr>",NULL);
	}

	HTML=MCatStr(HTML,"<tr bgcolor=#CCFFCC><td>ContentType</td><td>",GetVar(Vars,"ContentType"),"</td></tr>",NULL);

	if (FType != FILE_DIR)
	{
		Tempstr=CopyStr(Tempstr,"");
	//	HashFile(&Tempstr,"md5",Path,ENCODE_HEX);
		HTML=MCatStr(HTML,"<tr><td>MD5 Sum</td><td>",Tempstr,"</td></tr>",NULL);
	}


	Curr=ListGetNext(Vars);
	while (Curr)
	{
		if (StrLen(Curr->Item) && (MatchTokenFromList(Curr->Tag,IgnoreFields,0)==-1))  HTML=MCatStr(HTML,"<tr bgcolor=#CCFFCC><td>",Curr->Tag,"</td><td>",(char *) Curr->Item,"</td></tr>",NULL);
		Curr=ListGetNext(Curr);
	}

DestroyString(Tempstr);

return(HTML);
}




//Path is the ACTUAL path to the item, not it's VPath or URL. Thus, use Session->URL
//unless accessing the actual file
void DirectoryItemEdit(STREAM *S, HTTPSession *Session, char *Path)
{
char *HTML=NULL, *Tempstr=NULL, *URL=NULL, *Salt=NULL, *AccessToken=NULL, *ptr;
ListNode *Vars;
int val, FType;


HTML=MCopyStr(HTML,"<html>\r\n<head><title>Editing ",Session->URL,"</title></head>\r\n<body>\r\n<form>\r\n",NULL);

URL=FormatURL(URL,Session,Session->URL);

HTML=CatStr(HTML,"<table align=center width=90%% border=0>");
	
Vars=ListCreate();	
FType=LoadFileProperties(Path, Vars);
GenerateRandomBytes(&Salt,10,ENCODE_HEX);
AccessToken=MakeAccessToken(AccessToken, Salt, Session->UserName, "GET", "*", URL);
Tempstr=MCatStr(Tempstr,URL,"?AccessToken=",AccessToken,"&Salt=",Salt,"&User=",Session->UserName,"\n",NULL);
SetVar(Vars,"AccessToken",Tempstr);


	HTML=MCatStr(HTML,"<tr><td colspan=2><a href=\"",URL,"\">.. (Parent Directory)</a></td><td> &nbsp; </td></tr>",NULL);

	HTML=MCatStr(HTML,"<tr bgcolor=#CCCCFF><td>Path</td><td>",Session->URL,"</td></tr>",NULL);


	HTML=FormatFileProperties(HTML, FType, Path, Vars);

	//We must use the URL that this file was asked under, not its directory path. The directory path may not be
	//directly accessible to the user, and they may be accessing it via a VPATH
	URL=FormatURL(URL,Session,Session->URL);

	Tempstr=CopyStr(Tempstr,GetVar(Vars,"Comment"));
	HTML=MCatStr(HTML,"<tr><td>Comment</td><td><textarea rows=3 cols=40 name=fileproperty:comment>",Tempstr,"</textarea> <input type=submit name='sprops:",URL,"' value=change></td></tr>",NULL);

	HTML=MCatStr(HTML,"<tr bgcolor=#FFCCCC><td>Actions</td><td><input type=submit name='get:",URL,"' value=Get /> <input type=submit name='del:",URL,"' value=Del /> <input type=text name=renameto /><input type=submit name='renm:",URL,"' value=Rename /><input type=submit name='genaccess:",URL,"' value='Access Key'></td></tr>",NULL);
	

	HTML=CatStr(HTML,"</table>");
	HTML=CatStr(HTML,"</form></body></html>");

	HTTPServerSendResponse(S, Session, "200 OKAY", "text/html",HTML);

DestroyString(AccessToken);
DestroyString(Tempstr);
DestroyString(Salt);
DestroyString(HTML);
DestroyString(URL);

ListDestroy(Vars,DestroyString);
}



void FileDetailsSaveProps(STREAM *S, HTTPSession *Session, char *Path)
{
char *QuotedName=NULL, *QuotedValue=NULL, *Name=NULL, *Value=NULL, *ptr;
ListNode *Props;

Props=ListCreate();
ptr=GetNameValuePair(Session->Arguments,"&","=",&QuotedName,&QuotedValue);
while (ptr)
{
	Name=HTTPUnQuote(Name, QuotedName);
	Value=HTTPUnQuote(Value, QuotedValue);
	if (strncasecmp(Name,"fileproperty:",13)==0) SetVar(Props,Name+13,Value);
ptr=GetNameValuePair(ptr,"&","=",&QuotedName,&QuotedValue);
}

SetProperties(Path, Props);


ListDestroy(Props,DestroyString);

DestroyString(QuotedName);
DestroyString(QuotedValue);
DestroyString(Value);
DestroyString(Name);
}
