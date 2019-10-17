#include "Authenticate.h"
#include "ChrootHelper.h"

extern STREAM *ParentProcessPipe;

#define ACT_NONE	0
#define ACT_ADD		1
#define ACT_DEL		2
#define ACT_RDWR	3
#define ACT_RDONLY	4

#define SUCCESS    0
#define ERR_OPEN   1
#define ERR_EXISTS 2

int ParseFormData(HTTPSession *Session, char **Config)
{
int result=ACT_NONE;
char *Name=NULL, *Value=NULL, *QName=NULL, *QValue=NULL;
const char *ptr;

*Config=CopyStr(*Config, "");
ptr=GetNameValuePair(Session->Arguments,"&","=",&QName,&QValue);
while (ptr)
{
	Name=HTTPUnQuote(Name,QName);
	Value=HTTPUnQuote(Value,QValue);
	
	if (strcmp(Name,"AddUser")==0) result=ACT_ADD;
	else if (strncmp(Name,"DelUser:",8)==0) 
	{
		*Config=MCatStr(*Config," User=", Name+8, NULL);
		result=ACT_DEL;
	}
	else if (strcmp(Name,"UserLevel")==0)	
	{
		if (strcmp(Value, "admin")==0) *Config=CatStr(*Config, " Admin=Y");
		if (strcmp(Value, "read only")==0) *Config=CatStr(*Config, " HttpMethods=GET");
	}
	else *Config=MCatStr(*Config, " ",Name,"='",Value,"'",NULL);

	ptr=GetNameValuePair(ptr,"&","=",&QName,&QValue);
}


DestroyString(Name);
DestroyString(Value);
DestroyString(QName);
DestroyString(QValue);


return(result);
}



static char *DrawInputTable(char *Html)
{
Html=CatStr(Html, "<p align=center>\n");
Html=CatStr(Html, "<table align=center bgcolor=white cellspacing=5><tr><th bgcolor=blue colspan=10><font color=white>Add User</font></th></tr>\n");

Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td>User:</td>\n");
Html=CatStr(Html, "<td><input type=editbox name=\"User\" value=\"\"></td>\n");
Html=CatStr(Html, "</tr>\n");

Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td>Pass:</td>\n");
Html=CatStr(Html, "<td><input type=editbox name=\"Password\" value=""></td>\n");
Html=CatStr(Html, "</tr>\n");

Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td>Home Dir:</td>\n");
Html=CatStr(Html, "<td><input type=editbox name=\"HomeDir\" value=""></td>\n");
Html=CatStr(Html, "</tr>\n");

Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td>Real User:</td>\n");
Html=CatStr(Html, "<td><input type=editbox name=\"RealUser\" value=""></td>\n");
Html=CatStr(Html, "</tr>\n");

Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td>Level:</td>\n");
Html=CatStr(Html, "<td>\n");
Html=CatStr(Html, "<select name=\"UserLevel\">\n");
Html=CatStr(Html, "<option>admin</option>\n");
Html=CatStr(Html, "<option>read write</option>\n");
Html=CatStr(Html, "<option>read only</option>\n");
Html=CatStr(Html, "</select>\n");
Html=CatStr(Html, "</td>\n");
Html=CatStr(Html, "</tr>\n");


Html=CatStr(Html, "<tr>\n");
Html=CatStr(Html, "<td colspan=2><input type=submit name=\"AddUser\" value=\"Add\" ></td>\n");
Html=CatStr(Html, "</tr>\n");
Html=CatStr(Html, "</table></p>\n");

return(Html);
}


static char *DrawUsersTable(char *Html, HTTPSession *Session)
{
STREAM *F;
char *Tempstr=NULL, *Name=NULL, *RealUser=NULL, *HomeDir=NULL, *UserSettings=NULL;
char *PassType=NULL, *PassWord=NULL;
const char *ptr, *p_UserType="read write";

if (! ChrootSendRequest(Session, "LISTUSERS", "")) return(Html);

//Wait till process outside of chroot responds to our request, 
while (STREAMCheckForBytes(ParentProcessPipe)==0) usleep(10000);

//Read 'OKAY' line
//Tempstr=STREAMReadLine(Tempstr, ParentProcessPipe);

Html=CatStr(Html, "<p align=center>\n");
Html=CatStr(Html, "<table align=center bgcolor=white cellspacing=5>\n");
Html=CatStr(Html, "<tr><th bgcolor=green colspan=10><font color=white>Users</font></th></tr>\n");
Html=CatStr(Html, "<tr>");
Html=CatStr(Html, "<th bgcolor=#AAAAFF>User</th>");
Html=CatStr(Html, "<th bgcolor=#9999DD>Level</th>");
Html=CatStr(Html, "<th bgcolor=#AAAAFF>RealUser</th>");
Html=CatStr(Html, "<th bgcolor=#9999DD>Home</th>");
Html=CatStr(Html, "<th bgcolor=#AAAAFF>Actions</th></tr>\n");
	
Tempstr=STREAMReadLine(Tempstr, ParentProcessPipe);
while (Tempstr)
{
	StripTrailingWhitespace(Tempstr);
	if (strcmp(Tempstr, ".")==0) break;

	ptr=GetToken(Tempstr,":",&Name,0);
	ptr=GetToken(ptr,":",&PassType,0); //Passwd Type
	ptr=GetToken(ptr,":",&PassWord,0); //Passwd
	ptr=GetToken(ptr,":",&RealUser,0); //Real User
	ptr=GetToken(ptr,":",&HomeDir,0); //Home dir
	ptr=GetToken(ptr,":",&UserSettings,0); //Settings

	//axiomengineeringrfq:md5:a9bc601a6d87ac1ef6e5ebe60062a88c:nobody:/home/guest/axiomengineeringrfq:
	
	if (StrValid(Name)) 
	{
		Html=MCatStr(Html, "<tr><td>",Name,"</td>", NULL);

		ptr=GetNameValuePair(UserSettings, " ","=",&Name,&Tempstr);
		while (ptr)
		{
		if ((strcmp(Name,"Admin")==0) && (strcmp(Tempstr, "Y")==0)) p_UserType="admin";
		else if ((strcmp(Name,"HttpMethods")==0) && (strcmp(Tempstr, "GET")==0)) p_UserType="read only";
		ptr=GetNameValuePair(ptr, " ","=",&Name,&Tempstr);
		}

		Html=MCatStr(Html, "<td bgcolor=#DDDDDD>",p_UserType,"</td>\n",NULL);
		Html=MCatStr(Html, "<td>",RealUser,"</td>\n",NULL);

		Html=MCatStr(Html, "<td bgcolor=#DDDDDD>",HomeDir,"</td>\n",NULL);

		//Del Button
		Html=MCatStr(Html, "<td><input type=submit name=\"DelUser:", Name,"\" value=\"Delete\">\n",NULL);
		Html=MCatStr(Html, "</td></tr>\n");
	}
Tempstr=STREAMReadLine(Tempstr, ParentProcessPipe);
}
	
Html=MCatStr(Html, "</table></p>\n");


DestroyString(UserSettings);
DestroyString(RealUser);
DestroyString(HomeDir);
DestroyString(Tempstr);
DestroyString(Name);

return(Html);
}



/*
void AddUser(char *FPath, char *User, char *Pass)
{
char *Tempstr=NULL;

Tempstr=MCopyStr(Tempstr,"/home/guest/",User,NULL);
mkdir(Tempstr,0777);

Tempstr=MCopyStr(Tempstr,"/usr/sbin/alaya -user add ",User," ",Pass," -e plain -a ",FPath," -h ", "/home/guest/",User, NULL);

system(Tempstr);

DestroyString(Tempstr);
}
*/




void UserAdminScreenUpdateReadOnly(char *Path, char *User, int ReadOnly)
{
STREAM *Old, *New;
char *Tempstr=NULL, *Name=NULL, *UserLine=NULL;
const char *ptr;

Old=STREAMFileOpen(Path,O_RDONLY);
if (Old) 
{
	New=STREAMFileOpen("/tmp/AddUser.tmp",O_RDWR|O_CREAT|O_TRUNC);

	Tempstr=STREAMReadLine(Tempstr,Old);
	while (Tempstr)
	{
		ptr=GetToken(Tempstr,":",&Name,0);
		if (strcmp(Name,User)==0) UserLine=CopyStr(UserLine,Tempstr);
		else STREAMWriteLine(Tempstr,New);

		Tempstr=STREAMReadLine(Tempstr,Old);
	}
}

if (StrValid(UserLine))
{
	ptr=strrchr(UserLine, ':');
	if (ptr)
	{
		StrTrunc(UserLine, ptr - UserLine);

		//put ':' back on again
		UserLine=CatStr(UserLine, ":");
		if (ReadOnly) UserLine=CatStr(UserLine, "HttpMethods=GET");
		UserLine=CatStr(UserLine, "\n");

		STREAMWriteLine(UserLine,New);
	}
}

STREAMClose(Old);

Old=STREAMFileOpen(Path,O_CREAT|O_TRUNC|O_WRONLY);
STREAMSeek(New,0,SEEK_SET);
Tempstr=STREAMReadLine(Tempstr,New);
while (Tempstr)
{
STREAMWriteLine(Tempstr,Old);
Tempstr=STREAMReadLine(Tempstr,New);
}

STREAMClose(Old);
STREAMClose(New);

DestroyString(UserLine);
DestroyString(Tempstr);
DestroyString(Name);
}






void UserAdminScreenDisplay(STREAM *S, HTTPSession *Session)
{
char *Config=NULL, *Tempstr=NULL, *Html=NULL;
int result;

//print initial html
Html=CopyStr(Html, "<html><body bgcolor=\"#6600FF\"><form>\n");

result=ParseFormData(Session, &Config);

//STREAMWriteLine(Config, S);

switch (result)
{
case ACT_ADD:
	ChrootSendRequest(Session, "USERADD", Config);
break;

case ACT_DEL:
	ChrootSendRequest(Session, "USERDEL", Config);
break;
}

//print heading
Html=CatStr(Html, "<table align=center bgcolor=blue cellspacing=4><tr><td align=center bgcolor=white><h1>User Control</h1><a href=\"/Logout\"> Logout </a></td></table>\n");

Html=DrawInputTable(Html);
Html=DrawUsersTable(Html, Session);

Html=CatStr(Html, "</form></body></html>\n");
HTTPServerSendResponse(S, Session, "200 OK","text/html",Html);

Destroy(Tempstr);
Destroy(Config);
Destroy(Html);
}

