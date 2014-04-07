//Alaya, webdav server
//Named after 'Alaya-vijnana', the Buddhist concept of 'storehouse mind' that 
//'receives impressions from all functions of the other consciousnesses and retains them 
//as potential energy for their further manifestations and activities.'
//Written by Colum Paget.
//Copyright 2011 Colum Paget.


/****  Gnu Public Licence ****/
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "Authenticate.h"
#include "server.h"
#include <sys/utsname.h>


ListNode *MimeTypes=NULL;
ListNode *Connections=NULL;
STREAM *ParentProcessPipe=NULL;

void SetTimezoneEnv()
{
if (StrLen(tzname[1]))
{
   setenv("TZ",tzname[1],TRUE);
}
else
{
   setenv("TZ",tzname[0],TRUE);
}
}

void HandleUserSetup(char *Operation, int argc, char *argv[])
{
 int i, result;
 char *UserName=NULL, *Password=NULL, *PassType=NULL, *HomeDir=NULL, *RealUser=NULL, *Args=NULL;

	if (strcmp(Operation,"del")==0) PassType=CopyStr(PassType,"delete");
	else PassType=CopyStr(PassType,"md5");
	HomeDir=CopyStr(HomeDir,"/tmp");
	RealUser=CopyStr(RealUser,GetDefaultUser());
	Password=CopyStr(Password,"");
	Args=CopyStr(Args,"");

 for (i=3; i < argc; i++)
 {
	if (strcmp(argv[i],"-e")==0)
	{
		i++;
		if (strcmp(Operation,"del") !=0) PassType=CopyStr(PassType,argv[i]);
	}
	else if (strcmp(argv[i],"-h")==0)
	{
		i++;
		HomeDir=CopyStr(HomeDir,argv[i]);
	}
	else if (strcmp(argv[i],"-u")==0)
	{
		i++;
		RealUser=CopyStr(RealUser,argv[i]);
	}
	else if (strcmp(argv[i],"-a")==0)
	{
		i++;
		Settings.AuthPath=CopyStr(Settings.AuthPath,argv[i]);
	}
	else if (StrLen(UserName)==0) UserName=CopyStr(UserName,argv[i]);
	else if (StrLen(Password)==0) Password=CopyStr(Password,argv[i]);
	else Args=MCatStr(Args,argv[i]," ",NULL);
 }

	if (strcmp(Operation,"list")==0) ListNativeFile(Settings.AuthPath);
	else if (! StrLen(UserName)) printf("ERROR: NO USERNAME GIVEN\n");
	else if ((strcmp(Operation,"add")==0) && (! StrLen(Password))) printf("ERROR: NO PASSWORD GIVEN\n");
	else result=UpdateNativeFile(Settings.AuthPath, UserName, PassType, Password, HomeDir,RealUser, Args);

	if (result==ERR_FILE) printf("ERROR: Cannot open file '%s'\n",Settings.AuthPath);

 DestroyString(UserName);
 DestroyString(Password);
 DestroyString(PassType);
 DestroyString(RealUser);
 DestroyString(HomeDir);
 DestroyString(Args);

	//Always exit when this is done, don't launch webserver
 exit(0);
}

	

void PrintUsage()
{
fprintf(stdout,"\nAlaya Webdav Server: version %s\n",Version);
fprintf(stdout,"Author: Colum Paget\n");
fprintf(stdout,"Email: colums.projects@gmail.com\n");
fprintf(stdout,"Blog: http://idratherhack.blogspot.com \n");
fprintf(stdout,"\n");
fprintf(stdout,"Usage: alaya [-v] [-d] [-O] [-h] [-p <port>] [-A <auth methods>] [-a <auth file>] [-l <path>]  [-r <path>] [-key <path>] [-cert <path>] [-cgi <path>] [-ep <path>] [-u <default user>] [-g <default group>] [-m <http methods>] [-realm <auth realm>] [-compress <yes|no|partial>]\n\n");
fprintf(stdout,"	-v:		Verbose logging.\n");
fprintf(stdout,"	-v -v:		Even more verbose logging.\n");
fprintf(stdout,"	-a:		Specify the authentication file for 'built in' authentication.\n");
fprintf(stdout,"	-A:		Authentication methods. Comma separated list of pam,passwd,shadow,native,accesstoken. For 'Alaya native only' just use 'native' on its own\n");
fprintf(stdout,"	-d:		No daemon, don't background process.\n");
fprintf(stdout,"	-f:		Path to config file, defaults to /etc/alaya.conf, but alaya can be configured by command-line args only.\n");
fprintf(stdout,"	-O:		Open, don't require authentication.\n");
fprintf(stdout,"	-h:		'ChHome mode', switch to users home dir and chroot.\n");
fprintf(stdout,"	-i:		Set interface listen on, allows running separate servers on the same port on different interfaces/network cards.\n");
fprintf(stdout,"	-l:		Path to log file, default is to use 'syslog' instead.\n");
fprintf(stdout,"	-m:		HTTP Methods (GET, PUT, DELETE, PROPFIND) that are allowed.\nComma Separated. Set to 'GET' for very basic webserver, 'GET,PROPFIND' for readonly DAV.\n'BASE' will set GET,POST,HEAD. 'DAV' will set everything needed for WebDAV. 'RGET' will allow proxy-server gets. 'PROXY' will enable CONNECT and RGET. 'DAV,PROXY' enables everything.\n");
fprintf(stdout,"	-p:		Set port to listen on.\n");
fprintf(stdout,"	-r:		'ChRoot mode', chroot into directory and offer services from it\n");
fprintf(stdout,"	-key:		Keyfile for SSL (HTTPS)\n");
fprintf(stdout,"	-cert:		Certificate for SSL (HTTPS). This can be a certificate chain bundled in .pem format.\n");
fprintf(stdout,"	-cgi:		Directory containing cgi programs. These programs will be accessible even though they are outside of a 'chroot'\n");
fprintf(stdout,"	-hashfile:	File containing cryptographic hashes of cgi-scripts. This file contains the output of the md5sum, shasum, sha256sum or sha512sum utilities.\n");
fprintf(stdout,"	-ep:		'External path' containing files that will be accessible even outside a chroot.\n");
fprintf(stdout,"	-u:		User to run cgi-programmes and default 'real user' for any 'native users' that don't have one specified.\n");
fprintf(stdout,"	-g:		Group to run server in (this will be the default group for users)\n");
fprintf(stdout,"	-allowed:		Comma separated list of users allowed to login (default without this switch is 'all users can login'\n");
fprintf(stdout,"	-denied:		Comma separated list of users DENIED login\n");
fprintf(stdout,"	-realm:		Realm for HTTP Authentication\n");
fprintf(stdout,"	-compress:		Compress documents and responses. This can have three values, 'yes', 'no' or 'partial'. 'Partial' means alaya will compress directory listings and other internally genrated pages, but not file downloads.\n");
fprintf(stdout,"\n\nUser Setup for Alaya Authentication\n");
fprintf(stdout,"	Alaya can use PAM, /etc/shadow or /etc/passwd to authenticate, but has its own password file that offers extra features, or is useful to create users who can only use Alaya. Users in the Alaya password file are mapped to a 'real' user on the system (usually 'guest' or 'nobody'). The Alaya password file can be setup through the alaya commandline.\n\n");
fprintf(stdout," Add User: alaya -user add [-a <auth path>] [-e <password encryption type>]  [-h <user home directory>] <Username> <Password> <Setting> <Setting> <Setting>\n\n");
fprintf(stdout,"	-a:		Specify the authentication file for 'built in' authentication.\n");
fprintf(stdout,"	-h:		Specify home directory of new user.\n");
fprintf(stdout,"	-u:		Specify 'real user' that this user maps to.\n");
fprintf(stdout,"	-e:		Specify password encryption type (sha1, sha512, sha256, md5, plain or null).\n");
fprintf(stdout,"				Config file type settings (like 'ChHome' or 'ChRoot=/var/shared' or 'HttpMethods=GET,PUT,PROPFIND' or 'CgiPath=/usr/share/cgi' can be added so that these settings are specific to a user\n\n");

fprintf(stdout," Delete User: alaya -user del [-a <auth path>] <Username>\n\n");
fprintf(stdout," List Users : alaya -user list\n\n");

}



void ParseCommandLineArgs(int argc, char *argv[], TSettings *Settings)
{
int i;
char *Token=NULL, *ptr;


Settings->Flags=FLAG_REQUIRE_AUTH;
if (argc < 2) return;

if (strcmp(argv[1],"-user")==0)
{

	if (strcmp(argv[2],"list")==0) HandleUserSetup("list",argc, argv);
	else if (strcmp(argv[2],"add")==0) HandleUserSetup("add",argc, argv);
	else if (strcmp(argv[2],"del")==0) HandleUserSetup("del",argc, argv);
	else printf("-user must be followed by one of \"add\", \"del\" or \"list\"\n");


		exit(1);
}


for (i=1; i < argc; i++)
{
	if (strcmp(argv[i],"-nodemon")==0) Settings->Flags |= FLAG_NODEMON;
	else if (strcmp(argv[i],"-d")==0) Settings->Flags |= FLAG_NODEMON;
	else if (strcmp(argv[i],"-i")==0) Settings->BindAddress=CopyStr(Settings->BindAddress,argv[++i]);
	else if (strcmp(argv[i],"-a")==0) Settings->AuthPath=CopyStr(Settings->AuthPath,argv[++i]);
	else if (strcmp(argv[i],"-A")==0) Settings->AuthMethods=CopyStr(Settings->AuthMethods,argv[++i]);
	else if (strcmp(argv[i],"-v")==0) 
	{
		if (Settings->Flags & FLAG_LOG_VERBOSE) Settings->Flags |= FLAG_LOG_MORE_VERBOSE;
		Settings->Flags |= FLAG_LOG_VERBOSE;
	}
	else if (strcmp(argv[i],"-f")==0) Settings->ConfigPath=CopyStr(Settings->ConfigPath,argv[++i]);
	else if (strcmp(argv[i],"-l")==0) Settings->LogPath=CopyStr(Settings->LogPath,argv[++i]);
	else if (strcmp(argv[i],"-m")==0) Settings->HttpMethods=CopyStr(Settings->HttpMethods,argv[++i]);
	else if (strcmp(argv[i],"-p")==0) Settings->Port=atoi(argv[++i]);
	else if (strcmp(argv[i],"-O")==0) Settings->Flags &= ~FLAG_REQUIRE_AUTH;
	else if (strcmp(argv[i],"-compress")==0) 
	{
		Token=MCopyStr(Token,"Compression=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-u")==0) 
	{
		Token=MCopyStr(Token,"DefaultUser=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-g")==0) 
	{
		Token=MCopyStr(Token,"DefaultGroup=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-r")==0) 
	{
		Token=MCopyStr(Token,"ChRoot=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-h")==0) ParseConfigItem("ChHome");
	else if (strcmp(argv[i],"-key")==0) 
	{
		Token=MCopyStr(Token,"SSLKey=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-cert")==0) 
	{
		Token=MCopyStr(Token,"SSLCert=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-cgi")==0) 
	{
		Token=MCopyStr(Token,"Path=cgi,/cgi-bin/,",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-ep")==0) 
	{
		Token=MCopyStr(Token,"Path=files,,",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-denied")==0) 
	{
		Token=MCopyStr(Token,"DenyUsers=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-allowed")==0) 
	{
		Token=MCopyStr(Token,"AllowUsers=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-realm")==0) 
	{
		Token=MCopyStr(Token,"AuthRealm=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-dirtype")==0) 
	{
		Token=MCopyStr(Token,"DirListType=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (strcmp(argv[i],"-hashfile")==0) 
	{
		Token=MCopyStr(Token,"ScriptHashFile=",argv[++i],NULL);
		ParseConfigItem(Token);
	}
	else if (
						(strcmp(argv[i],"-version")==0) ||
						(strcmp(argv[i],"--version")==0) 
					)
	{
		printf("version: %s\n",Version); 
		exit(1);
	}
	else if (strcmp(argv[i],"-clientnames")==0) Settings->Flags |= FLAG_LOOKUP_CLIENT;
	else if (
						(strcmp(argv[i], "-?")==0) ||
						(strcmp(argv[i], "-help")==0) ||
						(strcmp(argv[i], "--help")==0)
					) 
	{
		PrintUsage();
		exit(0);
	}
	else 
	{
		printf("UNKNOWN ARGUMENT: [%s]\n",argv[i]);
		exit(1);
	}
}


}




int ChildFunc(void *Data)
{
		ParentProcessPipe=STREAMFromDualFD(0,1);
		HTTPServerHandleConnection((HTTPSession *) Data);
		STREAMClose(ParentProcessPipe);
		LogFileFlushAll(TRUE);
		_exit(0);
}

void AcceptConnection(int ServiceSock)
{
int fd, infd, outfd, errfd;
char *Tempstr=NULL, *ptr;
HTTPSession *Session;
STREAM *S;
int pid;

		//Check if log file has gotten big and rotate if needs be
		LogFileCheckRotate(Settings.LogPath);

		Session=HTTPSessionCreate();
		fd=TCPServerSockAccept(ServiceSock,&Session->ClientIP);
		Session->S=STREAMFromFD(fd);
		STREAMSetFlushType(Session->S, FLUSH_FULL,0);

		pid=PipeSpawnFunction(&infd,&outfd,NULL, ChildFunc, Session);
		Tempstr=FormatStr(Tempstr,"%d",pid);
		S=STREAMFromDualFD(outfd, infd);
		ListAddNamedItem(Connections,Tempstr,S);

	//Closes 'fd' too
	STREAMClose(Session->S);
	DestroyHTTPSession(Session);
	DestroyString(Tempstr);
}


void CollectChildProcesses()
{
int i, pid;
char *Tempstr=NULL;
ListNode *Curr;

	for (i=0; i < 20; i++) 
	{
		pid=waitpid(-1,NULL,WNOHANG);
		if (pid==-1) break;

		Tempstr=FormatStr(Tempstr,"%d",pid);
		Curr=ListFindNamedItem(Connections,Tempstr);
		if (Curr)
		{
			STREAMClose((STREAM *) Curr->Item);
			ListDeleteNode(Curr);
		}
	}
DestroyString(Tempstr);
}


/*
void WatchConnections(int ListenSock)
{
fd_set inputs;
int highfd, result;
ListNode *Curr, *Next;
STREAM *S;

FD_ZERO(&inputs);
FD_SET(ListenSock,&inputs);
highfd=ListenSock;

Curr=ListGetNext(Connections);
while (Curr)
{
	S=(STREAM *) Curr->Item;
	if (S)
	{
		//Check for data left in buffer
		if (S->InEnd > S->InStart) HandleChildProcessRequest(S);
		FD_SET(S->in_fd,&inputs);
		if (S->in_fd > highfd) highfd=S->in_fd;
	}
	Curr=ListGetNext(Curr);
}

result=select(highfd+1,&inputs,NULL,NULL,NULL);
if (result > 0)
{
	if (FD_ISSET(ListenSock,&inputs)) AcceptConnection(ListenSock);

	Curr=ListGetNext(Connections);
	while (Curr)
	{
		Next=ListGetNext(Curr);
		S=(STREAM *) Curr->Item;
		if (S && (! (SS->State & SS_EMBARGOED)) && FD_ISSET(S->in_fd,&inputs))
		{		
			result=HandleChildProcessRequest(S);
			if (! result) 
			{
				STREAMClose(S);
				ListDeleteNode(Curr);
			}
		}
		Curr=Next;
	}
}
else if (result==-1)
{
	sleep(2); //so we don't 'spin'	
}



}
*/

void WatchConnections(STREAM *ListenSock)
{


}


void InitSettings()
{
time_t Now;
struct utsname UnameData;

//Initialise timezone information, this is so that
//we don't get erratic times in log files from forked
//chrooted processes
time(&Now);
localtime(&Now);
srand(Now+getpid());
SetTimezoneEnv();


uname(&UnameData);
memset(&Settings,0,sizeof(TSettings));
Settings.MaxLogSize=999999;
Settings.LogPath=CopyStr(Settings.LogPath,"SYSLOG");
Settings.ConfigPath=CopyStr(Settings.ConfigPath,"/etc/alaya.conf");
Settings.DefaultDir=CopyStr(Settings.DefaultDir,"./");
Settings.AuthPath=CopyStr(Settings.AuthPath,"/etc/alaya.auth");
Settings.BindAddress=CopyStr(Settings.BindAddress,"");
Settings.AuthMethods=CopyStr(Settings.AuthMethods,"native,accesstoken");
Settings.AuthRealm=CopyStr(Settings.AuthRealm,UnameData.nodename);
Settings.DirListFlags=DIR_SHOWFILES | DIR_FANCY;
Settings.IndexFiles=CopyStr(Settings.IndexFiles,"index.html,dir.html");
Settings.M3UFileTypes=CopyStr(Settings.M3UFileTypes,".mp3,.ogg,.mp4,.flv,.webm,.m4v,.m4a,.aac");
Settings.VPaths=ListCreate();
Settings.HostConnections=ListCreate();
Settings.ScriptHandlers=ListCreate();
Settings.LoginEntries=ListCreate();
Settings.Port=80;
}

void ReadConfigFile(TSettings *Settings)
{
STREAM *S;
char *Tempstr=NULL;


S=STREAMOpenFile(Settings->ConfigPath,O_RDONLY);
if (S)
{
Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
	StripLeadingWhitespace(Tempstr);
	StripTrailingWhitespace(Tempstr);
	if (StrLen(Tempstr)) ParseConfigItem(Tempstr);
	Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);
}

DestroyString(Tempstr);
}



main(int argc, char *argv[])
{
STREAM *ServiceSock, *S;
int fd;
char *Tempstr=NULL;
int result;


//Drop most capabilities
DropCapabilities(CAPS_LEVEL_STARTUP);
nice(10);
InitSettings();

openlog("alaya",LOG_PID, LOG_DAEMON);

Connections=ListCreate();


ParseCommandLineArgs(argc,argv,&Settings);
ReadConfigFile(&Settings);
PostProcessSettings(&Settings);

//Do this before any logging!
if (! (Settings.Flags & FLAG_NODEMON)) demonize();


LogFileSetValues(Settings.LogPath, LOGFILE_LOGPID|LOGFILE_LOCK|LOGFILE_MILLISECS, Settings.MaxLogSize, 10);
LogToFile(Settings.LogPath, "Alaya starting up. Version %s",Version);

LoadFileMagics("/etc/mime.types","/etc/magic");

fd=InitServerSock(Settings.BindAddress,Settings.Port);
if (fd==-1)
{
	LogToFile(Settings.LogPath, "Cannot bind to port %s:%d",Settings.BindAddress,Settings.Port);
	printf("Cannot bind to port %s:%d\n",Settings.BindAddress,Settings.Port);
	exit(1);
}


Tempstr=FormatStr(Tempstr,"alaya-%s-port%d",Settings.BindAddress,Settings.Port);
WritePidFile(Tempstr);

ServiceSock=STREAMFromFD(fd);
ListAddItem(Connections,ServiceSock);

//We no longer need the 'bind port' capablity
DropCapabilities(CAPS_LEVEL_NETBOUND);

while (1)
{
S=STREAMSelect(Connections,NULL);

if (S)
{
	if (S==ServiceSock) AcceptConnection(S->in_fd);
	else 
	{
		result=HandleChildProcessRequest(S);
		if (! result) 
		{
			ListDeleteItem(Connections,S);
			STREAMClose(S);
		}
	}
}

CollectChildProcesses();
}

LogFileFlushAll(TRUE);
DestoryString(Tempstr);
}
