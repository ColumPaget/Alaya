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
#include "MimeType.h"
#include "ChrootHelper.h"
#include "server.h"
#include <sys/resource.h>

ListNode *MimeTypes=NULL;
ListNode *Connections=NULL;
STREAM *ParentProcessPipe=NULL;


//used in order to overwrite argc and argv to display connection info in 'ps' listings
int alaya_argc=0;
char *alaya_argv[];

void SigHandler(int sig)
{
if (sig==SIGHUP) Settings.Flags |= FLAG_SIGHUP_RECV;

//we do not want SIGPIPE to kill the parent process if a child process exits!
signal(SIGPIPE, SigHandler);

signal(SIGHUP, SigHandler);

//This is to stop select restarting if we get a SIGCHLD, if we get a signal
//we need to clean it up!
signal(SIGCHLD, SigHandler);
}




int ChildFunc(void *Data, int Flags)
{
HTTPSession *Session;
int i;

		//go back to the default behavior for SIGPIPE. If a child process gets disconnected
		//from anything we don't want to keep sending to it.
		signal(SIGPIPE, SIG_DFL);

		ParentProcessPipe=STREAMFromDualFD(0,1);
		STREAMSetTimeout(ParentProcessPipe, 10);
		Session=(HTTPSession *) Data;
		Session->StartDir=CopyStr(Session->StartDir,Settings.DefaultDir);
		STREAMSetFlushType(Session->S,FLUSH_FULL,0,4096);
		STREAMSetTimeout(Session->S,Settings.ActivityTimeout);
		/*
		for (i=2; i < 1024; i++) 
		{
			if (i != Session->S->in_fd) close(i);
		}
		*/

		ListDestroy(Connections, STREAMClose);

		ProcessSetTitle("alaya peer=%s", STREAMGetValue(Session->S, "PeerIP"));
		HTTPServerHandleConnection(Session);

		STREAMClose(Session->S);
		HTTPSessionDestroy(Session);

		STREAMClose(ParentProcessPipe);
		//LogFileFlushAll(TRUE);
		_exit(0);
}

void AcceptConnection(STREAM *Serv)
{
int fd, infd, outfd;
char *Tempstr=NULL;
HTTPSession *Session;
STREAM *S;
pid_t pid;

		//Check if log file has gotten big and rotate if needs be
		LogFileCheckRotate(Settings.LogPath);

		Session=HTTPSessionCreate();
		Session->S=STREAMServerAccept(Serv);
		STREAMSetFlushType(Session->S, FLUSH_FULL,0,0);

		pid=PipeSpawnFunction(&infd,&outfd,NULL, ChildFunc, Session, "");
		Tempstr=FormatStr(Tempstr,"%d",pid);
		S=STREAMFromDualFD(outfd, infd);
		ListAddNamedItem(Connections,Tempstr,S);

	//Close the *socket* connection, as this parent app no longer needs to speak to it.
	//however, the pipe connection to the child process stays open in Connections list
	STREAMClose(Session->S);
	HTTPSessionDestroy(Session);
	Destroy(Tempstr);
}



//There's two processes involved in a connection, the main service process and 
//possibly a 'helper' process that performs out-of-chroot tasks for the service
//process. Either of these can signal closing the socket, the service task just
//by exiting, and the helper by exiting with status '0' (which we also get if
//it crashed rather than exiting)
void CollectChildProcesses()
{
int i, status;
#define NO_OF_PROCESSES 20
pid_t *PidsList, owner, helper;
int *StatusList;
ListNode *Curr, *Next;
STREAM *S;

PidsList=(int *) calloc(NO_OF_PROCESSES,sizeof(pid_t));
StatusList=(int *) calloc(NO_OF_PROCESSES,sizeof(int));
for (i=0; i < 20; i++) 
{
	owner=waitpid(-1,&status,WNOHANG);
	if (owner < 1) break;
	PidsList[i]=owner;
	if (WIFEXITED(status)) StatusList[i]=WEXITSTATUS(status);
}

Curr=ListGetNext(Connections);
while (Curr)
{
	Next=ListGetNext(Curr);

	S=(STREAM *) Curr->Item;
	if (StrValid(Curr->Tag))
	{
	owner=strtol(Curr->Tag, NULL, 10);
	helper=(int) STREAMGetItem(S,"HelperPid");

	for (i=0; i < NO_OF_PROCESSES; i++)
	{
		if (PidsList[i] < 1) break;
		if (
					(owner==PidsList[i]) ||
					((helper==PidsList[i]) && (StatusList[i]==0))
			)
		{
			STREAMClose(S);
			ListDeleteNode(Curr);
			break;
		}
	}
	}

	Curr=Next;
}

Destroy(PidsList);
Destroy(StatusList);
}



void SetGMT()
{
time_t Now;

setenv("TZ","GMT",TRUE);
time(&Now);
localtime(&Now);
}


void ReopenLogFile(char *Msg)
{
LogFileClose(Settings.LogPath);
LogFileFindSetValues(Settings.LogPath, LOGFILE_LOGPID|LOGFILE_LOCK|LOGFILE_TIMESTAMP|LOGFILE_MILLISECS, Settings.MaxLogSize, Settings.MaxLogRotate, 10);
LogToFile(Settings.LogPath, "%s",Msg);
}



void SetResourceLimits()
{
struct rlimit limit;
rlim_t val;

val= (rlim_t) FromMetric(Settings.AddressSpace, 0);
if (val > 0)
{
getrlimit(RLIMIT_AS, &limit);
limit.rlim_cur=val;
setrlimit(RLIMIT_AS, &limit);
}

val= (rlim_t) FromMetric(Settings.AddressSpace, 0);
if (val > 0)
{
getrlimit(RLIMIT_STACK, &limit);
limit.rlim_cur=val;
setrlimit(RLIMIT_STACK, &limit);
}
}



// This function sets up the TLS/SSL environment, logging some warnings if settings are
// inconsistent
void InitSSL()
{
const char *ptr;

#ifdef HAVE_LIBSSL
	ptr=LibUsefulGetValue("SSL:PermittedCiphers");
	if (! StrValid(ptr))
	{
		LibUsefulSetValue("SSLPermitted:Ciphers", "DH+AESGCM:DH+AES256:DH+CAMELLIA256:ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+AES:EDH-RSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:CAMELLIA256:AES128-SHA256:CAMELLIA128:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:DES-CBC3-SHA:!ADH:!AECDH:!aNULL:!eNULL:!LOW:!EXPORT:!MD5");
	}

	ptr=LibUsefulGetValue("SSL_VERIFY_CERTFILE");
	if (! StrValid(ptr)) ptr=LibUsefulGetValue("SSL_VERIFY_CERTDIR");

	if ((Settings.AuthFlags & FLAG_AUTH_CERT_REQUIRED) && (! StrValid(ptr)))
	{
		HandleError(ERR_PRINT|ERR_LOG|ERR_EXIT, "ERROR: Client SSL Certificate required, but no certificate verify file/directory given.\nPlease Supply one with the -verify-path command-line-argument, or the SSLVerifyPath config file entry.");
	}

	if (Settings.Flags & FLAG_SSL_PFS) 
	{
	ptr=LibUsefulGetValue("SSL:DHParamsFile");
	if (! StrValid(ptr))
	{
		if (Settings.Flags & FLAG_PFS_GENERATE) 
		{
			printf("Generating Diffie-Helman parameters\n");
			OpenSSLGenerateDHParams();
			printf("DONE Generating Diffie-Helman parameters\n");
		}
		else HandleError(ERR_PRINT|ERR_LOG, "WARNING: No DH parameters file given for SSL. Perfect Forward Secrecy can only be achieved with Eliptic Curve (ECDH) methods. ECDH depends on fixed values recomended by the U.S. National Institute of Standards and technology (NIST) and thus may not be trustworthy.\n\nCreate a DHParams file with 'openssl dhparam -2 -out dhparams.pem 4096' and give the path to it using the -dhparams command-line-argument or the DHParams config file entry, if you want DiffieHelman key exchange for Perfect Forward Secrecy.");

	}
	}
#endif
}



int ServiceSocketsInit(ListNode *Connections)
{
char *Tempstr=NULL, *Token=NULL, *Config=NULL;
const char *ptr;
int fd, BoundCount=0;
STREAM *S;

////Allow 5 secs for any previous instance of alaya to shutdown
//for (i=0; i < 5; i++)

ptr=GetToken(Settings.BindAddress,",",&Token,0);
while (ptr)
{
	//if it starts with a '/' it's a unix Socket
	if (*Token=='/') 
	{
		Tempstr=MCopyStr(Tempstr,"unix:",Token,NULL);
		Config=CopyStr(Config, "");
	}
	else 
	{
		
		if (Settings.Flags & FLAG_USE_FASTOPEN) Config=CatStr(Config, "F");
		if (Settings.Flags & FLAG_USE_REUSEPORT) Config=CatStr(Config, "P");
		Tempstr=FormatStr(Tempstr, " listen=", Settings.ListenQueueLen);

		Tempstr=FormatStr(Tempstr,"tcp:%s:%d",Token,Settings.Port);
	}

	S=STREAMServerNew(Tempstr, Config);
	if (! S)
	{
		sleep(1);
		S=STREAMServerNew(Tempstr, Config);
	}

	if (S) 
	{
			ListAddItem(Connections,S);
			if (StrLen(Token)==0) Tempstr=MCopyStr(Tempstr,"alaya", Token, NULL);
			else Tempstr=MCopyStr(Tempstr,"alaya-", Token, NULL);
			WritePidFile(Tempstr);
			BoundCount++;
	}
	else
	{
		LogToFile(Settings.LogPath, "Cannot bind to port %s",Tempstr);
		printf("Cannot bind to port %s\n",Tempstr);
	}

	ptr=GetToken(ptr, ",",&Token,0);
}

if (BoundCount==0)
{
printf("Failed to bind any interface! Exiting.");
LogToFile(Settings.LogPath, "Failed to bind any interface! Exiting.");
exit(1);
}

Destroy(Tempstr);
Destroy(Config);
Destroy(Token);
}


main(int argc, char *argv[])
{
STREAM *S;
int fd;
char *Tempstr=NULL;
int result, i;
pid_t pid;

ProcessTitleCaptureBuffer(argv);

SetTimezoneEnv();

//Drop most capabilities
DropCapabilities(CAPS_LEVEL_STARTUP);
nice(10);
InitSettings();


//We should handle failed User/Group switches within alaya,
//so we don't need libUseful to handle them for us
LibUsefulSetValue("SwitchUserAllowFail","yes");
LibUsefulSetValue("SwitchGroupAllowFail","yes");

if (StrValid(Settings.Timezone)) setenv("TZ",Settings.Timezone,TRUE);
//LibUsefulMemFlags |= MEMORY_CLEAR_ONFREE;

openlog("alaya",LOG_PID, LOG_DAEMON);

Connections=ListCreate();

//do this initially to pick up -c <config file> option
SettingsParseCommandLine(argc,argv,&Settings);
ReadConfigFile(Settings.ConfigPath);
//do it again to override anything read from the config file
SettingsParseCommandLine(argc,argv,&Settings);
PostProcessSettings(&Settings);

SetResourceLimits();

Tempstr=FormatStr(Tempstr, "Alaya Version %s Starting up on %s:%d",Version,Settings.BindAddress,Settings.Port);
ReopenLogFile(Tempstr);


//Not only handles signals, but registers itself too, so we
//run it to set up signal handling
SigHandler(0);

if (Settings.Flags & FLAG_SSL) InitSSL();

LoadFileMagics("/etc/mime.types","/etc/magic");


ServiceSocketsInit(Connections);


//Do this before any logging!
if (! (Settings.Flags & FLAG_NODEMON)) demonize();


//We no longer need the 'bind port' capablity
DropCapabilities(CAPS_LEVEL_NETBOUND);

while (1)
{
S=STREAMSelect(Connections,NULL);

if (S)
{
	switch (S->Type)
	{
	case STREAM_TYPE_UNIX_SERVER:
	case STREAM_TYPE_TCP_SERVER:
		AcceptConnection(S);
	break;

	default:
		//This handles a request from a child process that is servicing a connection
		//Often they are chrooted and need to call back to the parent process to 
		//perform tasks for them. HandleChildProcessRequest can either return '0',
		//which means the request was dealt with or failed, and the connection can
		//be closed, or a pid. We book the pid against the appropriate connection
		//so when the process exits we can use its exit status to decide whether the
		//connection has been closed, or is 'keep alive'
		
		pid=HandleChildProcessRequest(S);
		if (pid==STREAM_CLOSED) 
		{
			ListDeleteItem(Connections,S);
			STREAMClose(S);
		}
		else if (pid > 0) STREAMSetItem(S,"HelperPid",(void *) pid);
	break;
	}
}

if (Settings.Flags & FLAG_SIGHUP_RECV) 
{
	ReopenLogFile("Reopening Log File");
	Settings.Flags &= ~FLAG_SIGHUP_RECV;
}
CollectChildProcesses();
}

LogFileFlushAll(TRUE);
Destroy(Tempstr);
}
