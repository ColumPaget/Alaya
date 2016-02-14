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

void SigHandler(int sig)
{
if (sig==SIGHUP) Settings.Flags |= FLAG_SIGHUP_RECV;
signal(SIGHUP, SigHandler);

//This is to stop select restarting if we get a SIGCHLD, if we get a signal
//we need to clean it up!
signal(SIGCHLD, SigHandler);
}




int ChildFunc(void *Data)
{
HTTPSession *Session;

		ParentProcessPipe=STREAMFromDualFD(0,1);
		Session=(HTTPSession *) Data;
		Session->StartDir=CopyStr(Session->StartDir,Settings.DefaultDir);
		STREAMSetFlushType(Session->S,FLUSH_FULL,0,4096);
		STREAMSetTimeout(Session->S,Settings.ActivityTimeout);

		HTTPServerHandleConnection(Session);

		STREAMClose(Session->S);
		HTTPSessionDestroy(Session);

		STREAMClose(ParentProcessPipe);
		//LogFileFlushAll(TRUE);
		_exit(0);
}

void AcceptConnection(int ServiceSock)
{
int fd, infd, outfd;
char *Tempstr=NULL;
HTTPSession *Session;
STREAM *S;
pid_t pid;

		//Check if log file has gotten big and rotate if needs be
		LogFileCheckRotate(Settings.LogPath);

		Session=HTTPSessionCreate();
		fd=TCPServerSockAccept(ServiceSock,&Session->ClientIP);
		Session->S=STREAMFromFD(fd);
		STREAMSetFlushType(Session->S, FLUSH_FULL,0,0);

		pid=PipeSpawnFunction(&infd,&outfd,NULL, ChildFunc, Session);
		Tempstr=FormatStr(Tempstr,"%d",pid);
		S=STREAMFromDualFD(outfd, infd);
		ListAddNamedItem(Connections,Tempstr,S);

	//Close the *socket* connection, as this parent app no longer needsto speak to it.
	//however, the pipe connection to the child process stays open in Connectoins list
	STREAMClose(Session->S);
	HTTPSessionDestroy(Session);
	DestroyString(Tempstr);
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
	if (StrLen(Curr->Tag))
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

DestroyString(PidsList);
DestroyString(StatusList);
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

val= (rlim_t) ParseHumanReadableDataQty(Settings.AddressSpace, 0);
if (val > 0)
{
getrlimit(RLIMIT_AS, &limit);
limit.rlim_cur=val;
setrlimit(RLIMIT_AS, &limit);
}

val= (rlim_t) ParseHumanReadableDataQty(Settings.AddressSpace, 0);
if (val > 0)
{
getrlimit(RLIMIT_STACK, &limit);
limit.rlim_cur=val;
setrlimit(RLIMIT_STACK, &limit);
}
}


main(int argc, char *argv[])
{
STREAM *ServiceSock, *S;
int fd;
char *Tempstr=NULL;
int result, i;
pid_t pid;


SetTimezoneEnv();

//Drop most capabilities
DropCapabilities(CAPS_LEVEL_STARTUP);
nice(10);
InitSettings();

if (StrLen(Settings.Timezone)) setenv("TZ",Settings.Timezone,TRUE);
//LibUsefulMemFlags |= MEMORY_CLEAR_ONFREE;

openlog("alaya",LOG_PID, LOG_DAEMON);

Connections=ListCreate();


ParseSettings(argc,argv,&Settings);
ReadConfigFile(&Settings);
ParseSettings(argc,argv,&Settings);
PostProcessSettings(&Settings);

if (Settings.Flags & FLAG_SSL_PFS) 
{
	//if (! StrLen(LibUsefulGetValue("SSL-DHParams-File"))) OpenSSLGenerateDHParams();
}

//Do this before any logging!
if (! (Settings.Flags & FLAG_NODEMON)) demonize();

SetResourceLimits();

Tempstr=MCopyStr(Tempstr, "Alaya Starting up. Version: ",Version,NULL);
ReopenLogFile(Tempstr);

//Not only handles signals, but registers itself too, so we
//run it to set up signal handling
SigHandler(0);

LoadFileMagics("/etc/mime.types","/etc/magic");

//Allow 5 secs for any previous instance of alaya to shutdown
for (i=0; i < 5; i++)
{
	fd=InitServerSock(SOCK_STREAM, Settings.BindAddress,Settings.Port);
	if (fd != -1) break;
	sleep(1);
}

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
DestroyString(Tempstr);
}
