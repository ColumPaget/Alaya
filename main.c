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
#include "Settings.h"
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
}




int ChildFunc(void *Data)
{
HTTPSession *Session;

		ParentProcessPipe=STREAMFromDualFD(0,1);
		Session=(HTTPSession *) Data;
		Session->StartDir=CopyStr(Session->StartDir,Settings.DefaultDir);
		STREAMSetFlushType(Session->S,FLUSH_FULL,4096);
		STREAMSetTimeout(Session->S,5);

		HTTPServerHandleConnection(Session);

		STREAMClose(Session->S);
		HTTPSessionDestroy(Session);

		STREAMClose(ParentProcessPipe);
		LogFileFlushAll(TRUE);
		_exit(0);
}

void AcceptConnection(int ServiceSock)
{
int fd, infd, outfd;
char *Tempstr=NULL;
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
	HTTPSessionDestroy(Session);
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
LogFileSetValues(Settings.LogPath, LOGFILE_LOGPID|LOGFILE_LOCK|LOGFILE_MILLISECS, Settings.MaxLogSize, 10);
LogToFile(Settings.LogPath, "%s",Msg);
}



void SetResourceLimits()
{
struct rlimit limit;

getrlimit(RLIMIT_AS, &limit);
limit.rlim_cur=(rlim_t) ParseHumanReadableDataQty(Settings.AddressSpace, 0);
setrlimit(RLIMIT_AS, &limit);

getrlimit(RLIMIT_STACK, &limit);
limit.rlim_cur=(rlim_t) ParseHumanReadableDataQty(Settings.StackSize, 0);
setrlimit(RLIMIT_STACK, &limit);
}


main(int argc, char *argv[])
{
STREAM *ServiceSock, *S;
int fd;
char *Tempstr=NULL;
int result, i;


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

signal(SIGHUP, SigHandler);

LoadFileMagics("/etc/mime.types","/etc/magic");

//Allow 5 secs for any previous instance of alaya to shutdown
for (i=0; i < 5; i++)
{
	fd=InitServerSock(Settings.BindAddress,Settings.Port);
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
		result=HandleChildProcessRequest(S);
		if (! result) 
		{
			ListDeleteItem(Connections,S);
			STREAMClose(S);
		}
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
