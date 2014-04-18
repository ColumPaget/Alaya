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
#include "server.h"


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
