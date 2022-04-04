#include "proxy.h"
#include "server.h"

static void ProxyCopyData(STREAM *Client, STREAM *Target)
{
    ListNode *List;
    STREAM *S;
    char *Buffer=NULL;
    int result, total=0;

    List=ListCreate();
    ListAddItem(List,Client);
    ListAddItem(List,Target);

    Buffer=SetStrLen(Buffer,BUFSIZ);

    while (1)
    {
        S=STREAMSelect(List, NULL);

        if (S)
        {
            result=STREAMReadBytes(S, Buffer, BUFSIZ);
            if (result > 0) total+=result;
            if (result ==EOF) break;

            if (S==Client)
            {
                STREAMWriteBytes(Target,Buffer,result);
                STREAMFlush(Client);
            }
            else
            {
                STREAMWriteBytes(Client,Buffer,result);
                STREAMFlush(Target);
            }
        }
    }

    Destroy(Buffer);
    ListDestroy(List,NULL);
}



//none of the usual complexity of 'HttpServerSendResponse'
static void HTTPProxySendResponse(STREAM *S, const char *Response)
{
    char *Date=NULL;

    STREAMWriteLine(Response,S);
    Date=CopyStr(Date,GetDateStr("Date: %a, %d %b %Y %H:%M:%S %Z\r\n",Settings.Timezone));
    STREAMWriteLine(Date,S);
    STREAMWriteLine("Connection: close\r\n",S);
    STREAMWriteLine("\r\n",S);
    STREAMFlush(S);
    LogToFile(Settings.LogPath,"PROXY: %s", Response);

    Destroy(Date);
}

//this function relates to old-fashioned HTTP proxy methods using GET and POST with a full URL
void HTTPProxyRGETURL(HTTPSession *Session)
{
    STREAM *TargetS;
    char *Tempstr=NULL;
    HTTPInfoStruct *Info;
    ListNode *Curr;

    if (StrValid(Session->Arguments)) Tempstr=MCopyStr(Tempstr,Session->Path,"?",Session->Arguments,NULL);
    else Tempstr=CopyStr(Tempstr,Session->Path);

    if (Session->MethodID==METHOD_RPOST)
    {
        Info=HTTPInfoFromURL("POST",Tempstr);
        Info->PostContentLength=Session->ContentSize;
        if (StrValid(Session->ContentType))
        {
            Info->PostContentType=CopyStr(Info->PostContentType,Session->ContentType);
            if (StrValid(Session->ContentBoundary)) Info->PostContentType=MCatStr(Info->PostContentType, "; boundary=", Session->ContentBoundary, NULL);
        }
    }
    else Info=HTTPInfoFromURL("GET",Tempstr);

    if (StrValid(Session->RemoteAuthenticate))
    {
        SetVar(Info->CustomSendHeaders,"Authorization",Session->RemoteAuthenticate);
    }

    Curr=ListGetNext(Session->Headers);
    while (Curr)
    {
        //Don't use 'SetVar' here, as we can have multiple cookie headers
        if (strcasecmp(Curr->Tag,"Cookie")==0) ListAddNamedItem(Info->CustomSendHeaders,"Cookie",CopyStr(NULL,Curr->Item));
        Curr=ListGetNext(Curr);
    }

    Info->Flags |= HTTP_NODECODE | HTTP_NOCOOKIES;

//We are probably chrooted and thus unable to do DNS lookups.
//As parent process to do it for us
    /*
    if (ParentProcessPipe)
    {
    Tempstr=MCopyStr(Tempstr,"GETIP"," ",Info->Host,"\n",NULL);
    STREAMWriteLine(Tempstr,ParentProcessPipe);
    STREAMFlush(ParentProcessPipe);
    Tempstr=STREAMReadLine(Tempstr,ParentProcessPipe);
    StripTrailingWhitespace(Tempstr);
    LogToFile(Settings.LogPath,"GOTIP: %s\n",Tempstr);
    if (StrValid(Tempstr)) Info->Host=CopyStr(Info->Host,Tempstr);
    }
    */



    TargetS=HTTPTransact(Info);

    if (TargetS)
    {
        LogToFile(Settings.LogPath,"PROXY: Connected To %s",Session->Path);
        //Must send POST data before doing anything else
        if (Session->ContentSize > 0)
        {
            STREAMSendFile(Session->S, TargetS, Session->ContentSize, SENDFILE_LOOP);
            //we shouldn't need this CR-LF, as we've sent 'Content-Length' characters
            //but some CGI implementations seem to expect it, and it does no harm to
            //provide it anyway
            STREAMWriteLine("\r\n", TargetS);
            STREAMFlush(TargetS);

            //For POST we must call transact again
            HTTPTransact(Info);
        }

        STREAMWriteLine("HTTP/1.1 200 OK Connection Established\r\n", Session->S);
        Curr=ListGetNext(Info->ServerHeaders);
        while (Curr)
        {
            Tempstr=MCopyStr(Tempstr,Curr->Tag,": ",Curr->Item,"\r\n",NULL);
            STREAMWriteLine(Tempstr, Session->S);
            Curr=ListGetNext(Curr);
        }
        STREAMWriteLine("Connection: close\r\n",Session->S);
        STREAMWriteLine("\r\n",Session->S);


        //Still have to do this, it's a two-way copy
        ProxyCopyData( Session->S, TargetS);
    }
    else HTTPProxySendResponse( Session->S, "HTTP/1.1 502 Connection Failed\r\n");

    STREAMClose(TargetS);

    Destroy(Tempstr);
}


//ClientHeads->Path will normally start with a '/', and may not have a port number
//so we reformat it here to be consistent
void HTTPProxyReformatPath(HTTPSession *ClientHeads)
{
    char *Host=NULL;
    int Port=443;
    const char *ptr;

    ptr=ClientHeads->Path;
    while (*ptr=='/') ptr++;
    ptr=GetToken(ptr, ":", &Host,0);
    if StrValid(ptr) Port=atoi(ptr);
    ClientHeads->Path=FormatStr(ClientHeads->Path, "%s:%d", Host, Port);

    Destroy(Host);
}


#define HTTP_PROXY_DENY 0
#define HTTP_PROXY_ALLOW 1
#define HTTP_PROXY_SSL 2

int HTTPProxyConnectAllowed(HTTPSession *ClientHeads)
{
    ListNode *Curr;
    char *Tempstr=NULL, *Token=NULL;
    char *Host=NULL;
    const char *ptr;
    int RetVal=HTTP_PROXY_DENY;

    Curr=ListGetNext(Settings.ProxyConfig);
    while (Curr)
    {

        if (fnmatch(Curr->Tag, ClientHeads->Path, FNM_CASEFOLD)==0)
        {
            if (Curr->ItemType == TRUE) RetVal = HTTP_PROXY_ALLOW;

            ptr=GetToken(Curr->Item, "\\S|,", &Token, GETTOKEN_MULTI_SEP);
            while (ptr)
            {
                if (strncasecmp(Token, "redirect=", 9)==0)
                {
                    ClientHeads->Path=CopyStr(ClientHeads->Path, Token+9);
                }
                if (strcasecmp(Token,"https")==0) RetVal |= HTTP_PROXY_SSL;
                if (strcasecmp(Token,"ssl")==0) RetVal |= HTTP_PROXY_SSL;
                if (strcasecmp(Token,"tls")==0) RetVal |= HTTP_PROXY_SSL;
                ptr=GetToken(ptr, "\\S|,", &Token, GETTOKEN_MULTI_SEP);
            }
        }

        Curr=ListGetNext(Curr);
    }


    Destroy(Tempstr);
    Destroy(Token);

    return(RetVal);
}


//this function relates to SSL/HTTPS proxies using the HTTP CONNECT method
void HTTPProxyConnect(HTTPSession *Session)
{
    STREAM *TargetS=NULL;
    char *Tempstr=NULL;
    int ConnectFlags=0;

    HTTPProxyReformatPath(Session);

    ConnectFlags=HTTPProxyConnectAllowed(Session);
    if (ConnectFlags & HTTP_PROXY_ALLOW)
    {
        LogToFile(Settings.LogPath,"HTTP CONNECT: [%s]", Session->Path);

        Tempstr=MCopyStr(Tempstr, "tcp:", Session->Path, NULL);
        TargetS=STREAMOpen(Tempstr, "");
        if (TargetS)
        {
            HTTPProxySendResponse(Session->S, "HTTP/1.1 200 OK Connection Established\r\n");
            if (ConnectFlags & HTTP_PROXY_SSL) HTTPServerActivateSSL(Session, Settings.SSLKeys);
            ProxyCopyData(Session->S,TargetS);
        }
        else HTTPProxySendResponse(Session->S, "HTTP/1.1 502 Connection Failed\r\n");
    }
    else HTTPProxySendResponse(Session->S, "HTTP/1.1 502 Connection Not Permitted\r\n");

    /*
    else
    {
    	STREAMWriteLine("HTTP/1.1 400 No port given\r\n",S);
    	Tempstr=MCopyStr(Tempstr, "Server: Alaya/",Version,"\r\n",NULL);
    	STREAMWriteLine(Tempstr,S);
    	STREAMWriteLine(Date,S);
    	STREAMWriteLine("Connection: close\r\n",S);
    	STREAMWriteLine("Content-Length: 0\r\n\r\n",S);
    }
    */


    STREAMClose(TargetS);

    Destroy(Tempstr);
}



int IsProxyMethod(int Method)
{
    if (Method==METHOD_RGET) return(TRUE);
    if (Method==METHOD_RPOST) return(TRUE);
    if (Method==METHOD_CONNECT) return(TRUE);

    return(FALSE);
}



#ifdef USE_SOCKS
//this function relates to SSL/HTTPS proxies using the HTTP CONNECT method
void SocksProxyConnect(HTTPSession *Session)
{
    STREAM *TargetS=NULL;
    char *Tempstr=NULL, *Host=NULL;
    uint16_t port;
    uint32_t ip4;
    int ConnectFlags=0;
    int val;

    val=STREAMReadChar(Session->S);
    if (val==4)
    {
        val=STREAMReadChar(Session->S);
        if (val==1)
        {
            STREAMReadBytes(Session->S, &port, 2);
            STREAMReadBytes(Session->S, &ip4, 4);
            ip4=ntohl(ip4);
            port=ntohs(port);

            if (ip4 > 255) Session->Path=FormatStr(Session->Path, "%s:%d", IPtoStr(ip4), port);
            else
            {
                Session->UserName=STREAMReadToTerminator(Session->UserName, Session->S, '\0');
                Tempstr=STREAMReadToTerminator(Tempstr, Session->S, '\0');
                Session->Path=FormatStr(Session->Path, "%s:%d", Tempstr, port);
            }
        }
    }

    if (StrValid(Session->Path))
    {
        ConnectFlags=HTTPProxyConnectAllowed(Session);
        if (ConnectFlags & HTTP_PROXY_ALLOW)
        {
            LogToFile(Settings.LogPath,"SOCKS CONNECT: [%s]", Session->Path);

            Tempstr=MCopyStr(Tempstr, "tcp:", Session->Path, NULL);
            TargetS=STREAMOpen(Tempstr, "");
            if (TargetS)
            {
                val=0;
                STREAMWriteBytes(Session->S, &val, 1);
                val=0x5a;
                STREAMWriteBytes(Session->S, &val, 1);
                port=0; //these are just padding
                STREAMWriteBytes(Session->S, &port, 2);
                ip4=0; //these are just padding
                STREAMWriteBytes(Session->S, &ip4, 4);
                STREAMFlush(Session->S);

                ProxyCopyData(Session->S, TargetS);
                STREAMClose(TargetS);
            }
        }
    }

    Destroy(Tempstr);
}
#endif

