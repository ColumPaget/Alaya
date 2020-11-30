#include "auth_client_certificate.h"

//Will only return false if FLAG_SSL_CERT_REQUIRED is set
int auth_client_certificate(HTTPSession *Session, STREAM *S)
{
    const char *ptr;
    int result=TRUE;

    ptr=STREAMGetValue(S,"SSL:CertificateVerify");

    if (StrValid(ptr) && (strcmp(ptr,"no certificate") !=0)  )
    {
        LogToFile(Settings.LogPath,"AUTH SSL Certificate Provided by '%s@%s'. Subject=%s Issuer=%s", Session->UserName, Session->ClientIP,STREAMGetValue(S,"SSL:CertificateSubject"), STREAMGetValue(S,"SSL:CertificateIssuer"));

        if (strcmp(ptr,"OK")!=0)
        {
            if (Settings.AuthFlags & FLAG_AUTH_CERT_REQUIRED)
            {
                LogToFile(Settings.LogPath,"AUTH: ERROR: SSL Certificate REQUIRED from client '%s@%s'. Invalid Certificate. Error was: %s", Session->UserName, Session->ClientIP, ptr);
                result=FALSE;
            }
            else LogToFile(Settings.LogPath,"AUTH: SSL Certificate Optional for client '%s@%s'. Invalid Certificate. Error was: %s", Session->UserName, Session->ClientIP, ptr);

            LogFileFlushAll(TRUE);
        }
    }
    else if (Settings.AuthFlags & FLAG_AUTH_CERT_REQUIRED) LogToFile(Settings.LogPath,"AUTH: ERROR: SSL Certificate REQUIRED from client '%s@%s'. Missing Certificate.", Session->UserName, Session->ClientIP);


    return(result);
}

