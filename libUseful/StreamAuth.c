#include "StreamAuth.h"
#include "OpenSSL.h"
#include "PasswordFile.h"
#include "HttpUtil.h"

//did the client provide an SSL certificate as authentication?
static int STREAMAuthProcessCertificate(STREAM *S, const char *CertName, const char *CommonName)
{
    char *Require=NULL;
    int AuthResult=FALSE;

//does the certificate name/subject match out expectation?
    Require=OpenSSLCertDetailsGetCommonName(Require, STREAMGetValue(S, CommonName));
    if (CompareStr(CertName, Require)==0)
    {
        //is certificate valid
        if (CompareStr(STREAMGetValue(S, "SSL:CertificateVerify"), "OK")==0) AuthResult=TRUE;
    }

    Destroy(Require);
    return(AuthResult);
}




static int STREAMBasicAuthPasswordFile(const char *Path, STREAM *S)
{
    char *User=NULL, *Password=NULL;
    const char *ptr;
    int AuthResult=FALSE;

    ptr=STREAMGetValue(S, "Auth:Basic");
    printf("AB: [%s]\n", ptr);
    if (! StrValid(ptr)) return(FALSE);

    HTTPDecodeBasicAuth(ptr, &User, &Password);
    AuthResult=PasswordFileCheck(Path, User, Password);

    Destroy(User);
    Destroy(Password);

    return(AuthResult);
}



static int STREAMAuthProcess(STREAM *S, const char *AuthTypes)
{
    char *Key=NULL, *Value=NULL;
    const char *ptr;
    int AuthResult=FALSE;

    ptr=GetNameValuePair(AuthTypes, ";", ":",&Key, &Value);
    while (ptr)
    {
        printf("AUTH: %s\n", Key);
        if (CompareStrNoCase(Key, "basic")==0)
        {
            if (CompareStr(Value, STREAMGetValue(S, "Auth:Basic"))==0) AuthResult=TRUE;
        }
        else if (
            (CompareStrNoCase(Key, "certificate")==0) ||
            (CompareStrNoCase(Key, "cert")==0)
        )  AuthResult=STREAMAuthProcessCertificate(S, Value, "SSL:CertificateSubject");
        else if (CompareStrNoCase(Key, "issuer")==0) AuthResult=STREAMAuthProcessCertificate(S, Value, "SSL:CertificateIssuer");
        else if (strncasecmp(Key, "cookie:", 7)==0)
        {
            if (InStringList(STREAMGetValue(S, Key), Value, ",")) AuthResult=TRUE;
        }
        else if (CompareStrNoCase(Key, "ip")==0)
        {
            if (InStringList(GetRemoteIP(S->in_fd), Value, ",")) AuthResult=TRUE;
        }
        else if (CompareStrNoCase(Key, "password-file")==0) AuthResult=STREAMBasicAuthPasswordFile(Value, S);

        ptr=GetNameValuePair(ptr, ";", "=",&Key, &Value);
    }

    if (AuthResult==TRUE) STREAMSetValue(S, "STREAM:Authenticated", "Y");
    Destroy(Key);
    Destroy(Value);

    return(AuthResult);
}



int STREAMAuth(STREAM *S)
{
    const char *ptr;

    ptr=STREAMGetValue(S, "Authenticator");
    if (! StrValid(ptr)) return(TRUE);

    return(STREAMAuthProcess(S, ptr));

    return(FALSE);
}
