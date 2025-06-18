#include "Authenticate.h"
#include "auth_access_token.h"
#include "auth_unix.h"
#include "auth_pam.h"
#include "auth_alaya_native.h"




const char *AuthMethods[]= {"none", "open", "deny", "native", "pam", "pam-account", "passwd", "shadow", "digest", "certificate", "cookie", "accesstoken", "urltoken", NULL};
typedef enum {AUTHTOK_NONE, AUTHTOK_OPEN, AUTHTOK_DENY, AUTHTOK_NATIVE, AUTHTOK_PAM, AUTHTOK_PAM_ACCT, AUTHTOK_PASSWD, AUTHTOK_SHADOW, AUTHTOK_DIGEST, AUTHTOK_CERTIFICATE, AUTHTOK_COOKIE, AUTHTOK_ACCESSTOKEN, AUTHTOK_URLTOKEN} TAuthTokens;



static int CheckSSLAuthentication(HTTPSession *Session, const char *UserName)
{
    const char *ptr;

    if (! Session->S) return(FALSE);
    if (Settings.AuthFlags & FLAG_AUTH_CERT_SUFFICIENT)
    {
        ptr=STREAMGetValue(Session->S, "SSL:Certificate-Verify");
        if (StrValid(ptr) && (strcmp(ptr, "OK")==0))
        {
            ptr=STREAMGetValue(Session->S, "SSL:CertificateCommonName");
            if (StrValid(ptr) && (strcmp(ptr,UserName)==0))
            {
                LogToFile(Settings.LogPath, "AUTH: SSL-Certificate Authentication sufficient for User '%s'",UserName);
                return(TRUE);
            }
        }
    }

    return(FALSE);
}




int AuthenticateExamineMethods(const char *Methods, int LogErrors)
{
    char *Token=NULL;
    const char *ptr;
    int MethodsFound=0, val;


    LogToFile(Settings.LogPath, "CONSIDER AUTH METHODS: %s",Methods);

    ptr=GetToken(Methods, ",",&Token,0);
    while (ptr)
    {
        StripTrailingWhitespace(Token);
        StripLeadingWhitespace(Token);
        val=MatchTokenFromList(Token,AuthMethods,0);
        switch (val)
        {
        case -1:
            if (LogErrors) LogToFile(Settings.LogPath, "WARNING: unknown authentication method '%s'",Token);
            break;

        case AUTHTOK_NONE:
        case AUTHTOK_OPEN:
            MethodsFound |= AUTH_OPEN;
            break;

        case AUTHTOK_DENY:
            MethodsFound |= AUTH_DENY;
            break;

        case AUTHTOK_NATIVE:
            MethodsFound |= AUTH_NATIVE;
            Settings.AuthFlags |= FLAG_AUTH_BASIC;
            break;

        case AUTHTOK_PAM:
            MethodsFound |= AUTH_PAM;
            Settings.AuthFlags |= FLAG_AUTH_BASIC;
            break;

        case AUTHTOK_PASSWD:
            MethodsFound |= AUTH_PASSWD;
            Settings.AuthFlags |= FLAG_AUTH_BASIC;
            break;

        case AUTHTOK_SHADOW:
            MethodsFound |= AUTH_SHADOW;
            Settings.AuthFlags |= FLAG_AUTH_BASIC;
            break;

        case AUTHTOK_DIGEST:
            MethodsFound |= AUTH_DIGEST;
            Settings.AuthFlags |= FLAG_AUTH_DIGEST;
            break;

        case AUTHTOK_ACCESSTOKEN:
            MethodsFound |= AUTH_ACCESSTOKEN;
            break;

        case AUTHTOK_URLTOKEN:
            MethodsFound |= AUTH_URLTOKEN;
            break;
        }

        ptr=GetToken(ptr, ",",&Token,0);
    }



    if (LogErrors)
    {
        if ((Settings.AuthFlags & FLAG_AUTH_REQUIRED) && (MethodsFound == 0))
        {
            LogToFile(Settings.LogPath, "WARNING: NO AUTHENTICATION SYSTEM CONFIGURED, but not set to run as an 'open' system");
        }
        else if ((MethodsFound & AUTH_OPEN) && (MethodsFound != AUTH_OPEN))
        {
            LogToFile(Settings.LogPath, "WARNING: 'open' authentication is enabled along with other authentication types. 'open' authentication means no authentication, so other auth types will be disabled.");
        }
        else if (  (MethodsFound & AUTH_DIGEST) && (((MethodsFound & ~(AUTH_DIGEST | AUTH_ACCESSTOKEN | AUTH_URLTOKEN)) !=0) ) )
        {
            LogToFile(Settings.LogPath, "WARNING: 'digest' authentication is enabled along with other authentication types. Digest authentication requires plain-text passwords in the *native* alaya authentication file, and cannot authenticate against /etc/passwd, /etc/shadow or PAM.  Most clients will use digest in preference to 'basic' authentication. Thus including 'digest' will thus disable other authentication types.");
        }
    }

    Destroy(Token);

    return(MethodsFound);
}






int CheckServerAllowDenyLists(const char *UserName)
{
    char *Token=NULL;
    const char *ptr;
    int result=FALSE;

    if (StrValid(Settings.DenyUsers))
    {
        ptr=GetToken(Settings.DenyUsers, ",",&Token,GETTOKEN_QUOTES);

        while (ptr)
        {
            if (strcmp(Token,UserName)==0)
            {
                LogToFile(Settings.LogPath, "AUTH: UserName '%s' in 'DenyUsers' list. Login Denied",UserName);
                Destroy(Token);
                return(FALSE);
            }
            ptr=GetToken(ptr, ",",&Token,GETTOKEN_QUOTES);
        }
    }

    if (! StrValid(Settings.AllowUsers)) result=TRUE;
    else
    {
        ptr=GetToken(Settings.AllowUsers, ",",&Token,GETTOKEN_QUOTES);
        while (ptr)
        {
            if (strcmp(Token,UserName)==0)
            {
                if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath, "AUTH: UserName '%s' Found in 'AllowUsers' list.",UserName);
                result=TRUE;
                break;
            }
            ptr=GetToken(ptr, ",",&Token,GETTOKEN_QUOTES);
        }
    }
    Destroy(Token);
    return(result);
}



// this checks if the credentials match the 'admin user', this is a
// temporary user defined on the command-line who is used to setup
// and administer alaya
static int AuthAdminUser(HTTPSession *Session)
{
    char *Token=NULL;
    const char *ptr;
    int result=USER_UNKNOWN;

//admin user is stored as '<username>:<password>'
    ptr=GetToken(Settings.AdminUser, ":",&Token,0);
    if (StrValid(Token) && (strcmp(Session->UserName, Token)==0))
    {
        if (strcmp(Session->Password, ptr)==0) result=TRUE;
        else result=FALSE;
    }

    Destroy(Token);

    return(result);
}




int AuthenticateLookupUserDetails(HTTPSession *Session)
{
    struct passwd *pwent;
    int uid;

    uid=getuid();

//if we are not root, then we'll not be able to switch to another user
//so set realuser up to be ourselves
    if (uid !=0)
    {
        pwent=getpwuid(uid);
        Session->RealUserUID=uid;
        Session->RealUser=CopyStr(Session->RealUser, pwent->pw_name);
        return(TRUE);
    }



//if we haven't got a real user, first try looking in the 'native' authentication
//file to find a mapping from UserName to RealUser
    if (! StrValid(Session->RealUser))
    {
        AuthNativeCheck(Session, FALSE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
    }

//if we didn't find a 'real user' in the native file, try looking the username up in the system
//password file to confirm it is a real username
    if (! StrValid(Session->RealUser))
    {
        Session->RealUser=CopyStr(Session->RealUser,Session->UserName);
        pwent=getpwnam(Session->RealUser);

        //if we didn't find it, then set our real user to be the server default user
        //though really, at this point, it's a mystery where this user is configured
        if (! pwent) Session->RealUser=CopyStr(Session->RealUser,Settings.DefaultUser);
    }

//Have to do this again in case first try failed
    pwent=getpwnam(Session->RealUser);
    if (pwent)
    {
        Session->RealUserUID=pwent->pw_uid;
        Session->GroupID=pwent->pw_gid;
        if (! StrValid(Session->HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,pwent->pw_dir);

        //grent=getgrnam(Session->Group);
    }

    return(TRUE);
}



int Authenticate(HTTPSession *Session)
{
    int result=0;
    char *Token=NULL;
    const char *ptr;
    int PAMAccount=FALSE;
    char *AuthenticationsTried=NULL;
//struct group *grent;


    LogToFile(Settings.LogPath, "AUTH: Authentication '%s'. Password: '%s'", Session->UserName, Session->Password);
    if (! CheckServerAllowDenyLists(Session->UserName))
    {
        LogToFile(Settings.LogPath, "AUTH: Authentication failed for UserName '%s'. User not allowed to log in",Session->UserName);
        return(FALSE);
    }

    if (AuthAdminUser(Session)==TRUE)
    {
        LogToFile(Settings.LogPath, "AUTH: Client Authenticated as AdminUser for %s@%s", Session->UserName,Session->ClientIP);
        Session->AuthFlags |= FLAG_AUTH_ADMIN;
        return(TRUE);
    }


    AuthenticationsTried=CopyStr(AuthenticationsTried, "");
//check for this as it changes behavior of other auth types
    ptr=GetToken(Settings.AuthMethods, ",", &Token, 0);
    while (ptr)
    {
        if (strcasecmp(Token, "pam-account")==0) PAMAccount=TRUE;
        ptr=GetToken(ptr, ",", &Token, 0);
    }

    ptr=GetToken(Settings.AuthMethods, ",", &Token, 0);
    while (ptr)
    {
        if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath, "AUTH: Try to authenticate '%s' via '%s'. Remaining authentication types: %s",Session->UserName, Token, ptr);

        if (strcasecmp(Token, "open")==0) result=TRUE;
        else if (strcasecmp(Token, "native")==0)
        {
            result=AuthNativeCheck(Session,FALSE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "digest")==0)
        {
            result=AuthNativeCheck(Session,TRUE, &Session->RealUser, &Session->HomeDir, &Session->UserSettings);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "passwd")==0)
        {
            result=AuthPasswdFile(Session, &Session->RealUser, &Session->HomeDir);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "shadow")==0)
        {
            result=AuthShadowFile(Session);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "cert")==0)
        {
            result=CheckSSLAuthentication(Session, Session->UserName);
            AuthenticationsTried=MCatStr(AuthenticationsTried, "ssl-certificate ", NULL);
        }
        else if (strcasecmp(Token, "certificate")==0)
        {
            result=CheckSSLAuthentication(Session, Session->UserName);
            AuthenticationsTried=MCatStr(AuthenticationsTried, "ssl-certificate ", NULL);
        }
        else if (strcasecmp(Token, "accesstoken")==0)
        {
            result=AuthAccessToken(Session, Session->Password);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "urltoken")==0)
        {
            result=AuthURLToken(Session, Session->Password);
            AuthenticationsTried=MCatStr(AuthenticationsTried, Token, " ", NULL);
        }
        else if (strcasecmp(Token, "cookie")==0)
        {
            result=AccessTokenAuthCookie(Session);
            AuthenticationsTried=MCatStr(AuthenticationsTried, "accesstoken ", NULL);
        }

#ifdef HAVE_LIBPAM
        else if (strcasecmp(Token, "pam")==0)
        {
            result=AuthPAM(Session);
            if (result==TRUE) PAMAccount=TRUE;
        }
#endif
        else if (strcasecmp(Token, "none")==0)
        {
            result=FALSE;
            break;
        }
        else if (strcasecmp(Token, "deny")==0)
        {
            result=FALSE;
            break;
        }

        if (result==TRUE)
        {
            LogToFile(Settings.LogPath, "AUTH: Client Authenticated with %s for %s@%s", Token, Session->UserName,Session->ClientIP);
            break;
        }

        AuthenticationsTried=MCatStr(AuthenticationsTried,Token, " ",NULL);

        ptr=GetToken(ptr, ",", &Token, 0);
    }


    switch (result)
    {
    case TRUE:
        AuthenticateLookupUserDetails(Session);

        if (Session->RealUserUID==0)
        {
            LogToFile(Settings.LogPath, "AUTH: No 'RealUser' for '%s'. Login Denied",Session->UserName);
            result=FALSE;
        }
        if (! StrValid(Session->HomeDir))
        {
            LogToFile(Settings.LogPath, "AUTH: No 'HomeDir' set for '%s'. Login Denied",Session->UserName);
            result=FALSE;
        }

//Use PAMCheckAccount to check if account is allowed to login even if authenticated
        if (result && PAMAccount)
        {
#ifdef HAVE_LIBPAM
            if (! AuthPAMCheckAccount(Session))
            {
                LogToFile(Settings.LogPath, "PAM Account invalid for '%s'. Login Denied",Session->UserName);
                result=FALSE;
            }
#endif
        }
        break;


    case USER_UNKNOWN:
        LogToFile(Settings.LogPath, "AUTH: Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->UserName,AuthenticationsTried);
        break;

    case FALSE:
        LogToFile(Settings.LogPath, "AUTH: Authentication failed for UserName '%s'. Bad Password/Credentials. Tried methods: %s ",Session->UserName,AuthenticationsTried);
        break;
    }


    Destroy(AuthenticationsTried);
    Destroy(Token);
    return(result);
}



const char *GetDefaultUser()
{
    const char *Possibilities[]= {"wwwrun", "nobody", "daemon", "guest",NULL};
    HTTPSession *Session;
    int i;

    Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));

    for (i=0; Possibilities[i] !=NULL; i++)
    {
        Session->UserName=CopyStr(Session->UserName,Possibilities[i]);
        Session->Password=CopyStr(Session->Password, "");
        if (AuthPasswdFile(Session, NULL, NULL) != USER_UNKNOWN) break;
    }
    HTTPSessionDestroy(Session);

    return(Possibilities[i]);
}



int CheckUserExists(const char *UserName)
{
    HTTPSession *Session;
    int result=FALSE;

    if (! UserName) return(FALSE);

    Session=(HTTPSession *) calloc(1,sizeof(HTTPSession));
    Session->UserName=CopyStr(Session->UserName,UserName);
    Session->Password=CopyStr(Session->Password, "");

    if (AuthPasswdFile(Session, NULL, NULL) != USER_UNKNOWN) result=TRUE;
    if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
    if (AuthNativeCheck(Session, FALSE, NULL, NULL, NULL) != USER_UNKNOWN) result=TRUE;

    HTTPSessionDestroy(Session);

    return(result);
}


