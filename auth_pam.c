/*

this file contains functions relating to authentication via Pluggable Authentication Modules

*/

#include "auth_pam.h"

#ifdef HAVE_LIBPAM

#include <security/pam_appl.h>
static pam_handle_t *pamh=NULL;


/* PAM works in a bit of a strange way, insisting on having a callback */
/* function that it uses to prompt for the password. We have arranged  */
/* to have the password passed in as the 'appdata' arguement, so this  */
/* function just passes it back!                                       */

static int PAMConvFunc(int NoOfMessages, const struct pam_message **messages, 
         struct pam_response **responses, void *appdata)
{
int count;
const struct pam_message *mess;
struct pam_response *resp;

*responses=(struct pam_response *) calloc(NoOfMessages,sizeof(struct pam_response));

mess=*messages;
resp=*responses;

for (count=0; count < NoOfMessages; count++)
{
if ((mess->msg_style==PAM_PROMPT_ECHO_OFF) ||
    (mess->msg_style==PAM_PROMPT_ECHO_ON))
    {
      resp->resp=CopyStr(NULL,(char *) appdata); 
      resp->resp_retcode=0;
    }
mess++;
resp++;
}

return(PAM_SUCCESS);
}


static int PAMStart(HTTPSession *Session, const char *User)
{
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
const char *PAMConfigs[]={"alaya","httpd","other",NULL};
int result=PAM_PERM_DENIED, i;

  PAMConvStruct.appdata_ptr=(void *)Session->Password;

  for (i=0; (PAMConfigs[i] != NULL) && (result != PAM_SUCCESS); i++)
  {
    result=pam_start(PAMConfigs[i],User,&PAMConvStruct,&pamh);
  }

  if (result==PAM_SUCCESS)
  {
  pam_set_item(pamh,PAM_RUSER,Session->UserName);
  if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
  else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
  else pam_set_item(pamh,PAM_RHOST,"");
  return(TRUE);
  }

  return(FALSE);
}


int AuthPAM(HTTPSession *Session)
{
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
int result;

result=PAMStart(Session, Session->UserName);
if (result != PAM_SUCCESS)
{
	pam_end(pamh,result);
  return(USER_UNKNOWN);
}

result=pam_authenticate(pamh,0);

if (result==PAM_SUCCESS)
{
	if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.LogPath,"AUTH: UserName '%s' Authenticated via PAM.",Session->UserName);
 return(TRUE);
}
else return(FALSE);
}




int AuthPAMCheckAccount(HTTPSession *Session)
{
if (! pamh)
{
  if (! PAMStart(Session, Session->RealUser)) return(FALSE);
}

if (pam_acct_mgmt(pamh, 0)==PAM_SUCCESS)
{
  pam_open_session(pamh, 0);
  return(TRUE);
}
return(FALSE);
}



void AuthPAMClose()
{
  if (pamh)
  {
  pam_close_session(pamh, 0);
  pam_end(pamh,PAM_SUCCESS);
  }
}
#endif


