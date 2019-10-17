/*

this file contains functions relating to authentication via Pluggable Authentication Modules

*/

#ifndef ALAYA_AUTH_PAM
#define ALAYA_AUTH_PAM

#include "Authenticate.h"

int AuthPAM(HTTPSession *Session);
int AuthPAMCheckAccount(HTTPSession *Session);
void AuthPAMClose();

#endif


