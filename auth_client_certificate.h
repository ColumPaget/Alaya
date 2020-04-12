#ifndef ALAYA_CLIENT_CERTS_H
#define ALAYA_CLIENT_CERTS_H

#include "common.h"

//Will only return false if FLAG_SSL_CERT_REQUIRED is set
int AuthClientCertificate(HTTPSession *Session, STREAM *S);

#endif

