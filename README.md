[![Build Status](https://travis-ci.com/ColumPaget/Alaya.svg?branch=master)](https://travis-ci.com/ColumPaget/Alaya)


SYNOPSIS
========

Alaya is a chrooting webserver with basic webdav extensions. It can serve both http and https and is intended to provide a simple means for people to share directories with webdav. Although it chroots it supports running CGI programs outside of the chroot via a trusted-path method. Alaya aims at ease of use, so all options can be configured via command-line args, though a config file is also supported.

As of version 3.0 Alaya is able to serve HTTP and HTTPS connections on the same port, and if support is compiled in and configured, also SOCKS4a proxy connections on the same port as HTTP and HTTPS.


AUTHOR
======

Alaya and libUseful are (C) 2011 Colum Paget. They are released under the GPL so you may do anything with them that the GPL allows.

Email: colums.projects@gmail.com


DISCLAIMER
==========

This is free software. It comes with no guarentees and I take no responsiblity if it makes your computer explode or opens a portal to the demon dimensions, or does (or doesn't do) anything.


CREDITS
=======

Thanks to Gregor Heuer and  Maurice R Volaski for bug reports. 



CLIENT ISSUES
=============

You may want to read the CLIENTPROGRAMS file for information on the current state of webdav client support with alaya. If you've used alaya with a particular client program, please send an email to colums.projects@gmail.com to let me know.



USAGE
=====

```
alaya [-v] [-d] [-O] [-h] [-p <port>] [-i <iface>] [-f <config file>] [-t <seconds>] [-A <auth methods>] [-a <auth file>] [-l <log file>] [-P <pid file>] [-r <path>] [-sslv <version>] [-key <path>] [-cert <path>] [-client-cert <level>] [-verify-path <path>] [-ciphers <cipher list>] [-pfs] [-cgi <path>] [-ep <path>] [-u <default user>] [-g <default group>] [-m <http methods>] [-realm <auth realm>] [-allowed <users>] -denied <users>] [-allow-ip <iplist>] [-nodir] [-dir <type>] [-compress <yes|no|partial>] [-ttl <ttl>] [-cache <seconds>] [-tz <timezone>] [-accesstokenkey <string>] [-urltokenkey <string>] [-clientnames] [-ttl <pkt ttl>] 

```


COMMAND-LINE OPTIONS
====================


`-v`
: Verbose logging.

`-v -v`
: Even more verbose logging.

`-a <path>`
: Specify the authentication file for 'built in' authentication.

`-A <method>,<method>...`
: Authentication methods. Comma separated list of 'pam', 'passwd', 'shadow', 'native', and 'accesstoken'. For to use alaya native authentication, with alaya's own password file just use 'native' on its own. See more in 'AUTHENTICATION' below.

`-d`
: No daemon, don't background process.

`-nodemon`
: No daemon, don't background process.

`-f <path>`
: Path to config file, defaults to /etc/alaya.conf, but alaya can be configured by command-line args only.

`-O`
: Open, don't require authentication.

`-r <path>`
: 'ChRoot mode', chroot into directory and offer services from it

`-chroot <path>`
: 'ChRoot mode', chroot into directory and offer services from it

`-h`
: 'ChHome mode', switch to users home dir and chroot.

`-chhome`
: 'ChHome mode', switch to users home dir and chroot.

`-i <interface>`
: Set interface listen on, allows running separate servers on the same port on different interfaces/network cards. For IPv4 either the interface name or address can be used (i.e. -i eth0 or -i 192.168.8.44) for IPv6 the IPv6 address must be used, (e.g. -i fe80::201:7ff6:ca5a:226b%wlan0). For unix sockets the 'address' (which is the file path) must start with '/'.

`-l <path>`
: Path to log file, default is to use 'syslog' instead.

`-m <method>,<method>...`
: HTTP Methods (GET, PUT, DELETE, PROPFIND) that are allowed. Comma Separated. Set to 'GET' for very basic webserver, 'GET,PROPFIND' for readonly DAV.  'BASE' will set GET,POST,HEAD. 'DAV' will set everything needed for WebDAV. 'RGET' will allow proxy-server gets. 'PROXY' will enable CONNECT and RGET. 'DAV,PROXY' enables everything.

`-p <port>`
: Set port to listen on.

`-P <path>`
: Path for pid file.

`-sslv <version>`
: Lowest SSL Version to use. One of ssl, tls, tls1.2, tls1.2

`-key <path>`
: Keyfile for SSL (HTTPS)

`-cert <path>`
: Certificate for SSL (HTTPS). This can be a certificate chain bundled in .pem format.

`-ciphers <name>,<name>...`
: List of SSL ciphers to use.

`-dhparams <path>`
: Path to a file containing Diffie Helmann parameters for Perfect Forward Secrecy.

`-pfs`
: Use Perfect Forward Secrecy. Will not generate Diffie Helmann parameters unless -dhgenerate is supplied too

`-client-cert [required|sufficient|required+sufficient]`
: Settings for SSL client certificate authentication. Three levels are available:    'required' means a client MUST supply a certificate, but that it may still be required to log in through normal authentication. 'sufficient' means that a client CAN supply a certificate, and that the certificate is all the authentication that's needed. 'required+sufficient' means that a client MUST provide a certificate, and that this certificate is sufficient for authentication.

`-verify-path <path>`
: Path to a file, or a directory, containing Authority certificates for verifying client certificates.

`-cgi <path>`
: Directory containing cgi programs. These programs will be accessible even though they are outside of a 'chroot'

`-hashfile <path>`
: File containing cryptographic hashes of cgi-scripts. This file contains the output of the md5sum, shasum, sha256sum or sha512sum utilities.

`-ep <path>`
: 'External path' containing files that will be accessible even outside a chroot.

`-u <user>`
: User to run cgi-programmes and default 'real user' for any 'native users' that don't have one specified.

`-g <group>`
: Group to run server in (this will be the default group for users)

`-allowed <user>,<user>...`
: Comma separated list of users allowed to login (default without this switch is 'all users can login'

`-denied <user>,<user>...`
: Comma separated list of users DENIED login

`-realm <string>`
: Realm for HTTP Authentication

`-cache <max age>`
: Takes an argument in seconds which is the max-age recommended for browser caching. Setting this to zero will turn off caching in the browser. Default is 10 secs.

`-compress [yes|no|partial]`
: Compress documents and responses. This can have three values, 'yes', 'no' or 'partial'. 'Partial' means alaya will compress directory listings and other internally genrated pages, but not file downloads.

`-t <seconds>`
: Timeout in seconds for 'idle' clients

`-ttl <value>`
: Max packet TTL for connections

`-allow-ip <pattern>,<pattern>...`
: Comma-seperated list of shell/fnmatch patterns of IP addresses allowed to connect

`-allow-ips <pattern>,<pattern>...`
: Comma-seperated list of shell/fnmatch patterns of IP addresses allowed to connect

`-nodir`
: Do not allow directory listings.

`-dir` 
: Directory listing type. One of: 'none', 'basic', 'fancy', 'interactive', or 'full'.

`-dirtype` 
: Directory listing type. One of: 'none', 'basic', 'fancy', 'interactive', or 'full'.

`-U`
: fancy, interactive dir listings with media, tarballs and other features..
 
`-accesstokenkey <secret>`
: Secret key to use with access-tokens.

`-urltokenkey <secret>`
: Secret key to use with url-tokens.

`-su`
: On linux systems disable the 'no su' feature, so that suid cgi programs can switch user. NOT RECOMENDED.




USER SETUP FOR ALAYA NATIVE AUTHENTICATION
==========================================

Alaya can use PAM, /etc/shadow or /etc/passwd to authenticate, but has its own password file that offers extra features, or is useful to create users who can only use Alaya. Users in the Alaya password file are mapped to a 'real' user on the system (usually 'guest' or 'nobody'). The Alaya password file can be setup through the alaya commandline.

Add User
--------

```
  alaya -user add [-a <auth path>] [-e <password encryption type>]  [-h <user home directory>] <Username> <Password> <Setting> <Setting> <Setting>

  -a:    Specify the authentication file for 'built in' authentication.
  -h:    Specify home directory of new user.
  -u:    Specify 'real user' that this user maps to.
  -e:    Specify password encryption type (sha1, sha512, sha256, md5, null, or plain).
```

Config file type settings (like 'ChHome' or 'ChRoot=/var/shared' or 'HttpMethods=GET,PUT,PROPFIND' or 'Path=cgi,/cgi-bin/,/usr/share/cgi' can be added so that these settings are specific to a user

Add user with home directory /home/Guest and a number of settings
------------------------------------------------------------------

```
  alaya -user add Guest Password -a /etc/FileServices.auth -e sha1 -h /home/Guest 'Path=cgi,/cgi-bin/,/usr/share/cgi' 'Path=files,/docs/,/usr/share/docs' ChHome 'SSLClientCertificate=required'

  alaya -user add test testing123 -h /home/test -e sha1 SSLClientCertificate=required
```

Delete User
-----------

```
  alaya -user del [-a <auth path>] <Username>
```

List Users
----------

```
  alaya -user list
```


Note that using 'SSLClientCertificate' in user entries in the authentication file requries 'SSLClientCertificate=ask' to be set in the main config file. This is so that alaya will ask for a certificate in the connection setup stage, BEFORE it gets to authentication. Without this entry it will be too late to ask for a certificate when we reach the authentication stage.



CONFIG FILE
============

Alaya is also configurable via a config-file (defaults to /etc/alaya.conf) 

There should be an example config file in the source distribution. It's worth looking at.

Config file entries are:


`include=<path>`
: Include another config file in this config.

`Chroot=<dir>`
: Specifies directory to serve requests out of

`ChHome`
: Serve requests out of users home directory

`AllowUsers=<list>`
: Only allow these users access.

`DenyUsers=<list>`
: Deny these users access.

`Port=<port>`
: Port to listen on

`LogFile=<path>`
: Log file path

`PidFile=<path>`
: Pid file path

`AuthPath=<path>`
: Path to native authentication file(s)

`AuthRealm=<realm>`
: Realm for HTTP authentication

`BindAddress=<addr>`
: Interface to serve requests on

`HttpMethods=<list>`
: List of methods like GET, PUT that are allowed

`AuthMethods=<list>`
: Which methods (native, shadow, passwd, pam, accesstoken) should be used for user authentication, and in what order. See more in 'AUTHENTICATION' below.

`SSLKey=<path>`
: Path to SSL key file

`SSLCert=<path>`
: Path to SSL certificate file

`SSLVersion=<ssl version>`
: Lowest SSL Version to use. Can be 'ssl', 'tls', 'tls1.1' or 'tls1.2'. 

`SSLCiphers=<cipher list>`
: List of Ciphers to use with SSL (in standard openssl format)

`SSLVerifyPath=<path>`
: Path to file or directory containing Certificate Authority certificates for peer authentication.

`SSLClientCertificate=<type>`
: 'required', 'sufficient' or 'required+sufficient' (See 'Client Certificates' below)

`SSLDHParams=<path>`
: Path to an openssl generated Diffie Helman parameters file. Auto-activates Perfect Forward Secrecy.

`PFS=<yes|no>`
: Use Perfect Forward Secrecy (not needed if SSLDHParams is supplied. Without SSLDHParams will use ElipticCurve algorithms).

`PerfectForwardSecrecy=<yes|no>`
: Use Perfect Forward Secrecy (not needed if SSLDHParams is supplied. Without SSLDHParams will use ElipticCurve algorithms).

`Path=<type>,<alias>,<path>`
: Path to a trusted directory outside of a chroot jail, which is made accessible as a 'virtual' directory under the top-level of the chroot. Currently there are two types of path 'cgi', for cgi programs, and 'files' for a standard directory made available in this way. (See 'VPaths' below)

`FileType=<pattern>,<settings>`
: Settings for files that match 'pattern'. See 'SETTINGS FOR FILE TYPES' below.

`LogVerbose`
: More information in log file

`MaxLogSize=<max bytes>`
: Max log file size. A suffix can be used to express size, e.g.  1G, 2M, 900k. When max size is reached the logfile is renamed to have a '-' suffix, and a new file opened.

`DefaultUser=<username>`
: Default user that is used both for running cgi scripts, and for 'native' users that have no specified 'real' user

`DefaultGroup=<groupname>`
: Default group for webserver

`DirListType=<type>`
: Type of directory listings served. Can be 'none', 'basic', 'fancy' or 'interactive', with other flags to see optional properties. See 'DIRECTORY LISTINGS' below.

`Compression=<yes|no|partial>`
:Use HTTP compression. 'Partial' will mean that only internally generated pages are compressed, not downloaded files.

`ScriptHashFile=<path>`
: Path to a file containing integrity hashes of cgi scripts. 

`ScriptHandler: <type>=<path>`
: Path to interpreter to handle scripts with the extension <type>

`CustomHeader=<full HTTP header>`
: Custom HTTP header to be added to all server responses.

`LookupClientName`
: If present then lookup client hostnames with DNS and use in logging. The default is just to log the ip-address, as this is faster.

`SanitizeAllowTags=<tag list>`
: List of HTML tags allowed to be used in 'POST' to cgi-scripts. If left blank, then all are allowed, if set, then all but the listed html elements will be stripped 

`UserAgentSettings=<UserAgentString>,<Settings>`
: Settings to be applied when a particular user agent string is seen.

`FileCacheTime=<seconds>`
: Amount of time to recommend the browser  caches documents for.

`ListenQueue=<num>`
: Number of connections to queue waiting for 'accept'. Default is 10.

`HttpKeepAlive=<yes|no>`
: Use http keep-alive

`ReusePort=<yes|no>`
: Bind server socket with SO_REUSEPORT allowing multiple server processes to bind to the same port (on by default).

`UseNamespaces=<yes|no>`
: Use linux namespaces to isolate the connection-handler processes (on by default).

`TcpFastOpen=<https|yes|no>`
: Use 'tcp fast open'. 'https' only enables this in for encrypted channels, which is the default due to some security concerns.

`MaxMemory=<max bytes>`
: Maximum amount of memory per alaya process. A suffix can be used to express the size as, for instance, 1G, 2M, 900k

`MaxStack=<max bytes>`
: Maximum Stack Size. A suffix can be used to express the size as, for instance, 1G, 2M, 900k

`ActivityTimeout=<value>`
: Amount of time, in seconds that a Client connection can be 'idle'

`TTL=<value>`
: Max TTL of TCP packets from alaya server

`PackFormats=<list>`
: List of 'pack formats' to offer in the 'download as packed' item on the directory page.

`WebsocketHandler: <path>:<protocol>=<script path>`
: Specify a program that handles websockets requests to a particular path and protocol.

`DenyProxy=<host>: <port>`
: Configuration for proxy systems, see 'PROXY' section below

`AllowProxy=<host>: <port> [redirect=<host>:<port>] [ssl]`
: Configuration for proxy systems, see 'PROXY' section below

`AllowIPs=<pattern>,<pattern>...` 
: Only allow hosts whose IP matches one of shell/fnmatch style '<pattern>' to connect

`Event=<type>:<match string>,<match str>,<match str>...:<action>`
: Trigger an action when an event occurs. See 'EVENTS' below.




HTTPS ENCRYPTION
================

HTTPS can be turned on (if compiled in) by using the -key and -cert command-line options to indictate where the SSL key and certificate files can be found.

Some certificates need supporting 'intermediate' or 'chain' certificates. These can be bundled together in one pem format file by simply 'cat'-ing the certificates, in .pem format, into one file and supplying that file to alaya with the -cert command-line option or the SSLCert config-file entry.

The optional '-ciphers' command-line-argument and the 'SSLCiphers' config file entry can be used to set a list of ciphers that should be used in openssl mode, though the default settings should be a suitable list of ciphers.

The optional '-sslv' command-line-argument and the 'SSLVersion' config file entry can be used to set the minimum SSL version to use. This can be one of:

```
ssl      sslv3 and above (so sslv3 + any tls)
tls      any tls
tls1.1  tls1.1 and above
tls1.2  tls1.2 and above
```


PERFECT FORWARD SECRECY
=======================

This is a complex topic. A better discussion than I can provide is to be found here: http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html

If the appropriate ciphers are set in SSLCiphers then alaya should support Perfect Forward Secrecy, a mode of SSL in which an ephemeral, short-lived key is created for encryption. Without this feature SSL creates keys from a long-lived server key, allowing recorded communications to be retrospectively read if this server key ever falls into the wrong hands.

Two types of PFS cipher are supported, those based on Eliptic Curves, and those based on Diffie-Helmann key exchange (actually both involve Diffie-Helmann, but whatever). An eliptic curve is a mathematical object that can be used for encryption, but for this system to work both the server and the client must agree to use the same curve. Unfortunately Firefox only supports a choice of three curves, and these three are ones recomended by the U.S. National Institute of Security and Technology, and some people (you know, the tin-hat types who say the government is spying on us) believe they may be 'backdoored' (i.e. contain weaknesses that would allow the government to decrypt communications using them).

An alternative scheme to Eliptic Curves is Diffie Helmann Key Exchange. Unfortunately this has a considerably performance-hit and  requires the pre-generation of a file of random numbers, the 'DHParams' file. This file can be generated with the openssl command-line tool, with the command:

```
openssl dhparam -out dhparams.pem 1024
```

The path to the dhparams.pem file should then be provided to alaya with the -dhparams command-line-argument, or with the SSLDHParams config file entry.



IPv6
====

Currently IPv6 is only supported for server-side, alaya will not proxy for IPv6 hosts. If specifying that an interface should be bound to in IPv6 mode the IPv6 address must be used (not the interface name), meaning that IPv4 will not be served (run without being bound to an address, alaya can service both IPv6 and IPv4 connections). If the IPv6 address being bound to is a link-local address then an interface identifier must be supplied (e.g. fe80::201:7ff6:ca5a:226b%eth0  Note the '%eth0').




AUTHENTICATION
==============

Alaya supports authentication as 'real users' via old style '/etc/passwd', newer '/etc/shadow' or via Pluggable Authentication Modules (PAM). However, alaya also supports it's own 'native' authentication using it's own password file (defaults to /etc/alaya.auth). The native authentication method allows some of the config settings to be set against an individual user. This can be used to limit the HTTP methods a given user can use, or to limit CGI access to certain users, etc, etc. Finally alaya has 'access token' and 'access cookie' authentication methods to handle special cases. Access tokens allow access to individual files through use of a URL that includes an access key. Access Cookies help in situations where clients don't always send authentication details.



NATIVE AUTHENTICATION
=====================

If alaya authenticates using 'native' authentication, then the users are 'virtual', they don't exist as 'real' users on the system, and so they really run as a default user and default group (defaults to 'nobody' or 'wwwrun' if such an account exists). This default user and default group can be set in the config file, or else a suitable default is found. The 'real user' and 'real group' can also be set on a user-by-user basis using a setup like:

```
  alaya -user add bill bills-password DefaultUser=nobody
```

If you want 'bill' to actually be the system-user 'bill', but have a different password for alaya, then you can configure him/her/it as:

```
  alaya -user add bill bills-alaya-password DefaultUser=bill
```

Alaya supports multiple hashing methods for passwords stored in the native file. The default is sha256. Available types are:

```
  md5, sha1, sha256, sha512, htdigest-md5, plain, null
```

You can set up a user with a specific type by:

```
  alaya -user add bill -e sha1 bills-password
```

The 'plain' encryption type is plain-text, which must be used if using HTTP Digest Authentication. The 'null' encryption type allows someone to log in with a blank password.

Many settings that can be put in the config-file can also be booked against a specific user. So:

```
  alaya -user add bill bills-password DefaultUser=nobody DefaultGroup=users ChRoot=/tmp HTTPMethods=GET
```

would map the virtual user 'bill' to the real user 'nobody', in group 'users', and on login they'll be chrooted to '/tmp'. They will only be allowed to use the HTTP GET method.

  
  
SYSTEM AUTHENTICATION
=====================

If alaya authenticates using the /etc/passwd, /etc/shadow or PAM methods, then the user will be logged in as the REAL system user that was found in /etc/passwd. If the 'ChHome' setting is active, then they will be chrooted into their home directory.



ACCESS-TOKEN AUTHENTICATION
===========================

Alaya supports a special authentication type 'accesstoken'. This is used in m3u playlists generated by the interactive directory listings when the 'Media' flag is active (see "DIRECTORY LISTINGS" below). A unique hash is created for each file in the playlist, against the ip-address that the user is coming from. As of version 1.4 the hash includes a random secret that is gathered when alaya starts up (thus, if you restart alaya, all access tokens given out by the previous alaya process will become invalid). This random value has been added to prevent an attacker 'guessing' the access token for a file. 

Access-Token authentication is provided because many media players do not fully support HTTP authentication. Thus the URL in the m3u file includes and 'access token' for that particular client and that particular file. This does mean that other users *at the same client IP* could use a replay attack to get the same file, if they can obtain the URL and access-token that was sent. This means you should particularly consider the use of access-tokens with unencrypted HTTP (although they are less insecure than 'Basic' authentication used over unencrypted HTTP, as each access-token only grants access to a single file).

An access token URL can also be generated for an arbitary file using the 'Access Token' button on the file 'Edit/Details' page.

'AccessToken' authentication can be turned off by simply not including it in the list of allowed authentication methods.


URL-TOKEN AUTHENTICATION
========================

Alaya supports a special authentication type 'urltoken'. This generates a unique, and long-lived authentication token for a given URL. Unlike access-tokens these do not use a random secret that is automatically generated when alaya starts up, but instead use a user-configured secret. A URL is combined with a salt and a secret string, hashed with sha256, and then this hash is used to permit access to just that URL. To use this feature you must supply the secret using `URLTokenKey` in alaya's config file, or on the commandline with '-urltokenkey'.


COOKIE AUTHENTICATION
=====================

Alaya supports authentication via 'session cookies'. Firstly the user must log on with some other method, and then alaya supplies then with an HTTP cookie that works similarly to an access-token (as described above). This is mostly used so that the Safari webbrowser can use the websockets feature of alaya, because Safari does not send authentication details when upgrading a connection from HTTP to websockets. However Safari does send cookies, so a session cookie allows it to authenticate the websockets connection.



DIGEST AUTHENTICATION
=====================

Alaya supports HTTP Digest Authentication. This requires the user to be set up with a password type of either htdigest-md5 or plain in the NATIVE authentication file. This means that the password will be stored in the native file either md5-hashed, or in plain text. htdigest-md5 is preferred to plain because the password is stored md5-hashed. Both plain and htdigest-md5 entries can be used to authenticate clients supplying either 'digest authentication' credentials, or 'basic authentication' (plaintext) credentials.

Digest authentication cannot work with pam/shadow/password authentication sources, nor with the native authentication if the password is not stored in either htdigest-md5 or plain, because digest authentication sends a hash of the password, and if the stored password is hashed with a different method, then there's no way of comparing them.

Furthermore, digest authentication changes how the server and client interact, and as a result if digest authentication is available, and the client choses to use it, then no other types of authentication will work. 

To set up a user to use Digest Authentication, use:

```
alaya -user add -e htdigest-md5 bill bills-alaya-password
```

or

```
alaya -user add -e plain bill bills-alaya-password
```


CLIENT CERTIFICATE AUTHENTICATION
=================================

Alaya can use client certificates for authentication. 

If 'SSLClientCertificate' is set to 'required' then a client must provide a certificate to connect to the service at all, but this can be any certificate that validates against the certificates in 'SSLVerifyPath', and the client will still have to go through 'normal' authentication. 

If 'SSLClientCertificate' is set to 'sufficient' then if a client provides a certificate that matches against a user entry in the native authentication file, it is logged in without needing any further authentication, otherwise it must go through the normal authentication methods.

If 'SSLClientCertificate' is set to 'required+sufficient' then a client MUST provide a certificate, and if this certificate matches against a user name in the native authentication file, the client is logged in without any further authentication.

The certificate for 'required' authentication can be a certificate that authenticates anything, a hostname, a username, a random string, whatever. The 'required' mode is simply intended as a form of two-factor authentication to be used in combination with normal username/password authentication.

For 'sufficient' mode the certificate must have a username in the 'common name' field (where the hostname would go in server certificates) and this username must be present in the native authentication file.

For 'required+sufficient' mode the rules are the same as for 'sufficient' mode.

Finally, there is a mode called 'ask'. In this mode a certificate will be asked for, but it does not have any effect on authentication UNLESS the 'SSLClientCertificate' option is set in the 'User settings' field of the native authentication file. This allows a certificate to be asked for, but only applied to those users who have the appropriate settings in their authentication file entry.

Unfortunately Client Certificate Authentication does not play well with Logout VPaths (see below) and the 'logout' feature will likely not work if you're using client certificates.



DIRECTORY LISTINGS
==================

Alaya supports a number of types of directory listing. These are set using the 'DirListType' config option. Available types are:

```
None          Refuse to show directories, only allow downloading of files
Basic          Just list directory/file names
Fancy          A much fancier listing of directory/file names, sizes, types, modified times, and other information
Interactive    This type provides buttons that allow users to delete, rename or upload files.
Full          Turn on everything except IndexPages
```

In addition to the type of listing, the DirListType config option accepts a number of comma-seperated modifiers. These are:

```
IndexPages     Search for an index.html file in a directory, and show that instead of the directory
Media          If a directory contains media files, then offer the option to download a .m3u playlist of them.
               This can then be  passed to a media playing app like mplayer, or some such.
ShowVPaths     Show VPaths as though they were subdirectories in the users top-level directory
TarDownloads   Offer downloads of entire directories as tarballs
MimeIcons      Use icons for filetypes, instead of text description of mimetype. See 'MIMEICON VPATHS' below
```

Examples:

```
  DirListType=none,IndexPages   Don't allow access to directory listings, but show index.html pages where available.

  DirListType=Fancy,Media      Show 'fancy' directory listings, and offer .m3u playlists in directories with media files.
```


PACK FORMATS
============

If 'interactive' is set as the directory listing type, or 'TarDownloads' is selected as an option, then directory listings page offers the option of 'pack and send' for the directory. This allows sending either the entire directory contents, or selected items, in some archive format. The 'PackFormats' settings allows specifying available formats and the commands to run to generate them. e.g.

```
PackFormats=tar:internal,zip:zip -,tbz:tar -jcO,txz:tar -JcO
```

'tar:internal' is an internal tar function that doesn't require an external program. All other variants have the form:

```
 <archive type>:<archive command>
```

A list of files to be archived is appended to the command. The command must send its archive data to standard out.



CHROOTING
=========

Simply running alaya in a directory without a config file or command-line args will cause it to chroot into that directory, and serve that directories contents over HTTP.

The -r flag can be used to specify the 'root' directory instead, e.g.

```
alaya -r /usr/share/httpd
```

This will cause alaya to chroot into /usr/share/httpd and serve out of there.

The -h flag turns on the 'chhome' mode, this awaits user authentication, then chroots into the user's home directory.

It will be noted that for 'chhome' to work some data is first read from the client in order to authenticate them. Conceivevably there might be a window for mischief prior to chrooting. The main aim of chroot is to rule out any possiblity of the user obtaining documents that they shouldn't (e.g. by using '/docs/../../etc/passwd' style methods) or accidentally dropping documents somewhere they shouldn't.



VPATHS
======

VPaths are URLs that map to some special behavior. VPaths can be used to indicate a directory contains CGI scripts that can be run, to mark items outside of a chroot jail to be made available within the jail, to indicate that some directories are accessible without authentication, to proxy a URL to another location, and other uses.

VPaths are configured with the format:

```
Path=<type>,<URL>,<Path>,<arguments>
```

where 'URL' is not normally a full url, but a part of a URL under the server root. For example:

```
Path=cgi,/cgi-bin/,/usr/share/cgi-progs
```

will map any url like:

```
  http://myhost/cgi-bin/myProg.cgi
```

To a file called '/usr/share/cgi-progs/myProg.cgi' and run it if it exists.


VPATHS: 'Local' VPaths and permissions on directories
-----------------------------------------------------

'local' VPaths currently have only one use: they allow a directory to be made accessible without authentication. This differs from chroot paths (see below) because those make a directory available to a user after authentication. 'local' vpaths are used to make a directory available to anyone, even if most of the rest of the server requires authentication. This is particularly useful for automated certificate generation via "let's encrypt". "Let's encrypt" needs access to a directory called '/.well-known/acme-challenge' under the webroot. This is used to pass information to the "let's encrypt" service, but there's no means of providing authentication details to that service. Thus we can declare a VPath like:

```
Path=local,/.well-known/,auth=open
```

With the 'auth=open' argument to make this path available without authentication.


VPATHS: Items outside of chroot
-------------------------------

Sometimes there is a requirement to chroot users into, say, their home directories, but make certain shared directories that are outside fo the chroot available to them. This can be achieved using the 'VPath' system. A VPath (Virtual Path) is a directory that a user can access through an 'alias' URL, even if it's outside of any chroot they're jailed in.

A VPath is set up in either the main config file, or else within a user's entry in the native authentication file. For example, this line in the config file:

```
Path=files,/Docs/,/usr/local/share/documents
```

Would create a vpath accessible by all users. They would see a directory called 'Docs' in their root directory, and accessing it would grant them access to /usr/local/share/documents. They'll be able to access /usr/local/share/documents even if they are chrooted and it is outside of their chroot jail.

If an entry is placed in a user's authentication file entry, like this:

```
Guest:md5:5a041e5ac20634d4daa01b073d0d65b7:nobody:/home/Guest/:Path=files,/Music/,/home/Music
```

Then only that user will see the 'Music' VPath.

If the 'ShowVPaths' argument is given to the DirListType config file argument, then users will see 'file' VPaths (but not cgi VPaths) as subdirectories of their top-level directory.

VPaths can contain multiple directories, as in

```
Path=files,/Docs/,/usr/local/share/documents-1:/usr/local/share/documents-2
```

So that an item like

http://localhost/Docs/my-document.txt

is searched for in both '/usr/local/share/documents-1' and '/usr/local/share/documents-2'

If the members of a VPath do not begin with a '/', then they are searched for within the chroot, rather than outside of it. So, if we have a root directory like this:

htdocs
user1-home
user2-home
user3-home

and our html files, including the root 'index.html' for the site are in 'htdocs' we can specify a 'root' VPath like this:

```
Path=files,/,htdocs/
```

Thus, when the user asks for any file in '/' '/htdocs' will be searched. If 'IndexFiles' is enabled in the config file, then 'htdocs/' will be searched for an index.html file.

A file vpath can take a number of extra arguments. Like this:

```
Path=files,/Docs/,/usr/local/share/documents,cache=3600,user=jane,group=documents,uploads=true,compress=false
```

These arguments effect server behavior in this Path:

```
user=<username>    Specifies the user that the Path is accessed as.
group=<groupname>  Specifies the group that the Path is accessed as.
cache=<seconds>    The number of seconds that items under this path can be cached for.
upload=<Y/n>       Are items allowed to be uploaded to this path?
uploads=<Y/n>      Are items allowed to be uploaded to this path?
compress=<Y/n>     Should the server use compression (TransferEncoding: gzip) when sending documents from this path?
```


VPATHS: Proxy URLs
------------------

From Alaya 1.0.10 proxy VPaths are supported. These allow a URL to be redirected to some other resource. For example:

```
Path=proxy,/Portal,http://otherhost:port/Dir/
```

This maps a path to another URL. All requests sent to alaya that are for paths below /Portal will be proxy-forwarded to the Path '/Dir' on host 'otherhost' at port 'port'. The current authentication

'Proxy' VPaths can take some arguments. Supported arguments are

```
user=<username>    Specifies the user that the Path is accessed as.
pass=<password>    Specifies the password that the Path is accessed with.
group=<groupname>  Specifies the group that the Path is accessed as.
```

e.g.

```
Path=proxy,/MyHost,http://myhost:port/Dir/,user=me,pass=secret
```

VPATHS: Logging out of HTTP sessions
------------------------------------

Alaya uses a special type of VPath, the 'Logout' vpath, to allow users to 'logout' and reenter HTTP authentication. Basically this redirects the client to a URL that will insist that the client re-authenticates, even if the client presents valid authentication credentials.

Configure this with:

```
Path=Logout,/Logout
```

This will mean that whenever the user requests to the imaginary document '/Logout' they will be asked to enter new login credentials.


VPATHS: CGI program directories
-------------------------------

At current CGI programs cannot be run within the served directory tree (which is chrooted). The main reason for this is that it would allow users to upload their own .cgi style programs and run them on the server. CGI programs can be run from a trusted VPath outside of the chroot, specified either with the -cgi command line argument, or by creating a VPath in the config file.

For example, this entry in the config file

```
Path=cgi,/cgi/,/usr/share/cgi
```

Would create a cgi-path under the alias '/cgi/' that allowed programs in /usr/share/cgi to be run. Thus urls of the form

```
http://servername/cgi/myscript.cgi
```

Will be map to /usr/share/cgi, where the appropriate program should be found and run.

The -cgi command line option creates a VPath with the alias of /cgi-bin/. thus

```
alaya -cgi /usr/share/cgi
```

Would cause urls of the form

```
  http://servername/cgi-bin/myscript.cgi
```

to map to `/usr/share/cgi`

Paths can contain multiple directories separated by colons, these directories will be searched till a matching file is found. Thus

```
  Path=cgi,/cgi-bin/,/usr/share/cgi:/usr/local/cgi
```

would cause both /usr/share/cgi and /usr/local/cgi to be searched when trying to map /cgi-bin/ in a url.


Alaya will refuse to service any URL for trusted paths that contains a '..'

ALAYA WILL NOT RUN CGI PROGRAMS AS ROOT. If you do not specify a 'DefaultUser' or 'CgiUser' then it will try using users like 'nobody' and 'wwwrun'. If it doesn't find any suitable user to run as then it will refuse to run the cgi.

You can take cryptographic hashes of your cgi scripts with md5sum, shasum, sha256sum or sha512sum. Redirect the output to a file, and specify that file with the 'ScriptHashFile' config argument like so:

```
ScriptHashFile=/etc/scripts.hash
```

Alaya will then use these hashes to check the integrity of any cgi program before it is run, and will refuse to run those whose hashes do not match the ones in the file.


If you have scripts that lack a #! header, or if you want to force the use of a specific interpreter for you scripts, there is the 'ScriptHandler' config item:

```
ScriptHandler:pl=/usr/bin/perl 
ScriptHandler:py=/usr/bin/python
```

These two examples allow you to specify the program used to run a perl or python script. The file-extension of the script is used to match the appropriate entry. The following entry:

```
ScriptHandler:*=/usr/local/bin/ScriptManager.exe
```

Would use the program '/usr/local/bin/ScriptManager.exe' as the interpreter for all scripts.

'CGI' VPaths can also take some of the arguments supported by 'Path' VPaths (see above). Supported arguments are

```
user=<username>    Specifies the user that the Path is accessed as.
group=<groupname>  Specifies the group that the Path is accessed as.
compress=<Y/n>     Should the server use compression (TransferEncoding: gzip) when sending documents from this path?
```



VPATHS: Mimeicons
-----------------

Alaya supports mime icons in file listings via a special VPATH. e.g.:

```
Path=MimeIcons,/mimeicons,/home/app-themes/icons/Free-file-icons-master/32px/$(FileExtn).png,/home/app-themes/icons/mediatype-icons/gnome-mime-$(mimeclass)-$(mimesub).png,/home/app-themes/icons/nuvola/32x32/mimetypes/unknown.png
```

This creates a URL which alaya internally uses to find icons for filetypes. A comma-separated list of file paths is searched until a match is found. Placeholders in the format '$(variable name)' are substituted to generate a file path. Available variables are:

```
$(FileExtn)    gets replaced with the file extension of the file we are seeking a mime icon for. 
$(MimeType)    gets replaced with the full mime type (e.g. 'image/jpeg'). 
$(MimeClass)  gets replaced with the mime class of the file we are seeking a mime icon for (so, 'audio', 'video', 'image' or 'application'). 
$(MimeSub)    gets replaced with the mime subtype of the file we are seeking a mime icon for (so, 'jpeg', 'x-shockwave-flash', 'pdf', 'text', 'html' etc, etc). 
$(FileType)    currently only used for directories/folders, where it is set to 'folder'
```

In order to handle unknown file types the last entry should have no variable placeholders, so that it always matches, and is a path to the 'default' icon.

Directories/folders have the MimeType variable set to 'inode/directory', and the FileType variable set to 'folder'

In order for mime icons to work you must also see the 'MimeIcons' property in the 'DirListType' config item.

'Mimeicon' VPaths can also take some of the arguments supported by 'Path' VPaths (see above). The 'cache' argument is useful for specifying the number of Supported arguments are

```
user=<username>    Specifies the user that the Path is accessed as.
group=<groupname>  Specifies the group that the Path is accessed as.
```


WEBSOCKETS
==========

Alaya supports websockets. These are persistent connections that are more like a standard bidirectional TCP link. Websockets are booked against a URL and a 'protocol'. The URL doesn't need to exist as any kind of document, and the protocol is just a string selected to represent a particular websocket service. Websockets are configured in the config file as:

```
 WebsocketHandler:<path>:<protocol>=<script path>
```

So, if you had a perl script 'chat.pl' that implements a chat protocol that exists under the /user URL you might write:

```
 WebsocketHandler:/user:chat=/usr/local/bin/chat.pl
```

The <path> option can be an fnmatch wildcard pattern, so you can make your chat program available under any URL via:

```
 WebsocketHandler:*:chat=/usr/local/bin/chat.pl
```

The scripts that provide the services over websockets simply write to stdout and read from stdin. Thus they behave similarly to 'inetd' programs, or indeed to command-line programs.

For websocket programs Alaya provides the standard CGI environment variables like REMOTE_USER, REMOTE_ADDRESS, etc. Don't assume that the stdin of your program is connected directly to the incoming network connection from the client program, it probably won't be, thus you can't discover the IP address of the peer with socket functions, you have to get the REMOTE_ADDRESS environment variable.



SETTINGS FOR FILE TYPES
=======================

Some settings can be changed on a per file basis using the 'FileType' command:

```
FileType=*.jpg,cache=3600
```

Currently supported settings are:

```
cache=<seconds>       The number of seconds that items under this path can be cached for.
compress=<Y/n>        Should the server use compression (TransferEncoding: gzip) when sending documents from this path?
mimetype=<mimetype>   Mimetype (HTTP Content-Type) for matching files.
```


TTL LIMITS
==========

The `TTL` config-file option and `-ttl` command-line options can be used to set a maximum TTL on TCP packets sent by alaya. This will limit hosts that can access alaya to being within a certain number of 'router hops' of the server. A value of '1' or '2' will normally limit connections to the local network. However, connections from beyond this will connect, but they will hang as alaya will be unable to send data back to them. Thus a timeout should be set with the `ActivityTimeout` config option or the `-t` command-line option.



ALLOWED IPS
===========

The `AllowIPs` config-file option and `-allow-ips` command-line option can be used to set a list of IP addresses allowed to connect. Their argument is a comma-separated list of shell-style patterns. e.g.:

```
AllowIPs=192.168.*.*,10.*,127.0.0.1
-allow-ips '192.168.*.*,10.*,127.0.0.1'
```



PROXY SUPPORT
=============

Alaya has very rudimentary proxy support. The CONNECT method is supported, as are GET requests that specify a full URL rather than a file path. If compiled with `--enable-socks` then alaya will support SOCKS4a connections on the same port as HTTP/HTTPS (SOCKS5 is planned for a future release). 

HTTP and SOCKS4a proxy functions are not enabled by default, you'll have to enable them by using the '-m' command line arg or 'HttpMethods' config file entry. 'RGET' and 'RPOST' are the http methods for HTTP proxing. 'CONNECT' is the method for https proxying. 'SOCKS' is the method name for SOCKS4a proxing. For example:

```
  alaya -m CONNECT,RGET
```

This only allows Alaya to work as a proxy, not as a webdav server. 'RGET' stands for 'REMOTE GET', it's the GET method with a full URL. Remote POST is not yet supported, but probably will be in a future release.

You could also use

```
  alaya -m PROXY
```

as 'PROXY' expands to CONNECT,RGET,SOCKS

If you want to allow remote GETS but not CONNECT then 

```
  alaya -m RGET
```

If you want to allow proxy server support and webdav, then

```
  alaya -m DAV,PROXY
```

'DAV' expands to all the supported HTTP methods except the proxy ones, so these two together is everything active.

All this also works with the 'HttpMethods' config-file entry, so

```
HttpMethods=DAV,PROXY
```

Allowed connections can be defined in the config file using the 'DenyProxy' and 'AllowProxy' settings. These settings take fnmatch/shell style wildcard patterns that define the hosts and ports they apply two. For example:

```
DenyProxy=*
AllowProxy=freshcode.club:*
AllowProxy=*duckduckgo.com:80
AllowProxy=github.com:443 redirect=github.com:80 ssl
```

This config denys all connections except for: connection to 'freshcode.club' (not www.freshcode.club, just freshcode.club) on any port, connections to duckduckgo.com (including www.duckduckgo.com, note leading '*') on port 80, and connections to 'github.com' on port 443, although these connections are redirected to another port.

The final line, for 'github.com' on port 443, illustrates both the 'redirect' and 'ssl' features. By adding `redirect=<host>:<port>` any requested host and port can be redirected to another host and port. The 'ssl' feature activates TLS/SSL BETWEEN ALAYA AND THE CLIENT. This can be used to add TLS encryption to a connection that isn't encrypted by the destination host. This is particularlly useful if alaya is being used as a reverse proxy allowing access to services behind a firewall.

This config applies to all proxy methods that are enabled.

If you want to have alaya serve up a proxy autoconfig PAC file, you'll likely need to specify the mime type for such files with:

```
FileType=*.pac,mimetype=application/x-ns-proxy-autoconfig
```


COMPRESSION
===========

Alaya supports gzip compression of both internally generated pages (like directory listings) and downloaded documents. This can be turned on and off with the command-line argument -compress or with the config file value 'Compression='. However, some clients (notably links) get confused when downloading a gzipped file and save it on disk as a gzipped file, but without any .gz suffix to indicate this. This can be very confusing for the user. Hence alaya supports 'partial' comprssion ('-compress partial' and 'Compression=partial') which only compresses internally generated pages like directory listings, which are normally displayed by the browser, not downloaded. Partial mode should speed up transfer of large directory listings, while downloaded documents will be transferred uncompressed.

Compression obviously has a 'cost' on the server-side, so if serving many users on a not-too-powerful machine it might be wise to set compression to either 'no' or 'partial'.



CACHING
=======

By default from version 1.3.2 alaya supports browser caching, and will tell browsers to cache files for 10 seconds. This is particularly useful for mime-type icons, as the same icon may appear many times in a directory listing.

The amount of time that an item can be cached for can be changed using the '-cache' command-line argument or the "FileCacheTime" config file entry.

Cache time can be set on a file-extension basis with the file-type command, like so:

```
FileType=\*.jpg,cache=3600
```

Similarly cache time can be set for file VPaths like so:

```
Path=files,/Docs/,/usr/local/share/documents,cache=3600
```


URL_SHORTENER
=============

Since version 5.0 alaya containes a url shortener for urls it serves. This feature mostly exists to support client apps that generate qrcodes that can be scanned to take one to a url. 


N.B. SHORTENED URLS ARE ASSUMED TO BE PUBLIC AND REQUESTS FOR THEM 'AUTHENTICATED'. Anyone with the short URL can access the file that URL points to without needing to log into the server.


The feature must be enabled at compile-time with `--enable-short` to build it into alaya. To activate it at runtime the 'URLShortener' config-file option must be set. 

```
URLShortner=<url path>,<database directory>
```

This config option specifies:

'url path'
:  a relative url, e.g. '/s', that when people go to that url generates a shortened url. 

'database directory'
:  a directory in which to store the short-to-full url mappings


e.g.

```
URLShortner=/s,/home/httpd/url-short/
```

would, for an example host called 'myhost' specify the 'magic' path of `http://myhost/s`. When going to this path one can supply HTTP parameters like so:

`http://myhost/s?u=<url>`
: store url in the shortener database

`http://myhost/s?s=<short>`
: query a url in the shortener database

usage 1 (with the 'u' argument) will store the url in the shortener database return a document containing solely the shortened url
usage 2 (with the 's' argument) will return a document containing solely the full url

once a url is stored in the shortener database anyone asking for the short url will be served up content from the full url.

The url in usage 1 MUST be http encoded, and SHOULD only be the 'path' part of the url. So to generate a short url for the url http://myhost.com/documents/quarterly report.pdf we would send:

```
https://myhost.com.com/s?u=/documents/quarterly%20report.pdf
```

and we would be returned a short url which from then on would redirect us to the original document if the short url is requested from the server.



HARDENING ON LINUX
==================

On the Linux platform alaya uses the prctl syscall to set the values 'PR_NO_NEW_PRIVS' and 'PR_SET_MDWE'. 

'PR_NO_NEW_PRIVS' tells the kernel to disallow a process from switching to superuser using methods like suid. This means that cgi-programs using suid permissions to carry out tasks as root will not work. It it enabled at compile time with `--enable-nosu`.

'PR_SET_MDWE' is used to tell the kernel that any memory that is not currently mapped as executable, cannot become executable in future, and that new memory mappings cannot be both writable and executable. This hardens the process against buffer-overflow vulnerabilities and other types of exploit. However it also prevents starting up new programs via exec. This option is thus used in alaya code-paths that do not require launching an external program (which is just about everything except the code that launches cgi programs). However, PR_SET_MDWE has the side effect that debugging programs like valgrind will no longer work, reporting random errors in the alaya process. It it enabled at compile time with `--enable-mdwe`.

Both 'PR_NO_NEW_PRIVS' and 'PR_SET_MDWE' and some other hardening options can be enabled at compile time with `--enable-harden`.


EVENTS
======

Alaya supports an event structure that allows taking certain actions or running scripts in response to the HTTP method, the file Path asked for, client IPs, client headers, usernames, 'bad' urls, or particular response codes.

The script will be run OUT OF CHROOT and as the DefaultUser and DefaultGroup (either the configured ones, or else alaya will try to find a user like 'nobody' or 'wwwrun').

Some example config-file entries for events:

The 'Event' entry in the config file has the format

```
Event=<type>:<matches>:<action> <args>
```

where <type> is one of:

```
  Method      Match the HTTP method
  Path        Match the path of the file asked for
  User        Match the username supplied in authentication
  Peer        Match client IP Addresses
  Header      Match a particular header supplied by the client
  Response    Match a response code
  BadURL      Match any URL that breaks alaya's inbuilt 'valid url' rules
  Auth        Match authentication state, '<matches>' will be either 'okay' or 'fail'
  Upload      Match a URL has just been uploaded
```

and <matches> is a comma-separated list of things that the rule matches. Shell/fnmatch wildcards are allowed in these lists.

<actions> is a comma-separated list of action types. These can be:

```
  ignore:    ignore this event (used to rule out some things that will match a later event)
  syslog:    send a message to syslog about this event
  deny:      refuse access to the requested url
```

any other entry is treated as a script to run. 

Log, syslog and any script actions be passed any arguments that are supplied after the 'action' section of the script. These arguments can contain variables in the form '$(name)'. Supported variable are:

```
$(URL)          URL of the request
$(Path)         The path of the URL. For 'Upload' events this will be the path on disk (from chroot directory if chroot used).
$(Method)       HTTP Method of the request (GET, POST, HEAD, etc, etc)
$(UserName)     UserName of remote user
$(ClientIP)     IP Address of remote host
$(UserAgent)    User-agent string for remote browser
$(Match)        This is a 'comment' string that describes the event.
```

Please note that these variables are not handled by the shell, alaya subsitutes them before running a script, so in order to coerce a variable that may contain spaces to be a single argument, you can just put single or double quotes around it.

example:

```
  Event=Header:*() {*:deny,/usr/local/sbin/BlockHTTPHacker.sh ShellShock '$(UserName)@$(ClientIP)' '$(URL)'
```

This would trigger if any header contains `() {`, which is a string used in shellshock attacks. The request will be denied, and the script `/usr/local/sbin/BlockHTTPHacker.sh` will be run. The script will be passed a static argument 'ShellShock' and two dynamically generated arguments, one specifying the UserName and ClientIP that the request came from, and the other specifying the URL that the request was sent to.

Upload events trigger at the end of a file upload. For these events the main variable you'll want to use is '$(Path)'. This variable gives the path to the uploaded file, relative to the chroot directory if ChRoot or ChHome is in use for the session.

examples:

```
Event=Path:*/myScript.php:ignore
Event=Path:*/setup.php,*/xmlrpc.php,/vtigercrm/,/cgi-bin/php*,/sql*,/manager/html,/mysql*,/HNAP1/:/usr/local/sbin/BlockHTTPHacker.sh InvalidScript '$(UserName)@$(ClientIP)' '$(URL)'
Event=Method:PUT:/usr/local/sbin/AlayaFilePut.sh '$(URL)'
Event=User:fred:syslog,/usr/local/sbin/Flintstone.sh
Event=Peer:192.168.*.*:syslog
Event=BadURL::deny,syslog
Event=Header:*() {*:deny,/usr/local/sbin/BlockHTTPHacker.sh ShellShock '$(UserName)@$(ClientIP)'
Event=Path:/favicon.ico:ignore
Event=ResponseCode:404:/usr/local/sbin/HTTPError.sh "nonexistent path"
Event=Upload:*:/usr/local/sbin/ProcessUpload.sh '$(Path)'
```


