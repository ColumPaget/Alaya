

AC_INIT([main.c])

VERSION="1.1.2" 
AC_SUBST(VERSION) 

AC_CONFIG_SUBDIRS([libUseful-2.0])

AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 
AC_SYS_LARGEFILE

AC_CHECK_LIB(z,deflate,,)
cf_have_libz=$ac_cv_lib_z_deflate

cf_have_capabilities=no
cf_have_xattr=no
cf_use_sendfile=yes
cf_use_largefiles=yes

AC_ARG_ENABLE(sendfile, [  --enable-sendfile       enable sendfile support (default=yes)], cf_use_sendfile=$enableval )
AC_ARG_ENABLE(xattr, [  --enable-xattr       enable extended file attributes support (default=no)], cf_use_xattr=$enableval )
AC_ARG_ENABLE(capabilities, [  --enable-capabilities       enable linux capabilities support (default=no)], cf_use_capabilities=$enableval )

AC_ARG_ENABLE(ssl, [  --enable-ssl		use Secure Sockets Layer (default=no)], cf_use_ssl=$enableval )
AC_ARG_ENABLE(ip6, [  --enable-ip6		use IPv6 (default=no)], cf_use_ip6=$enableval )
AC_ARG_ENABLE(pam, [  --enable-pam		enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )



if test "$cf_use_xattr" != "no"
then
AC_CHECK_HEADER(sys/xattr.h,AC_DEFINE([USE_XATTR]),,)
fi


if test "$cf_use_capabilities" != "no"
then
AC_CHECK_HEADER(sys/capability.h,cf_have_capabilities=yes,,)
AC_CHECK_HEADER(linux/capability.h,cf_have_capabilities=yes,,)
fi


if test "$cf_have_capabilities" = "yes"
then
AC_CHECK_LIB(cap,cap_init,,)
AC_DEFINE([USE_LINUX_CAPABILITIES])
fi


if test "$cf_use_pam" != "no"
then
AC_CHECK_LIB(pam, pam_start,,)
cf_have_libpam=$ac_cv_lib_pam_pam_start
fi



if test "$cf_use_ssl" = "yes" 
then
AC_CHECK_LIB(ssl,SSL_library_init,,)
cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init
fi


AC_CHECK_LIB(crypt, crypt,,)
cf_have_libcrypt=$ac_cv_lib_crypt_crypt

AC_CHECK_HEADER(shadow.h,AC_DEFINE(HAVE_SHADOW_H, 1))

dnl read Makefile.in and write Makefile 
AC_OUTPUT(Makefile)

echo
echo "********** Alaya Compile Settings *********"
if test	"$cf_have_libssl" != "yes" 
then
echo "SSL/https NOT enabled"
else
echo "SSL and https enabled"
fi

if test	"$cf_have_libpam" != "yes" 
then
echo "PAM authentication NOT enabled"
else
echo "PAM authentication enabled"
fi

if test	"$cf_have_libcrypt" != "yes" 
then
echo "LIBCRYPT authentication NOT enabled"
else
echo "LIBCRYPT authentication enabled"
fi

if test	"$ac_cv_header_shadow_h" != "yes" 
then
echo "/etc/shadow authentication NOT enabled"
else
echo "/etc/shadow authentication enabled"
fi

if test "$ac_cv_sys_file_offset_bits" != "64"
then
echo "Largefiles ( > 2GB ) NOT enabled"
else
echo "Largefiles ( > 2GB ) enabled"
fi

if test "$cf_have_capabilities" != "yes"
then
echo "Linux capabilties NOT enabled"
else
echo "Linux capabilties enabled"
fi

if test "$cf_use_ip6" != "yes"
then
echo "IPv6 NOT enabled"
else
echo "IPv6 enabled"
fi

if test "$cf_use_sendfile" != "yes"
then
echo "sendfile NOT enabled"
else
echo "sendfile enabled"
fi


