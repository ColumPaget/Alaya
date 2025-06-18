AC_INIT
AC_CONFIG_SRCDIR([main.c])

AC_PROG_CC 
AC_LANG([C]) 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
 
AC_SYS_LARGEFILE

AC_CHECK_LIB(z,deflate,,)
cf_have_libz=$ac_cv_lib_z_deflate


dnl set these here, they can be changed by multiple 'enable' options below
cf_use_mdwe="no"
cf_use_nosu="no"
cf_use_fortify="no"
cf_use_stackprotect="no"



dnl define a function we can use to check if a compiler flag
dnl is supported by the compiler
AC_DEFUN([CHECK_COMPILER_OPT],
[
    COMP_OPT="$@"
    AC_MSG_CHECKING(["checking if compiler supports $COMP_OPT"])
    OLD_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $COMP_OPT"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(test(){return 1;})], [COMP_OPT_SUPPORT="yes"], [COMP_OPT_SUPPORT="no"])
    AC_MSG_RESULT([$COMP_OPT_SUPPORT])
    AS_IF([test "$COMP_OPT_SUPPORT" != "yes"], [CFLAGS="$OLD_CFLAGS"])
])  


dnl prctl gets used in conjunction with unshare
dnl and also for PR_SET_NO_NEW_PRIVS, so we check
dnl for it independantly of unshare now
AC_CHECK_LIB(c,prctl,,)
if test "$ac_cv_lib_c_prctl" = "yes"
then
AC_DEFINE([USE_PRCTL])

AC_CHECK_HEADERS([linux/prctl.h]) 
AC_CHECK_DECL([PR_SET_NO_NEW_PRIVS], cf_use_nosu=yes,,[
#ifdef HAVE_LINUX_PRCTL_H
# include <sys/prctl.h>
# endif])

AC_CHECK_DECL([PR_SET_MDWE], cf_use_mdwe=yes,,[
#ifdef HAVE_LINUX_PRCTL_H
# include <sys/prctl.h>
# endif])
fi




AC_ARG_ENABLE([wall],
    [AS_HELP_STRING([--enable-wall], [use -Wall to get maximum compile warnings])],
    [cf_use_wall=$enableval],
    [cf_use_wall=no]
)
AS_IF([test "$cf_use_wall" = "yes"], [
    CFLAGS="$CFLAGS -Wall"
])


AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror], [treat compile warnings as errors])],
    [cf_use_werror=$enableval],
    [cf_use_werror=no]
)
AS_IF([test "$cf_use_werror" = "yes"], [
    CFLAGS="$CFLAGS -Werror"
])

AC_ARG_ENABLE([harden],
    [AS_HELP_STRING([--enable-harden], [use 'FORTIFY_SOURCE=3' and stack-protect to harden source code])],
    [cf_use_harden=$enableval],
    [cf_use_harden=no]
)


AC_ARG_ENABLE(harden, [  --enable-harden       enable both 'mdwe' and 'nosu' and other memory-harending features (default=no)], cf_use_harden=$enableval )


AS_IF([test "$cf_use_harden" = "yes"], 
[
    cf_use_mdwe="yes"
    cf_use_nosu="yes"
    cf_use_fortify="yes"
    cf_use_stackprotect="yes"

    CHECK_COMPILER_OPT("-ftrivial-auto-var-init=zero")
    CHECK_COMPILER_OPT("-fstack-clash-protection")
    CHECK_COMPILER_OPT("-fno-strict-overflow")
    CHECK_COMPILER_OPT("-fno-strict-aliasing")
    CHECK_COMPILER_OPT("-fno-delete-null-pointer-checks")
    CHECK_COMPILER_OPT("-fcf-protection=full")
    CHECK_COMPILER_OPT("-mmitigate-rop")
])


AC_ARG_ENABLE([fortify],
    [AS_HELP_STRING([--enable-fortify], [use 'FORTIFY_SOURCE=3' to harden source code])],
    [cf_use_fortify=$enableval]
)


if test "$cf_use_fortify" = "yes"
then
    CFLAGS="$CFLAGS -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
fi


AC_ARG_ENABLE([stack-protect],
    [AS_HELP_STRING([--enable-stack-protect], [use '-fstack-protector-strong' to harden source code])],
    [cf_use_stackprotect=$enableval]
)


if test "$cf_use_stackprotect" = "yes"
then
		CHECK_COMPILER_OPT("-fstack-protector-strong")
		if test "$COMP_OPT_SUPPORT" != "yes"
		then
			cf_use_stackprotect="no"
		fi
fi



AC_ARG_ENABLE(mdwe, [  --enable-mdwe           enable MDWE memory hardening (default=no)], cf_use_mdwe=$enableval )
if test "$cf_use_mdwe" = "yes"
then
AC_DEFINE([USE_MDWE])
fi


AC_ARG_ENABLE(nosu, [  --enable-nosu           enable prctl-based 'NO_NEW_PRIVS' to prevent su/sudo/suid (default=no)], cf_use_nosu=$enableval )
if test "$cf_use_nosu" = "yes"
then
AC_DEFINE([USE_NOSU])
fi


AC_ARG_ENABLE(sendfile, [  --enable-sendfile       enable sendfile support (default=yes)], cf_use_sendfile=$enableval, cf_use_sendfile=yes)
if test "$cf_use_sendfile" = "yes"
then
AC_DEFINE([USE_SENDFILE])
fi



AC_ARG_ENABLE(ip6, [  --enable-ip6            use IPv6 (default=no)], cf_use_ip6=$enableval )
if test "$cf_use_ip6" = "yes"
then
AC_DEFINE([USE_IP6])
fi



cf_use_xattr=no
AC_ARG_ENABLE(xattr, [  --enable-xattr          enable extended file attributes support (default=no)], cf_use_xattr=$enableval )
if test "$cf_use_xattr" != "no"
then
AC_CHECK_HEADER(sys/xattr.h,AC_DEFINE([USE_XATTR]),,)
AC_DEFINE([USE_XATTR])
fi

cf_use_socks=no
AC_ARG_ENABLE(socks, [  --enable-socks          enable socks proxy support (default=no)], cf_use_socks=$enableval )
if test "$cf_use_socks" != "no"
then
AC_DEFINE([USE_SOCKS])
fi


cf_use_short=no
AC_ARG_ENABLE(short, [  --enable-short          enable builtin url-shortener for local urls(default=no)], cf_use_short=$enableval )
if test "$cf_use_short" != "no"
then
AC_DEFINE([USE_URL_SHORTENER])
fi


AC_ARG_ENABLE(unshare, [  --enable-unshare        enable unshare containers support (default=no)], cf_use_unshare=$enableval )
if test "$cf_use_unshare" = "yes" 
then
AC_CHECK_LIB(c,unshare,,)
cf_have_unshare=$ac_cv_lib_c_unshare
fi

if test "$cf_have_unshare" = "yes"
then
AC_DEFINE([USE_UNSHARE])
fi


cf_have_capabilities=no
AC_ARG_ENABLE(capabilities, [  --enable-capabilities   enable linux capabilities support (default=no)], cf_use_capabilities=$enableval )
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


AC_ARG_ENABLE(pam, [  --enable-pam            enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )
if test "$cf_use_pam" != "no"
then
AC_CHECK_LIB(pam, pam_start,,)
cf_have_libpam=$ac_cv_lib_pam_pam_start
fi



AC_ARG_ENABLE(ssl, [  --enable-ssl            use Secure Sockets Layer (default=no)], cf_use_ssl=$enableval )
if test "$cf_use_ssl" = "yes" 
then
  AC_CHECK_LIB(crypt, crypt,,)
  cf_have_libcrypt=$ac_cv_lib_crypt_crypt

  AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
  cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init

  dnl New versions of openssl seem to lack EVP_CIPHER_CTX_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
  if test "$cf_have_libcrypto" != "yes"
  then
        AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_new,,)
        cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_new
  fi


  AC_CHECK_LIB(ssl,SSL_library_init,,)
  cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

  dnl New versions of openssl seem to lack SSL_library_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
  if test "$cf_have_libssl" != "yes"
  then
        AC_CHECK_LIB(ssl,OPENSSL_init_ssl,,)
        cf_have_libssl=$ac_cv_lib_ssl_OPENSSL_init_ssl
  fi
fi


AC_CHECK_HEADER(shadow.h,AC_DEFINE(HAVE_SHADOW_H, 1))


AC_ARG_WITH(system-libuseful, [  --with-system-libuseful       use systemwide libUseful.so rather than bundled version], cf_with_libuseful=$withval )

if test "$cf_with_libuseful" != "no" -a "$cf_with_libuseful" != ""
then
AC_CHECK_LIB([Useful],[OpenSSLVerifyCallback],
  [AC_CHECK_LIB([ssl],[SSL_new],,,[-lcrypto -lz])]
  [AC_CHECK_LIB([crypto],[ERR_load_CRYPTO_strings],,,[-lz])]
  [AC_CHECK_LIB([z],[inflate])]
  ,,[-lssl -lcrypto -lz])
AC_CHECK_LIB(Useful,GetToken)

LUSEFUL="system"
else
LUSEFUL="bundled"
AC_DEFINE(USE_LIBUSEFUL_BUNDLED)
STATIC_LIBS="libUseful-bundled/libUseful.a"
AC_SUBST(STATIC_LIBS)
AC_CONFIG_SUBDIRS([libUseful-bundled])
fi



dnl read Makefile.in and write Makefile 
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo "********** Alaya Compile Settings *********"

echo "Using $LUSEFUL libUseful"

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

if test "$cf_use_unshare" != "yes"
then
echo "unshare containers NOT enabled"
else
echo "unshare containers enabled"
fi

if test "$cf_use_socks" != "yes"
then
echo "socks proxy NOT enabled"
else
echo "socks proxy enabled"
fi

if test "$cf_use_short" != "yes"
then
echo "url shortener NOT enabled"
else
echo "url shortner enabled"
fi

if test "$cf_use_mdwe" != "yes"
then
echo "PR_SET_MDWE memory hardening NOT enabled"
else
echo "PR_SET_MDWE memory hardening enabled"
fi

if test "$cf_use_nosu" != "yes"
then
echo "deny su/sudo/suid via PR_NO_NEW_PRIVS is NOT enabled"
else
echo "deny su/sudo/suid via PR_NO_NEW_PRIVS enabled"
fi


