AC_INIT([libUseful], [5.57], [colums.projects@gmail.com])


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

m4_ifdef([AC_PROG_AR], [AC_PROG_AR])
AS_IF([test "$AR" = ""], [
    AR=ar
])
AC_SUBST(AR)

m4_ifdef([AC_PROG_LN], [AC_PROG_LN])
AS_IF([test "$LN" = ""], [
    LN=ln
])
AC_SUBST(LN)

echo "CC=$CC AR=$AR LN=$LN"

AC_PROG_CC
AC_LANG([C])
AC_PROG_MAKE_SET
AC_PROG_EGREP
AC_SYS_LARGEFILE
AC_C_VOLATILE
AC_C_INLINE

cf_have_libssl=no
cf_have_libcrypto=no
cf_have_libz=no

cf_use_simd=no
cf_use_sendfile=no
cf_use_xattr=no

cf_use_hashopenssl=auto


AC_SUBST([LICENSE], "GPLv3")
AC_ARG_ENABLE([lgpl],
    [AS_HELP_STRING([--enable-lgpl], [build code licensed under Lesser Gnu Public License (excludes some features like sha1 hashing)])],
    [cf_use_lgpl=$enableval],
    [cf_use_lgpl=no]
)
AS_IF([test "$cf_use_lgpl" = "yes"], [
    AC_SUBST([LICENSE], "LGPL")
    AC_DEFINE([USE_LGPL])
])



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


AC_ARG_ENABLE([fortify],
    [AS_HELP_STRING([--enable-fortify], [use 'FORTIFY_SOURCE=3' to harden source code])],
    [cf_use_fortify=$enableval],
    [cf_use_fortify=no]
)
AC_ARG_ENABLE([stack-protect],
    [AS_HELP_STRING([--enable-stack-protect], [use '-fstack-protector-strong' to harden source code])],
    [cf_use_stackprotect=$enableval],
    [cf_use_stackprotect=no]
)
AC_ARG_ENABLE([harden],
    [AS_HELP_STRING([--enable-harden], [use 'FORTIFY_SOURCE=3' and stack-protect to harden source code])],
    [cf_use_harden=$enableval],
    [cf_use_harden=no]
)
AC_ARG_ENABLE([soname],
    [AS_HELP_STRING([--enable-soname], [use 'soname' in shared lib. Defaults to 'yes' for gcc 'no' otherwise])],
    [cf_use_soname=$enableval],
    [cf_use_soname=gcc]
)

AC_SUBST(SONAME_FLAGS,"")
AS_IF([test "$cf_use_soname" != "no"], [
    AS_IF([test "$GCC" = "yes"], [
        AC_SUBST([SONAME_FLAGS], ['-Wl,${LINKER_SONAME_OPTION},${SONAME}'])
    ], [
	AS_IF([test "$cf_use_soname" = "yes"], [
		AC_SUBST([SONAME_FLAGS], ['-Wl,${LINKER_SONAME_OPTION},${SONAME}'])
        ])
    ])
])



AS_IF([test "$cf_use_harden" = "yes"], 
[
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


AS_IF([test "$cf_use_fortify" = "yes"], [
    CFLAGS="$CFLAGS -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
])

AS_IF([test "$cf_use_stackprotect" = "yes"], [
		CHECK_COMPILER_OPT("-fstack-protector-strong")
		AS_IF([test "$COMP_OPT_SUPPORT" != "yes"], [cf_use_stackprotect="no"])
])


AC_CHECK_FUNCS(ptsname_r clearenv setresuid initgroups poll mlock mlockall munlockall madvise htonll ntohll mkostemp mount umount umount2 getentropy prctl)

AC_CHECK_LIB(c,get_current_dir_name, AC_DEFINE([HAVE_GET_CURR_DIR]),)
AC_CHECK_FUNCS(getloadavg sysinfo sysconf getpagesize ptsname_r clearenv setresuid initgroups poll mlock mlockall munlockall madvise htonll ntohll mkostemp mount umount umount2 getentropy prctl)


AC_ARG_ENABLE([strlen-cache],
    [AS_HELP_STRING([--enable-strlen-cache], [use 'strlen cache' feature. This can improve performance with large strings (documents) on old systems without AVX strlen instructions.])],
    [cf_use_strlen_cache=$enableval],
    [cf_use_strlen_cache=yes]
)

AS_IF([test "$cf_use_strlen_cache" != "no"], AC_DEFINE([USE_STRLEN_CACHE]))


AC_ARG_ENABLE([sendfile],
    [AS_HELP_STRING([--enable-sendfile], [enable 'fastcopy' sendfile support])],
    [cf_use_sendfile=$enableval],
    [cf_use_sendfile=auto]
)

AS_IF([test "$cf_use_sendfile" != "no"], [
    AC_CHECK_HEADER(sys/sendfile.h,cf_use_sendfile=yes,cf_use_sendfile=no,)
    AS_IF([test "$cf_use_sendfile" != "no"], [
	AC_CHECK_FUNC(sendfile, AC_DEFINE([HAVE_SENDFILE]))
    ])
])





AC_CHECK_HEADER(sys/random.h,cf_use_sys_random=yes,cf_use_sys_random=no,)
AS_IF([test "$cf_use_sys_random" != "no"], [
    AC_DEFINE([HAVE_SYS_RANDOM])
])



AC_ARG_ENABLE([ip6],
    [AS_HELP_STRING([--enable-ip6], [enable IPv6 support])],
    [cf_use_ip6=$enableval],
    [cf_use_ip6=yes]
)
AS_IF([test "$cf_use_ip6" = "yes"], [
    AC_DEFINE([USE_INET6],1)
])


AC_ARG_ENABLE([xattr],
    [AS_HELP_STRING([--enable-xattr], [enable filesystem xattr support])],
    [cf_use_xattr=$enableval],
    [cf_use_xattr=yes]
)
AS_IF([test "$cf_use_xattr" = "yes"], [
    AC_CHECK_LIB(c,getxattr,,)
    cf_have_getxattr=$ac_cv_lib_c_getxattr
    AS_IF([test "$cf_have_getxattr" = "yes"], [
	AC_DEFINE([HAVE_XATTR])
    ])
])

AC_ARG_ENABLE([fsflags],
    [AS_HELP_STRING([--enable-fsflags], [enable support for immutable and append-only files (and use of these in logs)])],
    [cf_use_fsflags=$enableval],
    [cf_use_fsflags=no]
)
AS_IF([test "$cf_use_fsflags" = "yes"], [
    AC_CHECK_HEADER(linux/fs.h,cf_have_fsflags=yes,,)
])

AS_IF([test "$cf_have_fsflags" = "yes"], [
    AC_DEFINE([USE_FSFLAGS])
])


AC_ARG_ENABLE([crc32],
    [AS_HELP_STRING([--enable-crc32], [enable internal crc32 hash support (not supported under LGPL)])],
    [cf_use_crc32=$enableval],
    [cf_use_crc32=yes]
)

dnl LGPL disables crc32, as that code is GPLv3
AS_IF([test "$cf_use_lgpl" = "yes"],[
	  cf_use_crc32=no
])


AS_IF([test "$cf_use_crc32" = "yes"], [
    AC_DEFINE([USE_CRC32])
])




AC_ARG_ENABLE([md5],
    [AS_HELP_STRING([--enable-md5], [enable internal MD5 hash support])],
    [cf_use_md5=$enableval],
    [cf_use_md5=yes]
)
AS_IF([test "$cf_use_md5" = "yes"], [
    AC_DEFINE([USE_MD5])
])


AC_ARG_ENABLE([sha1],
    [AS_HELP_STRING([--enable-sha1], [enable internal SHA1 hash support (not supported under LGPL)])],
    [cf_use_sha1=$enableval],
    [cf_use_sha1=yes]
)


dnl LGPL disables sha1, as that code is GPLv3
AS_IF([test "$cf_use_lgpl" = "yes"],[
	  cf_use_sha1=no
])


AS_IF([test "$cf_use_sha1" = "yes"], [
    AC_DEFINE([USE_SHA1])
])


AC_ARG_ENABLE([sha2],
    [AS_HELP_STRING([--enable-sha2], [enable internal SHA2 (sha256, sha512 etc) hash support])],
    [cf_use_sha2=$enableval],
    [cf_use_sha2=yes]
)
AS_IF([test "$cf_use_sha2" = "yes"], [
    AC_DEFINE([USE_SHA2])
])

AC_ARG_ENABLE([whirl],
    [AS_HELP_STRING([--enable-whirl], [enable internal whirlpool hash support])],
    [cf_use_whirl=$enableval],
    [cf_use_whirl=yes]
)
AS_IF([test "$cf_use_whirl" = "yes"], [
    AC_DEFINE([USE_WHIRL])
])


AC_ARG_ENABLE([jh],
    [AS_HELP_STRING([--enable-jh], [enable internal jh hash support])],
    [cf_use_jh=$enableval],
    [cf_use_jh=yes]
)


AS_IF([test "$cf_use_jh" = "yes"], [
    AC_DEFINE([USE_JH])
])




AC_ARG_ENABLE([namespaces],
    [AS_HELP_STRING([--enable-namespaces], [enable linux namespace support])],
    [cf_use_namespaces=$enableval],
    [cf_use_namespaces=yes]
)
AS_IF([test "$cf_use_namespaces" = "yes"], [
    AC_CHECK_LIB(c,unshare,,)
    cf_have_unshare=$ac_cv_lib_c_unshare
    AS_IF([test "$cf_have_unshare" = "yes"], [
        AC_DEFINE([HAVE_UNSHARE])
    ])
    AC_CHECK_LIB(c,setns,,)
    cf_have_setns=$ac_cv_lib_c_setns
    AS_IF([test "$cf_have_setns" = "yes"], [
	AC_DEFINE([HAVE_SETNS])
    ])
])


AC_ARG_ENABLE([ssl],
    [AS_HELP_STRING([--enable-ssl], [use Secure Sockets Layer])],
    [cf_use_ssl=$enableval],
    [cf_use_ssl=yes]
)
AS_IF([test "$cf_use_ssl" = "yes"], [
    AC_CHECK_HEADER([openssl/crypto.h])
    AC_CHECK_HEADER([openssl/ssl.h])

    AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
    cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init

    dnl New versions of openssl seem to lack EVP_CIPHER_CTX_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
    AS_IF([test "$cf_have_libcrypto" != "yes"], [
	AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_new,,)
	cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_new
    ])


    AC_CHECK_LIB(ssl,SSL_library_init,,)
    cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

    dnl New versions of openssl seem to lack SSL_library_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
    AS_IF([test "$cf_have_libssl" != "yes"], [
	AC_CHECK_LIB(ssl,OPENSSL_init_ssl,,)
	cf_have_libssl=$ac_cv_lib_ssl_OPENSSL_init_ssl
    ])


    AS_IF([test "$cf_have_libssl" = "yes"], [
	cf_use_zlib=yes

	AC_CHECK_FUNCS(OpenSSL_add_all_algorithms EVP_MD_CTX_create EVP_MD_CTX_new EVP_MD_CTX_destroy EVP_MD_CTX_free X509_check_host SSL_set_tlsext_host_name SSL_set_min_proto_version EVP_CIPHER_fetch )


	AC_CHECK_DECLS(OpenSSL_add_all_algorithms,AC_DEFINE([HAVE_OPENSSL_ADD_ALL_ALGORITHMS]),[],[[#include <openssl/ssl.h>]])
	AC_CHECK_DECLS(SSL_set_tlsext_host_name,AC_DEFINE([HAVE_SSL_SET_TLSEXT_HOST_NAME]),[],[[#include <openssl/ssl.h>]])

	AC_MSG_CHECKING([that OpenSSL Library is at least version 0.9.7])
	AC_EGREP_CPP([yes], [
		#include <openssl/evp.h>
		#if SSLEAY_VERSION_NUMBER >= 0x00907000L
		yes
		#endif
	], [
		AC_MSG_RESULT([yes])
	# AC_DEFINE(USE_OPENSSL_ADD_ALL_ALGORITHMS, 1, [Use OpenSSL_add_all_algorithms])
	], [
	    AC_MSG_RESULT([no])
	])
    ])
])



AC_ARG_ENABLE([zlib],
    [AS_HELP_STRING([--enable-zlib] ,[use ZLib Compression])],
    [cf_use_zlib=$enableval],
    [cf_use_zlib=yes]
)
AS_IF([test "$cf_use_zlib" = "yes" -o "$cf_use_ssl" = "yes"], [
    AC_CHECK_LIB(z,deflate,,)
    cf_have_libz=$ac_cv_lib_z_deflate
])


AC_ARG_ENABLE([simd],
    [AS_HELP_STRING([--enable-simd=<level>], [use SIMD cpu extensions, 'level' can be one of mmx, sse, sse2])],
    [cf_use_simd=$enableval]
)
AS_CASE([$cf_use_simd],
    [mmx], [AC_SUBST(SIMD_CFLAGS,"-mmmx")],
    [sse], [AC_SUBST(SIMD_CFLAGS,"-mmmx -msse")],
    [sse2], [AC_SUBST(SIMD_CFLAGS,"-mmmx -msse -msse2")],
)


cf_have_capabilities=no
AC_ARG_ENABLE([capabilities],
    [AS_HELP_STRING([--enable-capabilities], [enable linux capabilities support (default=no)])],
    [cf_use_capabilities=$enableval],
    [cf_use_capabilities=no]
)

AS_IF([test "$cf_use_capabilities" = "yes"], [
    AC_CHECK_HEADER(sys/capability.h,cf_have_capabilities=yes,,)
    AC_CHECK_HEADER(linux/capability.h,cf_have_capabilities=yes,,)
])

AS_IF([test "$cf_have_capabilities" = "yes"], [
    AC_CHECK_LIB(cap,cap_init,,)
    AC_DEFINE([USE_CAPABILITIES])
])



AC_ARG_ENABLE([seccomp],
    [AS_HELP_STRING([--enable-seccomp], [enable seccomp to limit process syscalls])],
    [cf_use_seccomp=$enableval],
    [cf_use_seccomp=no]
)

AS_IF([test "$cf_use_seccomp" = "yes"], [
    AC_CHECK_HEADER([linux/seccomp.h],,cf_use_seccomp=no,)
    AC_CHECK_HEADER([linux/filter.h],,cf_use_seccomp=no,)
    AC_CHECK_HEADER([linux/bpf.h],,cf_use_seccomp=no,)
    AC_CHECK_LIB(c,prctl,,cf_use_seccomp=no)
    AS_IF([test "$cf_use_seccomp" = "yes"], [
	AC_DEFINE([USE_SECCOMP])
    ])
])




dnl read Makefile.in and write Makefile 
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo
echo "############# libUseful Build Config: #############"

echo "compile with -Wall - $cf_use_wall"
echo "compile with -Werror - $cf_use_werror"
echo "compile with FORTIFY_SOURCE=3 - $cf_use_fortify"
echo "compile with -fstack-protector-strong - $cf_use_stackprotect"
echo "CFLAGS=$CFLAGS"

AS_IF([test "$ac_cv_sys_file_offset_bits" = "64"], [
    echo "Largefiles ( > 2GB ) enabled"
], [
    echo "Largefiles ( > 2GB ) NOT enabled"
])

AS_IF([test "$cf_have_getxattr" = "yes"], [
    echo "Filesystem attribues (xattr) enabled"
], [
    echo "Filesystem attribues (xattr) NOT enabled"
])


AS_IF([test "$ac_cv_func_sendfile" = "yes"], [
    echo "Linux sendfile syscall enabled"
], [
    echo "Linux sendfile syscall NOT enabled"
])


AS_IF([test "$cf_use_ip6" = "yes"], [
    echo "IPv6 enabled"
], [
    echo "IPv6 NOT enabled"
])

AS_IF([test "$cf_have_libssl" = "yes"], [
    echo "SSL/TLS enabled"
], [
    echo "SSL/TLS NOT enabled"
])

AS_IF([test "$cf_have_libz" = "yes"], [
    echo "zlib support enabled"
], [
    echo "zlib NOT enabled"
])

AS_IF([test "$cf_use_crc32" = "yes"], [
    echo "crc32 hash support enabled"
], [
    echo "crc32 hash NOT enabled"
])


AS_IF([test "$cf_use_md5" = "yes"], [
    echo "md5 hash support enabled"
], [
    echo "md5 hash NOT enabled"
])

AS_IF([test "$cf_use_sha1" = "yes"], [
    echo "sha1 hash support enabled"
], [
    echo "sha1 hash NOT enabled"
])

AS_IF([test "$cf_use_sha2" = "yes"], [
    echo "sha2 hash support enabled"
], [
    echo "sha2 hash NOT enabled"
])

AS_IF([test "$cf_use_whirl" = "yes"], [
    echo "whirl hash support enabled"
], [
    echo "whirl hash NOT enabled"
])

AS_IF([test "$cf_use_jh" = "yes"], [
    echo "jh hash support enabled"
], [
    echo "jh hash NOT enabled"
])



AS_IF([test "$cf_have_fsflags" = "yes"], [
    echo "support for FS_APPEND_FL and FS_IMMUTABLE_FL flags and hardened logs enabled"
], [
    echo "support for FS_APPEND_FL and FS_IMMUTABLE_FL flags and hardened logs NOT enabled"
])

AS_IF([test "$cf_have_unshare" = "yes" -o "$cf_have_setns" = "yes"], [
    echo "linux namespace support enabled"
], [
    echo "linux namespace support NOT enabled"
])

AS_IF([test "$cf_have_capabilities" = "yes"], [
    echo "linux capabilities support enabled"
], [
    echo "linux capabilities support NOT enabled"
])

AS_IF([test "$cf_use_seccomp" = "yes"], [
    echo "linux seccomp support enabled"
], [
    echo "linux seccomp support NOT enabled"
])

