dnl $Id$
dnl config.m4 for extension sm

dnl Otherwise use enable:

PHP_ARG_ENABLE(sm, whether to enable sm support,
dnl Make sure that the comment is aligned:
[  --enable-sm           Enable sm support])

if test "$PHP_SM" != "no"; then

  if test -z "$PKG_CONFIG"; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  fi

  AC_MSG_CHECKING([OpenSSL 1.1.1])
  if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists openssl; then
    if $PKG_CONFIG --atleast-version=1.1.1 openssl; then
      found_openssl=yes
      OPENSSL_LIBS=`$PKG_CONFIG --libs openssl`
      OPENSSL_INCS=`$PKG_CONFIG --cflags-only-I openssl`
      OPENSSL_INCDIR=`$PKG_CONFIG --variable=includedir openssl`
    else
      AC_MSG_ERROR([OpenSSL version 1.1.1 or greater required.])
    fi

    if test -n "$OPENSSL_LIBS"; then
      PHP_EVAL_LIBLINE($OPENSSL_LIBS, $1)
    fi
    if test -n "$OPENSSL_INCS"; then
      PHP_EVAL_INCLINE($OPENSSL_INCS)
    fi
  fi

  if test "$found_openssl" = "yes"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_ERROR([OpenSSL 1.1.1 cannot be located])
  fi

  PHP_NEW_EXTENSION(sm, sm.c, $ext_shared)
  AC_DEFINE(HAVE_SMLIB,1,[ ])
  PHP_SUBST(SM_SHARED_LIBADD)

fi
