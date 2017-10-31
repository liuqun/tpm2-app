# Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)

AC_INIT([libtctiprobe],[1.0],[qunliu@zyhx-group.com],[],[https://zyhx-group.com])

AC_PROG_CC
AC_PROG_CXX

AC_CHECK_HEADERS

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([SAPI], [sapi >= 1.2.0])

AC_ARG_ENABLE([static-linking-against-shared-tcti-lib],
	AS_HELP_STRING([--enable-static-linking-against-shared-tcti-lib],
		[Allow to build against shared libtcti-*.so or static libtcti-*.a. (Default is NO)]
	),
	[
		AC_DEFINE([STATIC_LINKING_AGAINST_TCTI_DEVICE_LIB_IS_ALLOWED], [], [If static linking is allowed, libtcti-device.so must be avaliable on both host and target system, but using the libtcti-device.a from host system will also be acceptable])
		AC_DEFINE([STATIC_LINKING_AGAINST_TCTI_SOCKET_LIB_IS_ALLOWED], [], [If static linking is allowed, libtcti-socket.so must be avaliable on both host and target system, but using the libtcti-socket.a from host system will also be acceptable])
		AC_DEFINE([STATIC_LINKING_AGAINST_TCTI_TABRMD_LIB_IS_ALLOWED], [], [If static linking is allowed, libtcti-tabrmd.so must be avaliable on both host and target system, but using the libtcti-tabrmd.a from host system will also be acceptable])
		PKG_CHECK_MODULES([TCTI_DEVICE], [tcti-device >= 1.2.0])
		PKG_CHECK_MODULES([TCTI_SOCKET], [tcti-socket >= 1.2.0])
		PKG_CHECK_MODULES([TCTI_TABRMD], [tcti-tabrmd >= 1.1.1])
	],
	[
		AC_CHECK_HEADERS([tcti/tcti_device.h])
		AC_CHECK_HEADERS([tcti/tcti_socket.h])
		AC_CHECK_HEADERS([tcti/tcti-tabrmd.h])
	]
)

AC_DEFINE([FEATURE_TCTI_PROBE_ENABLED], [], [Enable this feature by default])

AC_CONFIG_FILES([config.mk])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
