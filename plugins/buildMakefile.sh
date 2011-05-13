#!/bin/bash

plugins=`ls *Plugin.c`

programs=""
ltlibraries=""


####################################

echo "SUBDIRS = . "

echo "PLUGIN_DIST_COMMON = Makefile.am Makefile.in"
echo "DISTCLEANFILES =  \#* *~ *.log *.o"
echo "CLEANFILES     = \$(DISTCLEANFILES)"
echo "EXTRA_DIST  ="

echo "SUFFIXES    = .so"

echo "# "
echo "# Where to install the plugin "
echo "# "
echo "plugindir = \${exec_prefix}/lib/nprobe/plugins"
echo "libdir = \$(plugindir)"
echo
echo "INCLUDES = -I.. @INCS@ "
echo
echo ".NOTPARALLEL:"


####################################

for name in $plugins
do
    plugin=$(echo $name | cut -d '.' -f 1)
    #echo $plugin

    programs="$programs ${plugin}.so"
    ltlibraries="$ltlibraries lib${plugin}.la"
    echo
    echo "############################################"
    echo
    echo "lib${plugin}_la_SOURCES = ${plugin}.c"
    echo "lib${plugin}_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@"
    echo "lib${plugin}_la_CFLAGS = \$(AM_CFLAGS)"
    echo
    echo ".libs/lib${plugin}.so@SO_VERSION_PATCH@:"
    echo "	@if test -f lib${plugin}_la-${plugin}.o; then \\"
    echo "    \$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/lib${plugin}.so@SO_VERSION_PATCH@ lib${plugin}_la-${plugin}.o; \\"
    echo "    else \\"
    echo "    \$(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/lib${plugin}.so@SO_VERSION_PATCH@ ${plugin}.o; \\"
    echo "    fi"
    echo
    echo "${plugin}.so\$(EXEEXT): .libs/lib${plugin}.so@SO_VERSION_PATCH@"
    echo "	@\$(LN_S) .libs/lib${plugin}.so ${plugin}.so\$(EXEEXT)"
    echo
done

echo "############################################"

echo "noinst_PROGRAMS = $programs"
echo "lib_LTLIBRARIES = $ltlibraries"


