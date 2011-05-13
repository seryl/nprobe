#!/bin/sh
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# Run this to generate all the initial makefiles for nprobe
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Copyright (C) 2004-2006 Rocco Carbone <rocco@ntop.org
# Copyright (C) 2005-2010 Luca Deri     <deri@ntop.org>
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# $Log$
# Revision 1.6  2007/06/05 17:08:26  deri
# Fixes for FreeBSD
#
# Revision 1.5  2006/11/22 09:13:58  deri
# Added fixes for FreeBSD
#
# Revision 2.11  2006/09/03 13:06:05  deri
# Minor updates. Added the skeleton of a new plugin that allows nprobe to be
# queried from remote without a web browser
#
# Revision 2.10  2006/05/26 13:39:44  deri
#
# Added (open)solaris fixes
#
# Revision 2.9  2006/05/17 13:04:00  burton
# (1) Add test for v2.50-2.52 of autoconf to autogen.sh
# (2) Begin to update docs and FAQ with change to autogen.sh
#
# -----Burton
#
#

######################################

#
# This is mostly a fix for FreeBSD hosts that have the
# bad behaviour of calling programs as <program name><version>
#

find_command()
{
    for P in "$1"; do
	IFS=:
	for D in $PATH; do
	    for F in $D/$P; do
		[ -x "$F" ] && echo $F && return 0
	    done
	done
    done
}

#######################################

AUTOMAKE=`find_command 'automake-*'`

version="0.2.1"

echo ""
echo "Starting nProbe automatic configuration system v$version"
echo ""
echo "  Please be patient, there is a lot to do..."
echo ""

# Defaults
NAME=nprobe
LIBTOOL=libtool
LIBTOOLIZE=libtoolize
config="y"

# OSx
(uname -a|grep -v Darwin) < /dev/null > /dev/null 2>&1 ||
{
   echo "....Adding fix for OS X"

   LIBTOOL=glibtool
   LIBTOOLIZE=glibtoolize
}

# The name of this program.
progname=`echo "$0" | sed 's%^.*/%%'`

GNU_OR_DIE=1

help="Try \`$progname --help' for more information"


for arg
do
  case "$arg" in
  -h | --help)
    cat <<EOF
This script should help you to configure 'nprobe'

Usage: $progname [OPTION]...

-h, --help            display this message and exit
-v, --version         print version information and exit
-d, --debug           enable verbose shell tracing
-p, --purge           purge all files which are not part of the source package
    --noconfig        skip the ./configure execution

Any unrecognized options will be passed to ./configure, e.g.:

 ./autogen.sh --prefix=/usr

becomes

 ./configure --prefix=/usr

EOF
    exit 0
    ;;

  --noconfig)
    config="n"
    ;;

  -v | --version)
    echo "$progname $version"
    exit 0
    ;;

  -p | --purge)
    echo "....Cleaning up file system of locally generated files..."

    if [ -f Makefile ]; then
      make -k clean > /dev/null 2>&1
    fi

    rm -rf .deps

    rm -f config.guess
    rm -f config.sub
    rm -f install-sh
    rm -f ltconfig
    rm -f ltmain.sh
    rm -f missing
#    rm -f mkinstalldirs
    rm -f INSTALL
#    rm -f COPYING
    rm -f texinfo.tex

    rm -f acinclude.m4
    rm -f aclocal.m4
    rm -f config.h.in
    rm -f stamp-h.in
    rm -f Makefile.in

    rm -f configure
    rm -f config.h
    rm -f depcomp
    rm -f stamp.h
    rm -f libtool
    rm -f Makefile
    rm -f stamp-h.in
    rm -f stamp-h
    rm -f stamp-h1

    rm -f config.cache
    rm -f config.status
    rm -f config.log

    rm -fr autom4te.cache

    rm -f Makefile
    rm -f Makefile.in
    
    rm -f compile
          
    rm -f plugins/Makefile
    rm -f plugins/Makefile.in

    rm -f *~

    exit 0
  ;;
  esac
done

echo "1. Testing gnu tools...."

($LIBTOOL --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have libtool installed to compile $NAME."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball from ftp://ftp.gnu.org/pub/gnu/libtool"
  echo "     We require version 1.4 or higher"
  echo "     We recommend version 1.5.26 or higher"
  GNU_OR_DIE=0
}

AUTOMAKE=`find_command 'automake*'`
($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have automake installed to compile $NAME."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball from ftp://ftp.gnu.org/pub/gnu/automake"
  echo "     We recommend version 1.6.3 or higher"
  GNU_OR_DIE=0
}

AUTOCONF=`find_command 'autoconf*'`
($AUTOCONF --version) < /dev/null > /dev/null 2>&1 ||
{
  echo
  echo "You must have autoconf installed to compile $progname."
  echo "Download the appropriate package for your distribution, or get the"
  echo "source tarball from ftp://ftp.gnu.org/pub/gnu/autoconf"
  echo "     We recommend version 2.53 or higher"
  GNU_OR_DIE=0
}

if test "$GNU_OR_DIE" -eq 0; then
  exit 1
fi

# Check versions...
libtoolversion=`$LIBTOOL --version < /dev/null 2>&1 | grep libtool | cut -d " " -f 4`
echo "    libtool ..... ${libtoolversion}"
case "${libtoolversion}" in
  *1\.3\.[[45]]\-freebsd\-ports*)
    echo ""
    echo "*******************************************************************"
    echo "*"
    echo "*ERROR: nprobe requires libtool version 1.4 or newer..."
    echo "*"
    echo "* FreeBSD ports 1.3.4 seems to work, so we will let it slide..."
    echo "*"
    echo "* Fasten your seat belt and good luck!  If you are injured, the"
    echo "* development team will disavow any knowledge of your intentions."
    echo "*"
    echo "*******************************************************************"
    ;;
  *1\.[[0-3]]*)
    echo ""
    echo "*******************************************************************"
    echo "*"
    echo "*ERROR: nprobe requires libtool version 1.4 or newer..."
    echo "*"
    echo "*"
    echo "*>>>   Unable to proceed with your request, aborting!"
    echo "*"
    echo "*******************************************************************"
    exit 1
    ;;
esac
echo "        .... ok"


automakeversion=`$AUTOMAKE --version < /dev/null 2>&1 | grep ^automake | cut -d " " -f 4`
echo "    automake .... ${automakeversion}"

case "${automakeversion}" in
  *1\.[[0-5]]*)
        echo ""
    echo "******************************************************************"
    echo "*"
    echo "*ERROR: nprobe requires automake version 1.6 or newer..."
    echo "*"
    echo "*>>>   Unable to proceed with your request, aborting!"
    echo "*"
    echo "*******************************************************************"
    exit 1
    ;;
esac
echo "        .... ok"


autoconfversion=`$AUTOCONF --version < /dev/null 2>&1 | grep ^autoconf | cut -d " " -f 4`
echo "    autoconf .... ${autoconfversion}"

case "${autoconfversion}" in
  *2\.[[0-4]]*)
    echo ""
    echo "******************************************************************"
    echo "*"
    echo "*ERROR: nprobe requires autoconf version 2.53 or newer..."
    echo "*"
    echo "*>>>   Unable to proceed with your request, aborting!"
    echo "*"
    echo "*******************************************************************"
    exit 1
    ;;
  *2\.5\[[0-2]]*)
    echo ""
    echo "******************************************************************"
    echo "*"
    echo "*ERROR: nprobe requires autoconf version 2.53 or newer..."
    echo "*"
    echo "*>>>   Unable to proceed with your request, aborting!"
    echo "*"
    echo "*******************************************************************"
    exit 1
    ;;
esac
echo "        .... ok"

echo ""

#
# 2. prepare the package to use libtool
#
echo "2. Preparing for libtool ...."
$LIBTOOLIZE --copy --force

if [ ! -f libtool.m4.in ]; then
  echo "    Finding libtool.m4.in"
  if [ -f /usr/local/share/aclocal/libtool.m4 ]; then
     echo "        .... found /usr/local/share/aclocal/libtool.m4"
     cp /usr/local/share/aclocal/libtool.m4 libtool.m4.in
  else
     if [ -f /usr/share/aclocal/libtool.m4 ]; then
      echo "        .... found /usr/share/aclocal/libtool.m4"
      cp /usr/share/aclocal/libtool.m4 libtool.m4.in
     else
      echo "        .... not found - aborting!"
     fi
  fi
fi
echo "        .... done"
echo ""

#
# 3. create local definitions for automake
#
echo "3. Create acinclude.m4, local definitions for automake ..."
cat acinclude.m4.in libtool.m4.in > acinclude.m4
echo "        .... done"
echo ""


#
# 4. run 'aclocal' to create aclocal.m4 from configure.in (optionally acinclude.m4)
#
echo "4. Running aclocal to create aclocal.m4 ..."
ACLOCAL=`find_command 'aclocal*'`
\rm aclocal.m4
$ACLOCAL $ACLOCAL_FLAGS
echo "        .... done"
echo ""


if [ -f /usr/share/aclocal/libtool.m4 ]; then
cat /usr/share/aclocal/libtool.m4 >> aclocal.m4
fi

if [ -f /usr/share/aclocal/ltoptions.m4  ]; then
cat /usr/share/aclocal/ltoptions.m4 >> aclocal.m4
fi

if [ -f /usr/share/aclocal/ltversion.m4 ]; then
cat /usr/share/aclocal/ltversion.m4 >> aclocal.m4
fi

if [ -f /usr/share/aclocal/ltsugar.m4 ]; then
cat /usr/share/aclocal/ltsugar.m4 >> aclocal.m4
fi

if [ -f /usr/share/aclocal/lt~obsolete.m4 ]; then
cat /usr/share/aclocal/lt~obsolete.m4 >> aclocal.m4
fi

#
# Generate plugins Makefile.am
#
if test -d plugins; then
    cd plugins;./buildMakefile.sh > ./Makefile.am; cd ..
fi


#
# 5. run 'autoheader' to create config.h.in from configure.in
#
echo "5. Running autoheader to create config.h.in ..."
AUTOHEADER=`find_command 'autoheader*'`
$AUTOHEADER
echo "        .... done"
echo ""

echo "timestamp" > stamp-h.in


#
# 6.
# run 'automake' to create Makefile.in from configure.in and Makefile.am
# (optionally aclocal.m4)
# the generated Makefile.in is compliant to GNU Makefile standard
#
echo "6. Running automake to create Makefile.in ..."
touch NEWS AUTHORS ChangeLog
$AUTOMAKE --add-missing --copy
echo "        .... done"
echo ""

if [ -f /usr/bin/which ]; then
echo "which command found"
else
echo "*************************************************************************"
echo
echo "WARNING: Unable to locate /usr/bin/which: compilation might fail later on"
echo "WARNING: Please make sure that your installation is not too minimal"
echo
echo "*************************************************************************"
fi

\/bin/rm -f libtool
ln -s `which glibtool` libtool

#
# 7.
# run 'autoconf' to create configure from configure.in
#
echo "7. Running autoconf to create configure ..."
$AUTOCONF
echo "        .... done"
echo ""

chmod gou+x ./config.guess

# Needed on some distro as CentOS
if ! test -d m4; then
    \mkdir m4
fi

#
# 8.
# run './configure' for real fun!
#
if [ ".${config}" = ".y" ]; then
  echo "8. Running ./configure ..."
  if [ -x config.status -a -z "$*" ]; then
    ./config.status --recheck
  else
    if test -z "$*"; then
      echo "I am going to run ./configure with no arguments"
      echo "if you wish to pass any to it, please specify them on the $0 command line."
    fi
    ./configure "$@" || exit 1
  fi
else
  echo "8. Skipping ./configure"
  echo "Run ./configure and then make to compile nprobe"
fi
echo ""


#
# cleanup to handle programs garbage
#
rm -f /tmp/acin* /tmp/acout*
rm -f autoha*
rm -f confdefs.h


# Local Variables: 
# mode:shell-script 
# sh-indentation:2 
# End: 
