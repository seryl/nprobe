# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the nprobe
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
#       Copyright (C) 2002-2010 Luca Deri <deri@ntop.org> 
#
#                     http://www.ntop.org/ 
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.

#
## The name of the game with its own major, minor and release version.
VERSION  = @PACKAGE_VERSION@
PROGRAM  = @PACKAGE_NAME@

PLATFORM=`uname -p`

APPL= nprobe
APPL_DEMO= nprobe_demo

PACKAGE=$(APPL)-@PACKAGE_VERSION@-0.$(PLATFORM).rpm
PKGNAME  = @PACKAGE_NAME@
PACKAGEDEMO=$(APPL)-demo-@PACKAGE_VERSION@-0.i386.rpm

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS)
LIBS      = @LIBS@ @CORELIBS@ @MORELIBS@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES =  *~ *.log *.lo *.so *.o $(APPL) @PLUGINS@/*.o @PLUGINS@/*.lo  @PLUGINS@/*~ @PLUGINS@/*.so @PLUGINS@/*.la ./private/dmidecode-2.9/*.[oa~] .libs @PLUGINS@/.libs
CLEANFILES     = $(DISTCLEANFILES)

SUBDIRS = . @PLUGINS@

bin_PROGRAMS  		 = nprobe
EXTRA_PROGRAMS		 = nprobe_demo

# nprobe
nprobe_SOURCES = nprobe.c
nprobe_DEPENDENCIES = libnprobe.la
nprobe_LDADD = libnprobe.la
nprobe_LDFLAGS = $(AM_LDFLAGS) -pthread -lm
nprobe_CFLAGS =

lib_LTLIBRARIES = libnprobe.la

# nprobe core library

#
# On old systems getopt might be undefined
#
GETOPT_FILES=#getopt1.c getopt.c
libnprobe_la_SOURCES = collect.c engine.c export.c database.c fb.c \
		       $(GETOPT_FILES) globals.c plugin.c \
		       sflow_collect.c util.c version.c $(PF_RING)
libnprobe_la_LDFLAGS = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# demo nprobe
nprobe_demo_SOURCES = nprobe.c
nprobe_demo_DEPENDENCIES = libnprobe.la
nprobe_demo_LDADD = libnprobe.la
nprobe_demo_LDFLAGS = $(AM_LDFLAGS)
nprobe_demo_CFLAGS = $(AM_LDFLAGS) -DDEMO_MODE

cleanup-rpm:
	rm -rf /usr/src/redhat/BUILD/nprobe* /usr/src/redhat/SOURCES/nProbe*

build-suse: $(APPL)
	@rm -f /usr/src/redhat/RPMS/$(PLATFORM)/$(PACKAGE)
	@cp $(APPL)  /usr/src/packages/BUILD
	@rpm -bb $(APPL).spec
	@mv /usr/src/packages/RPMS/$(PLATFORM)/$(PACKAGE) .

build-rh: cleanup-rpm maketarproplugins $(APPL)
	rm -rf nprobe-@PACKAGE_VERSION@
	mv nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins nprobe-@PACKAGE_VERSION@
	tar cvfz /usr/src/redhat/SOURCES/nProbe-@PACKAGE_VERSION@.tgz nprobe-@PACKAGE_VERSION@
	@rm -f /usr/src/redhat/RPMS/$(PLATFORM)/$(PACKAGE)
	@cp $(APPL) /usr/src/redhat/BUILD
	@rpmbuild -bb $(APPL).spec
	@mv /usr/src/redhat/RPMS/$(PLATFORM)/$(PACKAGE) .
	echo "Package $(PACKAGE) is now available"

build-cisco: cleanup-rpm maketarcisco $(APPL)
	rm -rf nprobe-@PACKAGE_VERSION@
	mv nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco nprobe-@PACKAGE_VERSION@
	tar cvfz /usr/src/redhat/SOURCES/nProbe-@PACKAGE_VERSION@.tgz nprobe-@PACKAGE_VERSION@
	@rm -f /usr/src/redhat/RPMS/$(PLATFORM)/$(PACKAGE)
	@cp $(APPL) /usr/src/redhat/BUILD
	@rpmbuild -bb $(APPL).spec
	@mv /usr/src/redhat/RPMS/$(PLATFORM)/$(PACKAGE) .
	echo "Package $(PACKAGE) is now available"

CLEANLIST = `ls -l $(DESTDIR)$(libdir)/*nprobe*.so $(DESTDIR)$(libdir)/*Plugin*.so | \
          grep -v $(VERSION) | \
          grep -v '\->' | \
          $(AWK) '{ print $$NF }'`

listlibclean:
	@echo ""
	@echo "This is a list of old shared library files that will be deleted"
	@echo "if you run 'make libclean'"
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""

libclean:
	@echo ""
	@echo "Cleanup of old shared library files..."
	@echo ""
	@echo "  This is a list of files that will be deleted..."
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""
	@echo ""
	@echo "Press cntl-c to stop or enter to continue and delete these files..."
	@read select
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   ...Deleting $$file"; \
             rm -f $$file; \
          fi; \
        done


clean:
	/bin/rm -rf $(CLEANFILES)

nprobes: $(nprobe_OBJECTS) $(nprobe_DEPENDENCIES)
	$(CC) -static *.o -o nprobes  -lpcap -lpthread -ldl $(LIBS)

#nprobes: $(nprobe_OBJECTS) nprobe
#	$(CC) -static *.o -o nprobes $(LIBS)

# Use a different name than fastbit as it's a directory
fast_bit:
	@if test -d "./fastbit"; then \
		cd fastbit; make; \
	fi


############

TODAY=`date +"%D" | sed -e 's/\///g'`

maketar: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp -r *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)
# Remove private + fastbit makefile
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' | sed -e 's/AC_CONFIG_FILES(\[plugins\/Makefile\])/echo ""/g' | sed -e 's/PLUGINS=plugins/PLUGINS=/g' > nprobe_@PACKAGE_VERSION@_$(TODAY)/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY).tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)


maketarpro: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/fastbit
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp plugins/dumpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp plugins/l7Plugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp -r fastbit/Makefile.in fastbit/*.cpp fastbit/*.[ch] fastbit/README* nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/fastbit
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins/ntop*
	grep -v 'private/Makefile' configure.in > nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro

maketarproplugins: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/fastbit
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/bgp
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp bgp/bgp_probe_client.pl bgp/README nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/bgp
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/bgpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/patricia.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/dumpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/l7Plugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp -r fastbit/Makefile.in fastbit/*.cpp fastbit/*.[ch] fastbit/README* nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/fastbit
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins/ntop*
	grep -v 'private/Makefile' configure.in > nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins

maketarcisco: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/bgp
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/html
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/python
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/private
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	cp utils/Makefile utils/nf_reflector.c nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	cp  private/mongoose.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/private
	cp -r ./html/ntop_logo.png ./html/favicon.ico ./html/white_bg.gif ./html/style.css ./html/index.html ./html/sparkline nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/html
	cp python/nprobeStats.py nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/python
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	cp plugins/ntopPlugin.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	cp utils/nf_reflector.conf nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils/nf_reflector.conf.example
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco

binarytar:
	\rm -rf nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY) nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)/plugins
	cp .libs/nprobe .libs/libnprobe-@PACKAGE_VERSION@.so .libs/libnprobe.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)
	cp plugins/.libs/lib*Plugin-@PACKAGE_VERSION@.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)/plugins
	tar cvfz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY).tgz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)

install: install-recursive	

datfiles: GeoLiteCity.dat GeoIPASNum.dat

GeoLiteCity.dat:
	wget http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	gunzip GeoLiteCity.dat.gz

GeoIPASNum.dat:
	wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
	gunzip GeoIPASNum.dat.gz
