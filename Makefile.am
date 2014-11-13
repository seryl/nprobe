# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the nprobe
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
#       Copyright (C) 2002-14 Luca Deri <deri@ntop.org> 
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
ACLOCAL_AMFLAGS  = -I m4

#
## The name of the game with its own major, minor and release version.
VERSION  = @PACKAGE_VERSION@
PROGRAM  = @PACKAGE_NAME@

PLATFORM =`uname -p`

APPL= nprobe
REVISION=`svn info . | grep "^Revision"|cut -d " " -f 2`
PACKAGE=$(APPL)-@PACKAGE_VERSION@-$(REVISION).$(PLATFORM).rpm
PKGNAME  = @PACKAGE_NAME@

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS) -I @NDPI_INC@
LIBS      = @LIBS@ @CORELIBS@ @MORELIBS@ @LIBNUMA@ @LIBNL@ @NDPI_LIB@ @NT_LIB@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES =  *~ *.log *.lo *.so *.o $(APPL) @PLUGINS@/*.o @PLUGINS@/*.lo  @PLUGINS@/*~ @PLUGINS@/*.so @PLUGINS@/*.la ./private/dmidecode-2.9/*.[oa~] .libs @PLUGINS@/.libs @USE_LICENSE@ nprobes
CLEANFILES     = $(DISTCLEANFILES)

SUBDIRS = . @PLUGINS@

PKG=nprobe-$(PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm
DEV_PKG=nprobe-dev-$(PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm
N2DISK_PKG=n2disk-$(N2DISK_PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm
N2DISKNT_PKG=n2disknt-$(N2DISK_PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm

bin_PROGRAMS = nprobe

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
libnprobe_la_SOURCES = cache.c collect.c engine.c export.c database.c \
		       $(GETOPT_FILES) globals.c plugin.c template.c patricia.c \
		       sflow_collect.c util.c version.c systemId.c $(PF_RING)
libnprobe_la_LDFLAGS = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@
libnprobe_la_DEPENDENCIES = @USE_LICENSE@

private/license/liblicense.a:
	cd private/license; make

#
# We need to compile it this way as the -fPIC libtool directive
# will break the logic
#

#systemId.o: systemId.c Makefile @USE_LICENSE@
#	gcc $(CFLAGS) -I@HERE@ @PIC@ -c systemId.c

cleanup-rpm:
	rm -rf $(HOME)/rpmbuild/BUILD/nprobe* $(HOME)/rpmbuild/SOURCES/nProbe*

cleanup-n2disk-rpm:
	rm -rf $(HOME)/rpmbuild/BUILD/n2disk* $(HOME)/rpmbuild/SOURCES/nProbe*

build-rpm: build-nprobe-rpm build-n2disk-rpm

build-nprobe-rpm: cleanup-rpm maketarproplugins datfiles $(APPL) changelog
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	-rm -rf nprobe-@PACKAGE_VERSION@
	cp -rf nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins nprobe-@PACKAGE_VERSION@
	mkdir -p nprobe-@PACKAGE_VERSION@/packages
	cp packages/*.spec.in nprobe-@PACKAGE_VERSION@/packages
	cp -rf pro nprobe-@PACKAGE_VERSION@
	cp -rf private nprobe-@PACKAGE_VERSION@
	cp *.dat Changelog COPYING LICENSE EULA.txt nprobe-@PACKAGE_VERSION@
	cp plugins/bgpPlugin.c plugins/dbPlugin.c plugins/dnsPlugin.c \
	plugins/httpPlugin.c plugins/mysqlPlugin.c plugins/nflitePlugin.c \
	plugins/rtpPlugin.c plugins/sipPlugin.c plugins/smtpPlugin.c \
	plugins/radiusPlugin.c plugins/gtpv1Plugin.c plugins/gtpv0Plugin.c \
	plugins/sprobe.c plugins/processPlugin.c plugins/l7BridgePlugin.c \
	plugins/gtpv2Plugin.c nprobe-@PACKAGE_VERSION@/plugins
	tar cvfz $(HOME)/rpmbuild/SOURCES/nprobe-@PACKAGE_VERSION@.tgz nprobe-@PACKAGE_VERSION@
	@rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@cp $(APPL) $(HOME)/rpmbuild/BUILD
	@rpmbuild -bb ./packages/$(APPL).spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(DEV_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)"

build-n2disk-rpm: maketarproplugins
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	\/bin/rm -rf n2disk-@N2DISK_PACKAGE_VERSION@
	cp -rf nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins n2disk-@N2DISK_PACKAGE_VERSION@
	mkdir -p n2disk-@N2DISK_PACKAGE_VERSION@/packages
	cp packages/*.spec.in n2disk-@N2DISK_PACKAGE_VERSION@/packages
	cp -rf pro n2disk-@N2DISK_PACKAGE_VERSION@
	cp -rf private n2disk-@N2DISK_PACKAGE_VERSION@
	tar cvfz $(HOME)/rpmbuild/SOURCES/n2disk-@N2DISK_PACKAGE_VERSION@.tgz n2disk-@N2DISK_PACKAGE_VERSION@
	rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	rpmbuild -bb ./packages/n2disk.spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)"


build-n2disknt-rpm: maketarproplugins
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	\/bin/rm -rf n2disknt-@N2DISK_PACKAGE_VERSION@
	cp -rf nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins n2disknt-@N2DISK_PACKAGE_VERSION@
	mkdir -p n2disknt-@N2DISK_PACKAGE_VERSION@/packages
	cp packages/*.spec.in n2disknt-@N2DISK_PACKAGE_VERSION@/packages
	cp -rf pro n2disknt-@N2DISK_PACKAGE_VERSION@
	cp -rf private n2disknt-@N2DISK_PACKAGE_VERSION@
	tar cvfz $(HOME)/rpmbuild/SOURCES/n2disknt-@N2DISK_PACKAGE_VERSION@.tgz n2disknt-@N2DISK_PACKAGE_VERSION@
	rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	rpmbuild -bb ./packages/n2disknt.spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)"
	-rm -rf nProbe-@N2DISK_PACKAGE_VERSION@ nprobe_@N2DISK_PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins.tgz

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
	cd plugins;make
#	$(CC) -static *.o plugins/*.o -o nprobes  -lpcap -lpthread -ldl $(LIBS)
	$(CC)  *.o plugins/*.o -o nprobes -lpthread -ldl -lresolv -ldl -lpthread -L./private/license -llicense $(LIBS) @NDPI_LIB@ $(HOME)/PF_RING/userland/libpcap/libpcap.a $(HOME)/PF_RING/userland/lib/libpfring.a

############

SVN_RELEASE=svn`svn info . | grep "^Revision"|cut -d " " -f 2`

maketar: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp python-config nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp -rf *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp README *.in autogen.sh Makefile.am nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp packages/*.spec.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/packages
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/utils
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h| sed -e 's/AC_CONFIG_FILES(\[plugins\/Makefile\])/echo ""/g' | sed -e 's/PLUGINS=plugins/PLUGINS=/g' > nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/configure.am
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/libtool
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -type d -name ".svn"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE).tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)

maketarproplugins: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*_proplugins
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/bgp
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp python-config nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp packages/*.spec.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/packages
	cp bgp/bgp_probe_client.pl bgp/README nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/bgp
	cp -rf pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/utils
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp plugins/bgpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp README *.in autogen.sh Makefile.am configure.am nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins/ntop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h> nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/configure.am
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/libtool
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins

maketarfranz: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/utils
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/extensions
	cp python-config nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp packages/*.spec.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/packages
	cp -rf pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/ftpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/dhcpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/popPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/imapPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/radiusPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/l7BridgePlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/loadl7example.sh plugins/l7Categorizer.py nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp extensions/*.[ch] nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/extensions
	cp README *.in autogen.sh Makefile.am configure.am nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins/ntop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h > nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/configure.am
	cp -r plugin_sdk nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugin_sdk/Makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/libtool
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	cd nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz; svn co https://svn.ntop.org/svn/ntop/trunk/nDPI/; \find . -name ".svn"|xargs /bin/rm -rf {} ';'
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz

maketarhomer: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*_homer
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/bgp
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp python-config nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp packages/*.spec.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/packages
	cp bgp/bgp_probe_client.pl bgp/README nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/bgp
	cp -rf pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/utils
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/bgpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp README *.in autogen.sh Makefile.am configure.am nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp plugins/README.plugins plugins/sipPlugin.c plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/hep.[ch] plugins/mos.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins/ntop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h> nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/configure.am
	\rm -f nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/libtool
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer


maketarnflite:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_nflite
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/nProbe/plugins
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/kernel
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/userland
	cp plugins/README.plugins plugins/nflitePlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/nProbe/plugins
#	cp private/PF_RING/NFLite/README private/PF_RING/NFLite/Makefile nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/
#	cp private/PF_RING/NFLite/kernel/Makefile private/PF_RING/NFLite/kernel/nflite_plugin.[ch] nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/kernel
#	cp private/PF_RING/NFLite/userland/nflite_dump.c private/PF_RING/NFLite/userland/Makefile nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/userland
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite

maketardns:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_dns
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns/nProbe/plugins
	cp plugins/README.plugins plugins/dnsPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns

maketarhttp:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_http
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http/nProbe/plugins
	cp plugins/README.plugins plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http

maketaremail:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_email
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email/nProbe/plugins
	cp plugins/README.plugins plugins/popPlugin.c plugins/smtpPlugin.c plugins/imapPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email

maketarvoip:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_voip
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip/nProbe/plugins
	cp plugins/README.plugins plugins/sipPlugin.c plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip

maketaroracle:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_oracle
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle/nProbe/plugins
	cp plugins/README.plugins plugins/oraclePlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle

maketarmysql:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_mysql
	mkdir -p nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql/nProbe/plugins
	cp plugins/README.plugins plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql.tgz ./nprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql

tar: maketar maketarproplugins maketarnflite maketarhttp maketardns maketaroracle maketarmysql maketaremail maketarvoip maketarhomer # maketarfranz

binarytar:
	\rm -rf nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)
	mkdir nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE) nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)/plugins
	cp .libs/nprobe .libs/libnprobe-@PACKAGE_VERSION@.so .libs/libnprobe.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)
	cp plugins/.libs/lib*Plugin-@PACKAGE_VERSION@.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)/plugins
	tar cvfz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE).tgz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)

install: install-recursive	

datfiles: GeoLiteCity.dat GeoIPASNum.dat GeoIPASNumv6.dat GeoLiteCityv6.dat

GeoLiteCity.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz; \
	fi
	gunzip GeoLiteCity.dat.gz

GeoIPASNum.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz; \
	fi
	gunzip GeoIPASNum.dat.gz

GeoIPASNumv6.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz; \
	fi
	gunzip GeoIPASNumv6.dat.gz

GeoLiteCityv6.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz; \
	fi
	gunzip GeoLiteCityv6.dat.gz

changelog:
	@echo "Generating changelog for recent activites..."
	@./utils/svn2changelog.py > Changelog
	@echo "Changelog file is ready"

cppcheck:
	cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force $(INCLUDES) $(libnprobe_la_SOURCES) plugins/*.c
