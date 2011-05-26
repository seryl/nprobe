# VERSION  = @PACKAGE_VERSION@
# PACKAGE  = @PACKAGE_NAME@
VERSION = 6.1.6
PACKAGE = nprobe

AUTOMAKE_OPTIONS = foreign 1.6
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = ChangeLog COPYING LICENSE \
             pro/pf_ring.c pro/pf_ring.h \
             .deps/ \
             plugins \
             fastbit 

bin_PROGRAMS=nprobe
nprobe_SOURCES= nprobe.c nprobe.h
nprobe_DEPENDENCIES=libnprobe.la
nprobe_LDADD=libnprobe.la
nprobe_LDFLAGS=$(AM_FLAGS) -pthread -lm -lpcap

lib_LTLIBRARIES=libnprobe.la
libnprobe_la_SOURCES=  bucket.h \
  collect.c \
  database.c \
  engine.c engine.h \
  export.c export.h \
  fb.c \
  globals.c globals.h \
  plugin.c \
  sflow_collect.c \
  util.c util.h \
  version.c \
  $(PF_RING)
libnprobe_la_LDFLAGS = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic

INCLUDES= $(all_includes)
