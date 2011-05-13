/*              __ _
 *             / _| |__   __ _ _   _  ___ _ __ _   _
 *            | |_| '_ \ / _` | | | |/ _ \ '__| | | |
 *            |  _| |_) | (_| | |_| |  __/ |  | |_| |
 *            |_| |_.__/ \__, |\__,_|\___|_|   \__, |
 *                          |_|                |___/
 *
 *                     Copyright (C) 2009-2010
 *                    Luca Deri <deri@ntop.org>
 *             Valeria Lorenzetti <lorenzetti@ntop.org>
 *
 *                     http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */


#ifndef _FBQUERY_H_
#define _FBQUERY_H_


/* Operating System header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#define DISABLE_GEOIP

/* C++ */
#define WITHOUT_FASTBIT_CONFIG_H

#include "ibis.h"
#include "tafel.h"

extern "C" {
#include "nprobe.h"
#include "capi.h"


  /* Version info */
#define FBQUERY_VERSION   "1.4.4"
#define FBQUERY_RELEASE   __DATE__


#define CSV_SEPARATOR  "|"
#define XMLTAG_RESULT  "Result"
#define XMLTAG_ROW     "Row"

#define IPV6_SRC_ADDR  "IPV6_SRC_ADDR"
#define IPV6_DST_ADDR  "IPV6_DST_ADDR"


  /* Column type */
  typedef struct
  {
    /* Column name */
    char * name;

    /* How to dump it */
    int type;

  } col_t;


  /* Fuctions in file fbutils.cpp */
  extern col_t ** parse_metadata_file (FILE * file, char ** columns);
  extern char * get_value_ij (char * value_ij, char * column, ibis::bundle &bun,
			      uint64_t row, u_int32_t col, col_t ** clist, u_int8_t native);
  extern void convert_ip (string &query);
  extern void convert_int (string &query);
  extern char ** get_subdirs (char * dirname, char ** dirs);
  extern col_t * mkcol (char * name, int type);
  extern void rmcol (void * col);
  extern int get_column_type (col_t ** clist, char * name);
  extern int vlen (void * argv []);
  extern void ** vmore (void * argv [], void * item);
  extern void ** vcleanup (void * argv [], void (* rmitem) (void *));
  extern char ** argsadd (char * argv [], char * s);
  extern char ** argspieces (char * list, char * separator);
  extern char * dump_formatted_uint (unsigned long input, char * output, int outputLen);
  extern char * dump_tcp_flags (u_int8_t flags, char * output, int outputLen);

  /* Functions in file fastbit.c */
  extern int lock_dir(char *dir);
  extern int unlock_dir(char *dir);
};

#if defined(WIN32)
#define DIRENT_INCLUDED

struct dirent
{
    char *d_name;
};


typedef struct DIR
{
    long                handle; /* -1 for failed rewind */
    struct _finddata_t  info;
    struct dirent       result; /* d_name null iff first time */
    char                *name;  /* NTBS */
} DIR;

extern "C" {
DIR           *opendir(const char *);
int           closedir(DIR *);
fstruct dirent *readdir(DIR *);
void          rewinddir(DIR *);
};

#endif

#endif /* _FBQUERY_H_ */
