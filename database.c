/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2004-11 Luca Deri <deri@ntop.org> 
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "nprobe.h"

#ifdef HAVE_MYSQL

/* #define DEBUG */

static MYSQL mysql;
static char * table_prefix = NULL;
u_int8_t db_initialized = 0, skip_db_creation = 0;

/* If you need to add a key to the table
   then add the the V9 name of the field
   to the array below
*/
static char *db_keys[] = {
  "FIRST_SWITCHED",
  "LAST_SWITCHED",
  "IPV4_SRC_ADDR",
  "IPV4_DST_ADDR",
  "L4_SRC_PORT",
  "L4_DST_PORT",
  NULL
};

/* ***************************************************** */

int exec_sql_query(char *sql, u_char dump_error_if_any) {
#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "%s", sql); 
#endif

  if(!db_initialized) {
    static char shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_INFO, "MySQL error: DB not yet initialized");
      traceEvent(TRACE_INFO, "Please use the %s command line option", MYSQL_OPT);
      shown_msg = 1;
    }
    return(-2);
  }

  if(mysql_query(&mysql, sql)) {
    if(dump_error_if_any)
      traceEvent(TRACE_ERROR, "MySQL error: %s", mysql_error(&mysql));
    return(-1);
  } else {
    /* traceEvent(TRACE_INFO, "Successfully executed '%s'", sql);  */
    return(0);
  }
}

/* ***************************************************** */

char* get_last_db_error() {
  return((char*)mysql_error(&mysql));
}

/* ***************************************************** */

char * get_db_table_prefix() { return table_prefix; }

/* ***************************************************** */

int init_database(char *db_host, char* user, char *pw, 
		  char *db_name, char *tp) {
  char sql[2048];

  db_initialized = 0;

  if(mysql_init(&mysql) == NULL) {
    traceEvent(TRACE_ERROR, "Failed to initialize MySQL connection");
    return(-1);
  } else
    traceEvent(TRACE_INFO, "MySQL initialized");

  if(!mysql_real_connect(&mysql, db_host, user, pw, NULL, 0, NULL, 0)){
    traceEvent(TRACE_ERROR, "Failed to connect to MySQL: %s [%s:%s:%s:%s]\n",
	       mysql_error(&mysql), db_host, user, pw, db_name);
    return(-2);
  } else
    traceEvent(TRACE_INFO, "Successfully connected to MySQL [host:dbname:user:passwd]=[%s:%s:%s:%s]",
	       db_host, db_name, user, pw);

  db_initialized = 1;
  table_prefix = strdup(tp);

  /* *************************************** */

  snprintf(sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS %s", db_name);
  if(exec_sql_query(sql, 0) != 0) {
    traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-3);
  }

  if(mysql_select_db(&mysql, db_name)) {
    traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-4);
  }

  /* *************************************** */

  /* NetFlow */
  snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `%sflows` ("
	   "`idx` int(11) NOT NULL auto_increment,"
	   "UNIQUE KEY `idx` (`idx`)"
	   ") ENGINE=MyISAM"
	   /* " DEFAULT CHARSET=latin1" */
	   , table_prefix
	   );

  if(exec_sql_query(sql, 0) != 0) {
    traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-5);
  }

  return(0);
}

/* *************************************** */

static void createTemplateTable(V9V10TemplateElementId **template) {
  char sql[2048];
  int i, j;

  for(i=0; i<TEMPLATE_LIST_LEN; i++) {
    if(template[i] != NULL) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Found [%20s][%d bytes]",
		 template[i]->templateElementName,
		 template[i]->templateElementLen);
#endif

      if((template[i]->elementFormat != ascii_format)
	 && (template[i]->templateElementLen <= 4)) {
	char *sql_type;

	if(template[i]->templateElementLen <= 1)
	  sql_type = "tinyint(4) unsigned";
	else if(template[i]->templateElementLen <= 2)
	  sql_type = "smallint(6) unsigned";
	else if(template[i]->templateElementLen <= 4)
	  sql_type = "int(20) unsigned";

	snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` %s NOT NULL default '0'",
		 table_prefix ? table_prefix : "",
		 template[i]->templateElementName, sql_type);
      } else {
	snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` varchar(%d) NOT NULL default ''",
		 table_prefix ? table_prefix : "",
		 template[i]->templateElementName,
		 2*template[i]->templateElementLen);
      }

      if(exec_sql_query(sql, 0) != 0) {
#ifdef DEBUG
	traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
#endif
      } else {
	for(j=0; db_keys[j] != NULL; j++)
	  if(!strcmp(template[i]->templateElementName, db_keys[j])) {
	    snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD INDEX (`%s`)",
		     table_prefix ? table_prefix : "",
		     template[i]->templateElementName);

	    if(exec_sql_query(sql, 0) != 0) {
#ifdef DEBUG
	      traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
#endif
	    }
	    break;
	  }
      }
    } else
      break;
  }
}

/* ************************************************ */

int init_db_table(void) {
  if(!db_initialized) return(0);

  if(skip_db_creation) {
    traceEvent(TRACE_NORMAL, "Skipping database schema creation...");
    return(0);
  } else
    traceEvent(TRACE_NORMAL, "Creating database schema...");

  traceEvent(TRACE_INFO, "Scanning templates");

  createTemplateTable(readOnlyGlobals.v9TemplateElementListV4);

  if(readOnlyGlobals.v9TemplateElementListV6[0] != NULL) /* IPv6 template defined */
    createTemplateTable(readOnlyGlobals.v9TemplateElementListV6);

  return(0);
}

/* ************************************************ */

void dump_flow2db(V9V10TemplateElementId **template, char *buffer, u_int32_t buffer_len) {
  if(db_initialized) {
    char sql_a[2048] = { 0 }, sql_b[2048] = { 0 }, sql[4096] = { 0 }, buf[128];
    int i, pos = 0;

    /* traceEvent(TRACE_INFO, "dump_flow2db()"); */

    snprintf(sql_a, sizeof(sql_a), "INSERT DELAYED INTO `%sflows` (",
	     table_prefix ? table_prefix : "");
    strcpy(sql_b, "VALUES (");

    for(i=0; (i<TEMPLATE_LIST_LEN); i++) {
      if(template[i] != NULL) {
#ifdef DEBUG
	traceEvent(TRACE_INFO, "Found [%20s][%d bytes]",
		   template[i]->templateElementName,
		   template[i]->templateElementLen);
#endif

	if(i > 0) {
	  strcat(sql_a, ", ");
	  strcat(sql_b, ", ");
	}

	buf[0] = '\0';
	strcat(sql_a, template[i]->templateElementName);

	if((template[i]->elementFormat != ascii_format)
	   && (template[i]->templateElementLen <= 4)) {
	  u_int8_t a = 0, b = 0, c = 0, d = 0;
	  u_int32_t val;

	  if(template[i]->templateElementLen == 1) {
	    d = buffer[pos];
	    pos += 1;
	  } else if(template[i]->templateElementLen == 2) {
	    c = buffer[pos], d = buffer[pos+1];
	    pos += 2;
	  } else if(template[i]->templateElementLen == 3) {
	    b = buffer[pos], c = buffer[pos+1], d = buffer[pos+2];
	    pos += 3;
	  } else if(template[i]->templateElementLen == 4) {
	    a = buffer[pos], b = buffer[pos+1], c = buffer[pos+2], d = buffer[pos+3];
	    pos += 4;
	  }

	  a &= 0xFF, b &= 0xFF, c &= 0xFF, d &= 0xFF;
	  val = (a << 24) + (b << 16) + (c << 8) + d;
	
	  if((template[i]->templateElementId == 21 /* LAST_SWITCHED */)
	     || (template[i]->templateElementId == 22 /* FIRST_SWITCHED */)) {
	    /*
	      We need to patch this value as we want to save the epoch on fastbit and not
	      the sysuptime expressed in msec
	    */

	    if(readOnlyGlobals.numCollectors == 0) /* Don't do this with collectors */
	      val = (val / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;
	  }

	  snprintf(buf, sizeof(buf), "'%u'", val);

	  /*
	    snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` varchar(%d) NOT NULL default ''",
	    table_prefix ? table_prefix : "",
	    template[i]->templateElementName, 
	    template[i]->templateElementLen);
	  */

	  // traceEvent(TRACE_INFO, "%X", val);
	} else {
	  int k = 0, j = 0;

	  buf[0] = '\'';

	  switch(template[i]->elementFormat) {
	  case ipv6_address_format:
	    /* ret = (char*)*/ inet_ntop(AF_INET6, &buffer[pos], &buf[1], sizeof(buf)-1);
	    j = strlen(buf);
	    break;

	  case ascii_format:
	    for(j = 1; k<template[i]->templateElementLen; pos++, k++) {
	      if(buffer[pos] == '\'')
		snprintf(&buf[j], sizeof(buf)-j, "\\%c", buffer[pos]);

	      snprintf(&buf[j], sizeof(buf)-j, "%c", buffer[pos]);
	      j++;
	    }
	    j = strlen(buf);
	    break;

	  case numeric_format:
	  case hex_format:
	    for(j = 1; k<template[i]->templateElementLen; pos++, k++) {
	      snprintf(&buf[j], sizeof(buf)-j, "%02X", buffer[pos] & 0xFF);
	      j += 2;
	    }
	    break;
	  }

	  buf[j] = '\'';
	  buf[j+1] = '\0';
	  
	  if(template[i]->templateElementLen == 0) {
	    traceEvent(TRACE_WARNING, "nProbe does not yet handle variable length flow elements"); //  FIX
	  } else
	    pos += template[i]->templateElementLen;
	}

	strcat(sql_b, buf);
      }

      if(pos > buffer_len) {
	traceEvent(TRACE_WARNING, "Internal error [pos=%d][buffer_len=%d]", 
		   pos, buffer_len);
	break;
      }
    }

    strcat(sql_a, ")");
    strcat(sql_b, ")");

    snprintf(sql, sizeof(sql), "%s %s", sql_a, sql_b);

    exec_sql_query(sql, 1);
  }
}
#endif
