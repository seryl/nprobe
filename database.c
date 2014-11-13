/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2004-14 Luca Deri <deri@ntop.org>
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

#ifndef htonll
#define ntohll(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )                                        
#define htonll(x) ntohll(x)
#endif

/* ***************************************************** */

int exec_sql_query(char *sql, u_char dump_error_if_any) {
  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_NORMAL, "%s", sql);

  if(!readOnlyGlobals.db_initialized) {
    static char shown_msg = 0;

    if(!shown_msg) {
      traceEvent(TRACE_INFO, "MySQL error: DB not yet initialized");
      traceEvent(TRACE_INFO, "Please use the %s command line option", MYSQL_OPT);
      shown_msg = 1;
    }
    return(-2);
  }

  if(mysql_query(&readOnlyGlobals.db.mysql, sql)) {
    if(dump_error_if_any)
      traceEvent(TRACE_ERROR, "MySQL error: [%s][%s]", mysql_error(&readOnlyGlobals.db.mysql), sql);
    return(-1);
  } else {
    /* traceEvent(TRACE_INFO, "Successfully executed '%s'", sql);  */
    return(0);
  }
}

/* ***************************************************** */

char* get_last_db_error() {
  return((char*)mysql_error(&readOnlyGlobals.db.mysql));
}

/* ***************************************************** */

char* get_db_table_prefix() { return readOnlyGlobals.db.table_prefix; }

/* ***************************************************** */

int init_database(char *db_host, u_int db_port,
		  char* user, char *pw,
		  char *db_name, char *tp) {
  char sql[2048];
  MYSQL *rc;

  readOnlyGlobals.db_initialized = 0;

  if(mysql_init(&readOnlyGlobals.db.mysql) == NULL) {
    traceEvent(TRACE_ERROR, "Failed to initialize MySQL connection");
    return(-1);
  } else
    traceEvent(TRACE_INFO, "MySQL initialized");

  if(db_host[0] == '/')
    rc = mysql_real_connect(&readOnlyGlobals.db.mysql, NULL /* host */, user, pw,
			    NULL /* db */, 0, db_host /* socket */, 0);
  else
    rc = mysql_real_connect(&readOnlyGlobals.db.mysql, db_host, user, pw,
			    NULL /* db */, db_port, NULL /*socket */, 0);

  if(rc == NULL) {
    traceEvent(TRACE_ERROR, "Failed to connect to MySQL: %s [%s:%s:%s:%s]\n",
	       mysql_error(&readOnlyGlobals.db.mysql), db_host, user, pw, db_name);
    return(-2);
  } else {
    char pwd[32];
    int len = min(strlen(pw), sizeof(pwd)-1);

    memset(pwd, 'x', len);
    pwd[len] = '\0';

    traceEvent(TRACE_INFO, "Successfully connected to MySQL [host:dbname:user:passwd]=[%s@%d:%s:%s:%s]",
	       db_host, db_port, db_name, user, pwd);
  }

  readOnlyGlobals.db_initialized = 1;
  readOnlyGlobals.db.table_prefix = strdup(tp);

  /* *************************************** */

  snprintf(sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS %s", db_name);
  if(exec_sql_query(sql, 0) != 0) {
    traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-3);
  }

  if(mysql_select_db(&readOnlyGlobals.db.mysql, db_name)) {
    traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-4);
  }

  /* *************************************** */

  /* NetFlow */
  snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `%sflows` ("
	   "`idx` int(11) NOT NULL auto_increment,"
	   "UNIQUE KEY `idx` (`idx`)"
	   ") ENGINE=%s"
	   /* " DEFAULT CHARSET=latin1" */
	   , readOnlyGlobals.db.table_prefix, readOnlyGlobals.dbEngineType);

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
      if(readOnlyGlobals.enable_debug)
	traceEvent(TRACE_INFO, "Found [%20s][%d bytes]",
		   template[i]->netflowElementName,
		   template[i]->templateElementLen);

      if((template[i]->elementFormat != ascii_format)
	 && (template[i]->templateElementLen <= 4)) {
	char *sql_type = "";

	if(template[i]->templateElementLen <= 1)
	  sql_type = "tinyint(4) unsigned";
	else if(template[i]->templateElementLen <= 2)
	  sql_type = "smallint(6) unsigned";
	else if(template[i]->templateElementLen <= 4)
	  sql_type = "int(20) unsigned";

	snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` %s NOT NULL default '0'",
		 readOnlyGlobals.db.table_prefix ? readOnlyGlobals.db.table_prefix : "",
		 template[i]->netflowElementName, sql_type);
      } else {
	snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` varchar(%d) NOT NULL default ''",
		 readOnlyGlobals.db.table_prefix ? readOnlyGlobals.db.table_prefix : "",
		 template[i]->netflowElementName,
		 2*template[i]->templateElementLen);
      }

      if(exec_sql_query(sql, 0) != 0) {
	if(readOnlyGlobals.enable_debug)
	traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
      } else {
	for(j=0; db_keys[j] != NULL; j++)
	  if(!strcmp(template[i]->netflowElementName, db_keys[j])) {
	    snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD INDEX (`%s`)",
		     readOnlyGlobals.db.table_prefix ? readOnlyGlobals.db.table_prefix : "",
		     template[i]->netflowElementName);

	    if(exec_sql_query(sql, 0) != 0) {
	      if(readOnlyGlobals.enable_debug)
		traceEvent(TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
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
  int i;

  if(!readOnlyGlobals.db_initialized) return(0);

  if(readOnlyGlobals.skip_db_creation) {
    traceEvent(TRACE_NORMAL, "Skipping database schema creation...");
    return(0);
  } else
    traceEvent(TRACE_NORMAL, "Creating database schema...");

  traceEvent(TRACE_INFO, "Scanning templates");

  for(i=0; i<readOnlyGlobals.numActiveTemplates; i++)
    createTemplateTable(readOnlyGlobals.templateBuffers[i].v9TemplateElementList);

  return(0);
}

/* ************************************************ */

void dump_flow2db(V9V10TemplateElementId **template, char *buffer, u_int32_t buffer_len) {
  if(readOnlyGlobals.db_initialized) {
    char sql_a[4096] = { 0 }, sql_b[4096] = { 0 }, sql[4096] = { 0 }, buf[256];
    int i, pos = 0;

    /* traceEvent(TRACE_INFO, "dump_flow2db()"); */

    snprintf(sql_a, sizeof(sql_a), "INSERT INTO `%sflows` (",
	     readOnlyGlobals.db.table_prefix ? readOnlyGlobals.db.table_prefix : "");
    strcpy(sql_b, "VALUES (");

    for(i=0; (i<TEMPLATE_LIST_LEN) && (template[i] != NULL); i++) {
      u_int16_t field_len;

      if(i > 0) {
	strcat(sql_a, ", ");
	strcat(sql_b, ", ");
      }

      buf[0] = '\0';
      memset(buf, 0, sizeof(buf));
      strcat(sql_a, template[i]->netflowElementName);

      if((readOnlyGlobals.netFlowVersion == 10)
	 && (template[i]->variableFieldLength == VARIABLE_FIELD_LEN)) {
	field_len = buffer[pos];
	pos++;

	if(field_len == 255) {
	  /* Long length */
	  memcpy(&field_len, &buffer[pos], 2);
	  pos += 2;
	  field_len = ntohs(field_len);
	}
      } else
	field_len = template[i]->templateElementLen;

      if((template[i]->elementFormat != ascii_format)
	 && (field_len <= 4)) {
	u_int8_t a = 0, b = 0, c = 0, d = 0;
	u_int32_t val;

	if(field_len == 1) {
	  d = buffer[pos];
	} else if(field_len == 2) {
	  c = buffer[pos], d = buffer[pos+1];
	} else if(field_len == 3) {
	  b = buffer[pos], c = buffer[pos+1], d = buffer[pos+2];
	} else if(field_len == 4) {
	  a = buffer[pos], b = buffer[pos+1], c = buffer[pos+2], d = buffer[pos+3];
	}
	pos += field_len;

	a &= 0xFF, b &= 0xFF, c &= 0xFF, d &= 0xFF;
	val = (a << 24) + (b << 16) + (c << 8) + d;

	if((template[i]->templateElementId == 21 /* LAST_SWITCHED */)
	   || (template[i]->templateElementId == 22 /* FIRST_SWITCHED */)) {
	  /*
	    We need to patch this value as we want to save the epoch on fastbit and not
	    the sysuptime expressed in msec
	  */

	  val = (val / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;
	}

	snprintf(buf, sizeof(buf), "'%u'", val);

	if(readOnlyGlobals.enable_debug)
	  traceEvent(TRACE_NORMAL, "[%s][%u][variable length=%s]",
		     template[i]->netflowElementName, val,
		     template[i]->variableFieldLength == VARIABLE_FIELD_LEN ? "Yes" : "No");

	/*
	  snprintf(sql, sizeof(sql), "ALTER TABLE `%sflows` ADD `%s` varchar(%d) NOT NULL default ''",
	  readOnlyGlobals.db.table_prefix ? readOnlyGlobals.db.table_prefix : "",
	  template[i]->netflowElementName,
	  field_len);
	*/

	// traceEvent(TRACE_INFO, "%X", val);
      } else {
	int j = 0;
	int dump_len = min(field_len, sizeof(buf));

	/*
	if(dump_len == 0)
	  traceEvent(TRACE_WARNING, "Zero length detected");
	*/

	buf[0] = '\'';

	if(dump_len > 0) {  
	  switch(template[i]->elementFormat) {
	  case ipv6_address_format:
	    /* ret = (char*)*/ inet_ntop(AF_INET6, &buffer[pos], &buf[1], sizeof(buf)-1);
	    j = strlen(buf);
	    pos += field_len;
	    break;

	  case ascii_format:
	    {
	      int k;
	      
	      for(k = 0, j = 1; k<dump_len; pos++, k++) {
		if(buffer[pos] == '\'') {
		  snprintf(&buf[j], sizeof(buf)-j, "\\%c", buffer[pos]);
		  j++; /* We add both \\ and ' */
		} else
		  snprintf(&buf[j], sizeof(buf)-j, "%c", buffer[pos]);
		j++;
	      }
	      j = strlen(buf);
	    }
	    break;

	  case numeric_format:
	    {
	      u_int8_t u8;
	      u_int16_t u16;
	      u_int32_t u32;
	      u_int64_t u64;

	      switch(dump_len) {
	      case 1:
		u8 = *(u_int8_t*)&buffer[pos];
		u64 = (u_int64_t)u8;
		break;
	      case 2:
		u16 = *(u_int16_t*)&buffer[pos];
		u64 = (u_int64_t)ntohs(u16);
		break;
	      case 4:
		u32 = *(u_int32_t*)&buffer[pos];
		u64 = (u_int64_t)ntohl(u32);
		break;
	      case 8:
		u64 = ntohll(*(u_int64_t*)&buffer[pos]);
		break;
	      default:
		traceEvent(TRACE_WARNING, "Internal error [dump_len=%u]", dump_len);
	      }
	      
	      j = 1;
	      snprintf(&buf[j], sizeof(buf)-j, "%lu", u64);
	      j = strlen(buf);
	    }
	    break;

	  case hex_format: 
	    {
	      int k;
	      
	      for(j = 1, k = 0; k<dump_len; pos++, k++) {
		snprintf(&buf[j], sizeof(buf)-j, "%02X", buffer[pos] & 0xFF);
		j += 2;
	      }
	    }
	    break;
	  }
	} else
	  j = 1;

	buf[j] = '\'';
	buf[j+1] = '\0';

	if(readOnlyGlobals.enable_debug)
	  traceEvent(TRACE_NORMAL, "[%s][%s][len=%d][variable length=%s]",
		     template[i]->netflowElementName, buf, field_len,
		     template[i]->variableFieldLength == VARIABLE_FIELD_LEN ? "Yes" : "No");
      }

      strcat(sql_b, buf);

      if(pos > buffer_len) {
	traceEvent(TRACE_WARNING, "Internal error [pos=%d][buffer_len=%d]",
		   pos, buffer_len);
	break;
      }

      if(readOnlyGlobals.enable_debug && (template[i] != NULL))
	traceEvent(TRACE_INFO, "Handled %20s [id %d][%d bytes][total %d/%d bytes]",
		   template[i]->netflowElementName,
		   (template[i]->templateElementEnterpriseId == NTOP_ENTERPRISE_ID) ? template[i]->templateElementId-NTOP_BASE_ID : template[i]->templateElementId,
		   field_len, pos, buffer_len);

    }

    strcat(sql_a, ")");
    strcat(sql_b, ")");

    snprintf(sql, sizeof(sql), "%s %s", sql_a, sql_b);

    exec_sql_query(sql, 1);
  }
}
#endif
