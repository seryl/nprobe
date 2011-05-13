/*
 *  Copyright (C) 2006-11 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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
 */

#include "nprobe.h"


/* #define DEBUG */

static V9V10TemplateElementId dbPlugin_template[] = {
  /* Nothing to export into a template */
  { FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL }
};

/* *********************************************** */

static PluginInfo dbPlugin; /* Forward */

/* *********************************************** */

#ifdef HAVE_MYSQL
static char * tokenizer(char * arg, int c, char **data) {
  char *p = NULL;

  if((p = strchr(arg, c)) != NULL) {
    *p = '\0';
    if(data) {
      if(strlen(arg))
	*data = strdup(arg);
      else
	*data = strdup("");
    }

    arg = &(p[1]);
  } else if (data)
    *data = NULL;

  return (arg);
}
#endif

/* *********************************************** */

void dbPlugin_init(int argc, char *argv[]) {
  int save = readOnlyGlobals.traceLevel;
#ifdef HAVE_MYSQL
  int i;
  char *arg = NULL, *host=NULL, *user=NULL, *pw=NULL, *dbname=NULL, *tprefix=NULL;

  skip_db_creation = 0;
#endif

  readOnlyGlobals.traceLevel = 10;

#ifdef HAVE_MYSQL
  traceEvent(TRACE_INFO, "Initializing DB plugin\n");

  if((argc == 2) && (argv[1][0] != '-')) {
    FILE * fd;
    char   line[256];

    fd = fopen(argv[1], "r");
    if(fd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to read config. file %s", argv[1]);
      fclose(fd);
      return;
    }

    while(fgets(line, sizeof(line), fd)) {
      char * p = NULL;

      if(strncmp(line, MYSQL_SKIP_DB_CREATION, strlen(MYSQL_SKIP_DB_CREATION)) == 0) {
	skip_db_creation = 1;
      } else if((strncmp(line, MYSQL_OPT, strlen(MYSQL_OPT)) == 0) 
		&& ((line[strlen(MYSQL_OPT)] == ' ') || (line[strlen(MYSQL_OPT)] == '='))) {
	int sz = strlen(line)+2;
	arg = malloc(sz);
	if(arg == NULL) {
	  traceEvent(TRACE_ERROR, "Not enough memory?");
	  fclose(fd);
	  return;
	}
	p = strchr(line,'\n');
	if(p) *p='\0';
	p = strchr(line,'=');
	snprintf(arg, sz, "%s:", p+1);
      }
    }

    fclose(fd);
  } else {
    for(i=0; i<argc; i++)

      if(strncmp(argv[i], MYSQL_SKIP_DB_CREATION, strlen(MYSQL_SKIP_DB_CREATION)) == 0) {
	skip_db_creation = 1;
      } else if((strncmp(argv[i], MYSQL_OPT, strlen(MYSQL_OPT)) == 0) 
		&& ((argv[i][strlen(MYSQL_OPT)] == ' ') || (argv[i][strlen(MYSQL_OPT)] == '='))) {
	char *mysql_arg = argv[i+1];
	int sz;

	if(argv[i][strlen(MYSQL_OPT)] == '=') {
	  mysql_arg = &argv[i][strlen(MYSQL_OPT)+1];
       } else
	  mysql_arg = argv[i+1];

	sz = strlen(mysql_arg)+2;

	if(mysql_arg == NULL) {
	  traceEvent(TRACE_ERROR, "Bad format specified for --mysql parameter");
	  return;
	}

	sz = strlen(mysql_arg)+2;

	arg = malloc(sz);
	if(arg == NULL) {
	  traceEvent(TRACE_ERROR, "Not enough memory?");
	  return;
	}

	snprintf(arg, sz, "%s:", mysql_arg);
      }
  }

  if(arg) {
    char * arg_save = arg;

    /* <host>:<dbname>:<table_prefix>:<user>:<pw>  --mysql=localhost:::root: */
    arg = tokenizer(arg, ':', &host);
    arg = tokenizer(arg, ':', &dbname);
    arg = tokenizer(arg, ':', &tprefix);
    arg = tokenizer(arg, ':', &user);
    arg = tokenizer(arg, ':', &pw);

    if(host && user) {
      if(dbname == NULL)  dbname  = strdup("nprobe");
      if(tprefix == NULL) tprefix = strdup("table_");
      if(pw == NULL)      pw      = strdup("");

      traceEvent(TRACE_INFO, "Attempting to connect to database as [%s][%s][%s][%s][%s]",
		 host, dbname, tprefix, user, pw);
      init_database(host, user, pw, dbname, tprefix);
    } else {
      traceEvent(TRACE_WARNING,
		 "Bad format for --mysql=<host>:<dbname>:<table_prefix>:<user>:<pw> [host=%s][dbname=%s][table prefix=%s][user=%s][pw=%s]",
		 host, dbname, tprefix, user, pw);
      traceEvent(TRACE_WARNING, "Database support has been disabled.");
    }

    if(host    != NULL) free(host);
    if(dbname  != NULL) free(dbname);
    if(tprefix != NULL) free(tprefix);
    if(user    != NULL) free(user);
    if(pw      != NULL) free(pw);
    free(arg_save);
  }
#else
  traceEvent(TRACE_INFO, "WARNING: DB support is not enabled (disabled at compile time)");
#endif

  readOnlyGlobals.traceLevel = save;
}

/* *********************************************** */

static void dbPlugin_packet(u_char new_bucket, void *pluginData,
			    FlowHashBucket *bkt,
			    FlowDirection flow_direction,
			    u_short proto, u_char isFragment,
			    u_short numPkts, u_char tos,
			    u_short vlanId, struct eth_header *ehdr,
			    IpAddress *src, u_short sport,
			    IpAddress *dst, u_short dport,
			    u_int len, u_int8_t flags,
			    u_int32_t tcpSeqNum, u_int8_t icmpType,
			    u_short numMplsLabels,
			    u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			    const struct pcap_pkthdr *h, const u_char *p,
			    u_char *payload, int payloadLen
			    ) {
#ifdef HAVE_MYSQL
  if(!db_initialized) return;

  if(new_bucket) {
    PluginInformation *info;

    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&dbPlugin;
    info->pluginData = NULL;

    info->next = bkt->plugin;
    bkt->plugin = info;

#ifdef DEBUG
    traceEvent(TRACE_INFO, "dbPlugin_create called.\n");
#endif
  }
#endif
}

/* *********************************************** */

static void dbPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "dbPlugin_delete called.");
#endif

#ifdef HAVE_MYSQL
  if(!db_initialized) return;

  if(pluginData != NULL) {
    struct plugin_info *info = (struct plugin_info*)pluginData;
#ifdef DEBUG
    char buf[256], buf1[256];

    traceEvent(TRACE_INFO, "Flow [%s:%d -> %s:%d] terminated.\n",
	       _intoa(bkt->src, buf, sizeof(buf)), (int)bkt->sport,
	       _intoa(bkt->dst, buf1, sizeof(buf1)), (int)bkt->dport);
#endif

    free(info);
  }
#endif
}

/* *********************************************** */

static V9V10TemplateElementId* dbPlugin_get_template(char* template_name) {
  int i;

  for(i=0; dbPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, dbPlugin_template[i].templateElementName)) {
      return(&dbPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

static int dbPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate, 
			   FlowDirection direction,
			   FlowHashBucket *bkt, char *outBuffer,
			   uint* outBufferBegin, uint* outBufferMax) {

  // traceEvent(TRACE_ERROR, " +++ dbPlugin_export()");

  return(-1); /* Not handled */
}

/* *********************************************** */

static int dbPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate, FlowDirection direction,
			  FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  return(-1); /* Not handled */
}

/* *********************************************** */

static void dbPlugin_help(void) {
#ifdef HAVE_MYSQL
  printf("  --mysql=<host>:<dbname>:<table_prefix>:<user>:<pw> | Enable MySQL database support configuration\n");
  printf("  %s                           | Skip database schema creation\n", MYSQL_SKIP_DB_CREATION);
#endif
}

/* *********************************************** */

static V9V10TemplateElementId* dbPlugin_conf(void) {
  return(dbPlugin_template);
}

/* *********************************************** */

static PluginInfo dbPlugin = {
  NPROBE_REVISION,
  "MySQL DB",
  "0.1",
  "Save flows into a database",
  "L.Deri <deri@ntop.org>",
  0 /* always enabled */, 1, /* enabled */
  dbPlugin_init,
  NULL, /* Term */
  dbPlugin_conf,
  dbPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  dbPlugin_packet,
  dbPlugin_get_template,
  dbPlugin_export,
  dbPlugin_print,
  NULL,
  dbPlugin_help
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* dbPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&dbPlugin);
}

