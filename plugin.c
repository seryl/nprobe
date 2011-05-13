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

/* *********************************************** */

static u_short numDeleteFlowFctn, numPacketFlowFctn;
static PluginInfo *all_plugins[MAX_NUM_PLUGINS+1] = { NULL };
static uint num_plugins;
static PluginInfo *all_active_plugins[MAX_NUM_PLUGINS+1] = { NULL };
static uint num_active_plugins;

#ifdef MAKE_STATIC_PLUGINS
extern PluginInfo* sipPluginEntryFctn(void);
extern PluginInfo* rtpPluginEntryFctn(void);
extern PluginInfo* dumpPluginEntryFctn(void);
extern PluginInfo* dbPluginEntryFctn(void);
#ifdef WIN32
extern PluginInfo* processPluginEntryFctn(void);
#endif
extern PluginInfo* l7PluginEntryFctn(void);

/* extern PluginInfo* classIdPluginEntryFctn(void); */
extern PluginInfo* httpPluginEntryFctn(void);
extern PluginInfo* smtpPluginEntryFctn(void);
extern PluginInfo* mysqlPluginEntryFctn(void);
extern PluginInfo* bgpPluginEntryFctn(void);
#else
static char *pluginDirs[] = { "./plugins",
			      "/usr/local/lib/nprobe/plugins",
			      NULL };
#endif

/* *********************************************** */

static void loadPlugin(char *dirName, char *pluginName);

/* *********************************************** */

static int plugin_sanity_check(char *name, V9V10TemplateElementId *rc, 
			       char *ref_name, V9V10TemplateElementId *ref_template) {
  /* Sanity check */

  if(rc != NULL) {
    int j = 0;
    
    while(rc[j].templateElementId != 0) {
      /* Search the elementId among the standard fields */
      int k =0;
      
      while(ref_template[k].templateElementId != 0) {
	if(ref_template[k].templateElementId == rc[j].templateElementId) {
	  traceEvent(TRACE_ERROR, "FATAL ERROR: elementId clash [%s][%d][%s] that conflicts with [%s][%d][%s]",
		     name, rc[j].templateElementId, rc[j].templateElementDescr,
		     ref_name, ref_template[k].templateElementId, ref_template[k].templateElementDescr);
	  return(-1);
	} else
	  k++;
      }
      
      j++;
    }
  }

  return(0);
}

/* *********************************************** */

void initPlugins(int argc, char* argv[]) {
  int i;
#ifndef MAKE_STATIC_PLUGINS
  int idp = 0;
#ifndef WIN32
  char dirPath[256];
  struct dirent* dp;
  DIR* directoryPointer=NULL;
#endif
#endif

  /* ******************************** */

  /* Register plugins */
  num_plugins = num_active_plugins = 0;

#ifdef MAKE_STATIC_PLUGINS
#ifdef ENABLE_PLUGINS
  traceEvent(TRACE_INFO, "Initializing static plugins.");

  loadPlugin(NULL, "sipPlugin");
  loadPlugin(NULL, "rtpPlugin");
  loadPlugin(NULL, "httpPlugin");
  loadPlugin(NULL, "smtpPlugin");
  loadPlugin(NULL, "mysqlPlugin");
  loadPlugin(NULL, "bgpPlugin");

  loadPlugin(NULL, "dumpPlugin");
  loadPlugin(NULL, "dbPlugin");

#ifdef WIN32
  loadPlugin(NULL, "processPlugin");
#endif

#if defined(HAVE_PCRE_H) && defined(HAVE_LIBPCRE)
  loadPlugin(NULL, "l7Plugin");
#endif

  /* loadPlugin(NULL, "classIdPlugin"); */
#endif

#else /* MAKE_STATIC_PLUGINS */
  traceEvent(TRACE_INFO, "Loading plugins...");

  for(idp = 0; pluginDirs[idp] != NULL; idp++) {
    snprintf(dirPath, sizeof(dirPath), "%s", pluginDirs[idp]);
    directoryPointer = opendir(dirPath);

    if(directoryPointer != NULL)
      break;
    else
      traceEvent(TRACE_NORMAL, "No plugins found in %s", dirPath);
  }

  if(directoryPointer == NULL) {
    traceEvent(TRACE_WARNING, "Unable to find plugins directory. nProbe will work without plugins!");
  } else {
    traceEvent(TRACE_NORMAL, "Loading plugins [%s] from %s", PLUGIN_EXTENSION, dirPath);

    while((dp = readdir(directoryPointer)) != NULL) {
      char buf[256];
      struct stat st;

      if(dp->d_name[0] == '.')
	continue;
      else if((strstr(dp->d_name, "Plugin") == NULL)
	      || strcmp(&dp->d_name[strlen(dp->d_name)-strlen(PLUGIN_EXTENSION)], PLUGIN_EXTENSION))
	continue;

      /* Check if a plugin with version name exists: 
	 if so we ignore this plugin and load the other one */
      
      snprintf(buf, sizeof(buf), "%s/%s", dirPath, dp->d_name);
      buf[strlen(buf)-strlen(PLUGIN_EXTENSION)] = '\0';
      
      snprintf(&buf[strlen(buf)], sizeof(buf)-strlen(buf), "-%s%s",
	       version, PLUGIN_EXTENSION);
      
      if(stat(buf, &st) == 0) {
	traceEvent(TRACE_INFO, "Plugin %s also exists: skipping %s/%s", buf, dirPath, dp->d_name);
      } else
	loadPlugin(dirPath, dp->d_name);
    }

    closedir(directoryPointer);
  }

#endif /* MAKE_STATIC_PLUGINS */

  /* ******************************** */

  numDeleteFlowFctn = numPacketFlowFctn = 0;

  i = 0;
  while((i < MAX_NUM_PLUGINS) && (all_plugins[i] != NULL)) {
    if(all_plugins[i]->enabled || all_plugins[i]->always_enabled) {
      /* traceEvent(TRACE_INFO, "-> %s", all_plugins[i]->name); */
      if(all_plugins[i]->initFctn != NULL) all_plugins[i]->initFctn(argc, argv);
      if(all_plugins[i]->deleteFlowFctn != NULL) numDeleteFlowFctn++;
      if(all_plugins[i]->packetFlowFctn != NULL) numPacketFlowFctn++;
    }

    i++;
  }

  traceEvent(TRACE_INFO, "%d plugin(s) loaded [%d delete][%d packet].",
	     i, numDeleteFlowFctn, numPacketFlowFctn);
}

/* *********************************************** */

void termPlugins() {
  int i;

  traceEvent(TRACE_INFO, "Terminating plugins.");

  i = 0;
  while((i < MAX_NUM_PLUGINS) && (all_plugins[i] != NULL)) {
    if(all_plugins[i]->enabled && all_plugins[i]->termFctn) {
      traceEvent(TRACE_INFO, "Terminating %s", all_plugins[i]->name);
      all_plugins[i]->termFctn();
    }

    i++;
  }
}

/* *********************************************** */

void dumpPluginTemplates() {
  int i = 0;

  while(all_plugins[i] != NULL) {
    V9V10TemplateElementId *templates = all_plugins[i]->pluginFlowConf();

    if(templates && (templates[0].templateElementName != NULL)) {
     printf("\nPlugin %s templates:\n", all_plugins[i]->name);
     printTemplateInfo(templates, 0);
   }

    i++;
  }
}

/* *********************************************** */

void dumpPluginHelp() {
  int i = 0;

  while(all_plugins[i] != NULL) {
    if(all_plugins[i]->helpFctn) {
      printf("[%s]\n", all_plugins[i]->name);
      all_plugins[i]->helpFctn();
      printf("\n");
    }

    i++;
  }
}

/* *********************************************** */

void pluginCallback(u_char callbackType, FlowHashBucket* bkt,
		    FlowDirection direction,
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
		    u_char *payload, int payloadLen) {
  int i = 0;

  if(num_active_plugins == 0) return;

  switch(callbackType) {
  case CREATE_FLOW_CALLBACK:
    while(all_active_plugins[i] != NULL) {
      switch(callbackType) {
      case CREATE_FLOW_CALLBACK:
	if((all_active_plugins[i]->enabled)
	   && (all_active_plugins[i]->packetFlowFctn != NULL)) {
	  all_active_plugins[i]->packetFlowFctn(1 /* new flow */,
						NULL, bkt,
						direction,
						proto, isFragment,
						numPkts, tos,
						vlanId, ehdr,
						src, sport,
						dst, dport,
						len, flags, tcpSeqNum, icmpType,
						numMplsLabels,
						mplsLabels, 
						h, p, payload, payloadLen);
	}
	break;
      }
      
      i++;
    }
    break;

  case DELETE_FLOW_CALLBACK:
    if(bkt->plugin != NULL) {
      PluginInformation *plugin = bkt->plugin, *next;

      while(plugin != NULL) {
	if(plugin->pluginPtr->deleteFlowFctn != NULL) {
	  plugin->pluginPtr->deleteFlowFctn(bkt, plugin->pluginData);
	  next = plugin->next;
	  free(plugin);
	  bkt->plugin = next;
	  plugin = next;
	}
      }

      bkt->plugin = NULL;
    }
    break;

  case PACKET_CALLBACK:
    if(bkt->plugin != NULL) {
      PluginInformation *plugin = bkt->plugin;

      while(plugin != NULL) {
	if((plugin->pluginPtr->packetFlowFctn != NULL) 
	   && plugin->pluginPtr->call_packetFlowFctn_for_each_packet) {
	  plugin->pluginPtr->packetFlowFctn(0 /* existing flow */,
					    plugin->pluginData,
					    bkt, direction,
					    proto, isFragment,
					    numPkts, tos,
					    vlanId, ehdr,
					    src, sport,
					    dst, dport,
					    len, flags, tcpSeqNum, icmpType,
					    numMplsLabels,
					    mplsLabels, 
					    h, p, payload, payloadLen);
	}

	plugin = plugin->next;
      }
    }
    break;

  default:
    return; /* Unknown callback */
  }
}

/* *********************************************** */

V9V10TemplateElementId* getPluginTemplate(char* template_name) {
  int i=0;

  while(all_plugins[i] != NULL) {
    if(all_plugins[i]->getPluginTemplateFctn != NULL) {
      V9V10TemplateElementId *rc = all_plugins[i]->getPluginTemplateFctn(template_name);

      if(rc != NULL) return(rc);
    }

    i++;
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

int checkPluginExport(V9V10TemplateElementId *theTemplate, /* Template being export */
		      FlowDirection direction,             /* 0 = src->dst, 1 = dst->src   */
		      FlowHashBucket *bkt,       /* The flow bucket being export */
		      char *outBuffer,           /* Buffer where data will be exported */
		      uint *outBufferBegin,      /* Index of the slot (0..outBufferMax) where data will be insert */
		      uint *outBufferMax         /* Length of outBuffer */
		      ) {
  if(bkt->plugin != NULL) {
    PluginInformation *plugin = bkt->plugin;

    while(plugin != NULL) {
      if(plugin->pluginPtr->checkPluginExportFctn != NULL) {
	int rc = plugin->pluginPtr->checkPluginExportFctn(plugin->pluginData, theTemplate, direction, bkt,
							  outBuffer, outBufferBegin, outBufferMax);

	if(rc == 0) return(0);
      }

      plugin = plugin->next;
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

int checkPluginPrint(V9V10TemplateElementId *theTemplate, 
		     FlowDirection direction,
		     FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  if(bkt->plugin != NULL) {
    PluginInformation *plugin = bkt->plugin;

    while(plugin != NULL) {
      if(plugin->pluginPtr->checkPluginPrintFctn != NULL) {
	int rc = plugin->pluginPtr->checkPluginPrintFctn(plugin->pluginData, theTemplate,
							 direction, bkt, line_buffer, line_buffer_len);
	if(rc == 0) return(0);
      }

      plugin = plugin->next;
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static void loadPlugin(char *dirName, char *pluginName) {
  char pluginPath[256];
  PluginInfo* pluginInfo;
#ifndef MAKE_STATIC_PLUGINS
#ifndef WIN32
  void *pluginPtr = NULL;
  void *pluginEntryFctnPtr;
  PluginInfo* (*pluginJumpFunc)(void);
#endif
#endif    
  int i;

  snprintf(pluginPath, sizeof(pluginPath), "%s/%s", dirName != NULL ? dirName : ".", pluginName);

#ifndef MAKE_STATIC_PLUGINS
  pluginPtr = (void*)dlopen(pluginPath, RTLD_NOW /* RTLD_LAZY */); /* Load the library */

  if(pluginPtr == NULL) {
    traceEvent(TRACE_WARNING, "Unable to load plugin '%s'", pluginPath);
    traceEvent(TRACE_WARNING, "Message is '%s'", dlerror());
    return;
  } else
    traceEvent(TRACE_INFO, "Loaded '%s'", pluginPath);

  pluginEntryFctnPtr = (void*)dlsym(pluginPtr, "PluginEntryFctn");

  if(pluginEntryFctnPtr == NULL) {
#ifdef WIN32
    traceEvent(TRACE_WARNING, "Unable to locate plugin '%s' entry function [%li]",
	       pluginPath, GetLastError());
#else
    traceEvent(TRACE_WARNING, "Unable to locate plugin '%s' entry function [%s]",
	       pluginPath, dlerror());
#endif /* WIN32 */
    return;
  }

  pluginJumpFunc = (PluginInfo*(*)(void))pluginEntryFctnPtr;
  pluginInfo = pluginJumpFunc();
#else /* MAKE_STATIC_PLUGINS */

  if(strcmp(pluginName, "sipPlugin") == 0)
    pluginInfo = sipPluginEntryFctn();
  else if(strcmp(pluginName, "rtpPlugin") == 0)
    pluginInfo = rtpPluginEntryFctn();
  else if(strcmp(pluginName, "dumpPlugin") == 0)
    pluginInfo = dumpPluginEntryFctn();
  else if(strcmp(pluginName, "httpPlugin") == 0)
    pluginInfo = httpPluginEntryFctn();
  else if(strcmp(pluginName, "smtpPlugin") == 0)
    pluginInfo = smtpPluginEntryFctn();
  else if(strcmp(pluginName, "dbPlugin") == 0)
    pluginInfo = dbPluginEntryFctn();
 else if(strcmp(pluginName, "bgpPlugin") == 0)
    pluginInfo = bgpPluginEntryFctn();
 else if(strcmp(pluginName, "mysqlPlugin") == 0)
    pluginInfo = mysqlPluginEntryFctn();
#ifdef WIN32
  else if(strcmp(pluginName, "processPlugin") == 0)
    pluginInfo = processPluginEntryFctn();
#endif
  else {
    pluginInfo = NULL;
    traceEvent(TRACE_WARNING, "Missing entrypoint for plugin '%s'", pluginName);
  }

#endif /* MAKE_STATIC_PLUGINS */
  
  if(pluginInfo != NULL) {
    if(strcmp(pluginInfo->nprobe_revision, nprobe_revision)) {
      traceEvent(TRACE_WARNING, "Plugin %s (%s/%s) version mismatch [loaded=%s][expected=%s]: discarded",
		 pluginInfo->name, dirName, pluginName,
		 pluginInfo->nprobe_revision, nprobe_revision);
      return;
    }

    if(plugin_sanity_check(pluginInfo->name, pluginInfo->pluginFlowConf(), 
			   "standard templates", ver9_templates) == -1) {
      traceEvent(TRACE_WARNING, "Plugin %s/%s will be ignored", dirName, pluginName);
    } else {    
      int rc = 0;
      
      for(i=0; i<num_plugins; i++) {
	rc = plugin_sanity_check(pluginInfo->name, pluginInfo->pluginFlowConf(), 
				 all_plugins[i]->name, all_plugins[i]->pluginFlowConf());
	if(rc != 0) break;
      }

      if(rc == 0) {
	if(pluginInfo != NULL)
	  all_plugins[num_plugins++] = pluginInfo; /* FIX : add PluginInfo to the list */
      } else {
	traceEvent(TRACE_WARNING, "Plugin %s/%s will be ignored", dirName, pluginName);
      }
    }
  }
}

/* *************************** */

void enablePlugins() {
  int i = 0, found = 0;

  while(all_plugins[i] != NULL) {
    if((readOnlyGlobals.stringTemplateV4 == NULL) 
       && (readOnlyGlobals.flowDumpFormat == NULL))
      found = 0;
    else {
      if(all_plugins[i]->enabled && (!all_plugins[i]->always_enabled)) {
	V9V10TemplateElementId *templates = all_plugins[i]->pluginFlowConf();

	found = 0;

	if(templates && (templates[0].templateElementName != NULL)) {
	  int j = 0;

	  while(templates[j].templateElementName != NULL) {
	    if((readOnlyGlobals.stringTemplateV4 && (strstr(readOnlyGlobals.stringTemplateV4, templates[j].templateElementName)))
	       || (readOnlyGlobals.flowDumpFormat && strstr(readOnlyGlobals.flowDumpFormat, templates[j].templateElementName))) {
	      found = 1;
	      break;
	    }

	    j++;
	  }
	}
      }
    }

    if((!found) 
       && (!all_plugins[i]->always_enabled)) {
      traceEvent(TRACE_INFO, "Disabling plugin %s (no template is using it)",
		 all_plugins[i]->name);
      all_plugins[i]->enabled = 0;
    } else {
      traceEvent(TRACE_NORMAL, "Enabling plugin %s", all_plugins[i]->name);
      all_plugins[i]->enabled = 1;
   }

    i++;
  }
}

/* *************************** */

void setupPlugins() {
  int i = 0;

  while(all_plugins[i] != NULL) {
    if(all_plugins[i]->enabled 
       && (all_plugins[i]->setupFctn != NULL)) {
      all_plugins[i]->setupFctn();
    }
    i++;
  }
}

/* *************************** */

void buildActivePluginsList(V9V10TemplateElementId *template_element_list[]) {
  int plugin_idx = 0;
  num_active_plugins = 0;

  while(all_plugins[plugin_idx] != NULL) {
    u_int8_t is_http = 0, is_dns = 0, is_mysql = 0;

    traceEvent(TRACE_INFO, "Scanning plugin %s", all_plugins[plugin_idx]->name);

    if(strcasestr(all_plugins[plugin_idx]->name, "http")) {
      is_http = 1;
      if(readOnlyGlobals.enableHttpPlugin)
	all_plugins[plugin_idx]->always_enabled = 1;
    }
    
    if(strcasestr(all_plugins[plugin_idx]->name, "dns")) {
      is_dns = 1;
      if(readOnlyGlobals.enableDnsPlugin)
	all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(all_plugins[plugin_idx]->name, "mysql")) {
      is_mysql = 1;
      if(readOnlyGlobals.enableMySQLPlugin)
	all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(all_plugins[plugin_idx]->always_enabled) {
      all_active_plugins[num_active_plugins++] = all_plugins[plugin_idx];
    } else if(all_plugins[plugin_idx]->getPluginTemplateFctn != NULL) {
      int j;

      j = 0;
      while(template_element_list[j] != NULL) {
	if(all_plugins[plugin_idx]->getPluginTemplateFctn(template_element_list[j]->templateElementName)) {
	  all_active_plugins[num_active_plugins++] = all_plugins[plugin_idx];

	  if(is_dns) readOnlyGlobals.enableDnsPlugin = 1;
	  else if(is_http)  readOnlyGlobals.enableHttpPlugin = 1;
	  else if(is_mysql) readOnlyGlobals.enableMySQLPlugin = 1;
	  traceEvent(TRACE_INFO, "Enabling plugin %s", all_plugins[plugin_idx]->name);
	  break;
	}

	j++;
      }
    }

    plugin_idx++;
  }

  all_active_plugins[num_active_plugins] = NULL;
  traceEvent(TRACE_NORMAL, "%d plugin(s) enabled", num_active_plugins);
}

/* ******************************************** */

char* dumpformat2ascii(ElementDumpFormat fileDumpFormat) {
  switch(fileDumpFormat) {
  case dump_as_uint:           return("uint");
  case dump_as_formatted_uint: return("formatted_uint");
  case dump_as_ip_port:        return("ip_port");
  case dump_as_ip_proto:       return("ip_proto");
  case dump_as_ipv4_address:   return("ipv4_address");
  case dump_as_ipv6_address:   return("ipv6_address");
  case dump_as_mac_address:    return("mac_address");
  case dump_as_epoch:          return("epoch");
  case dump_as_bool:           return("bool");
  case dump_as_tcp_flags:      return("tcp_flags");
  case dump_as_hex:            return("hex");
  case dump_as_ascii:          return("ascii");
  default:                     return("hex"); /* It should not happen ! */
  } 
}

/* ******************************************** */

static void printTemplateMetadata(FILE *file, V9V10TemplateElementId *templates) {
  int j = 0;

  while(templates[j].templateElementName != NULL) {
    if((!templates[j].isOptionTemplate)
       && (templates[j].templateElementId < 0xA0))
      fprintf(file, "%s\t%d\t%s\t%s\n",
	      templates[j].templateElementName,
	      templates[j].templateElementId,
	      dumpformat2ascii(templates[j].fileDumpFormat),
	      templates[j].templateElementDescr);
    j++;
  }
}

/* ******************************************** */

void printMetadata(FILE *file) {
  int i = 0;
  time_t now = time(NULL);

  fprintf(file,
	  "#\n"
	  "# Generated by nprobe v.%s (%s) for %s\n"
	  "# on %s"
	  "#\n",
	  version, nprobe_revision, osName,
	  ctime(&now));

  fprintf(file, 
	  "#\n"
	  "# Name\tId\tFormat\tDescription\n"
	  "#\n"
	  "# Known format values\n"
	  );

  fprintf(file, "#\t%s\n", "uint (e.g. 1234567890)");
  fprintf(file, "#\t%s\n", "formatted_uint (e.g. 123'456)");
  fprintf(file, "#\t%s\n", "ip_port (e.g. http)");
  fprintf(file, "#\t%s\n", "ip_proto (e.g. tcp)");
  fprintf(file, "#\t%s\n", "ipv4_address (e.g. 1.2.3.4)");
  fprintf(file, "#\t%s\n", "ipv6_address (e.g. fe80::21c:42ff:fe00:8)");
  fprintf(file, "#\t%s\n", "mac_address (e.g. 00:1c:42:00:00:08)");
  fprintf(file, "#\t%s\n", "epoch (e.g. Tue Sep 29 14:05:11 2009)");
  fprintf(file, "#\t%s\n", "bool (e.g. true)");
  fprintf(file, "#\t%s\n", "tcp_flags (e.g. SYN|ACK)");
  fprintf(file, "#\t%s\n", "hex (e.g. 00 11 22 33)");
  fprintf(file, "#\t%s\n", "ascii (e.g. abcd)");
  fprintf(file, "#\n");

  printTemplateMetadata(file, ver9_templates);

  while(all_plugins[i] != NULL) {
    V9V10TemplateElementId *templates = all_plugins[i]->pluginFlowConf();

    if(templates && (templates[0].templateElementName != NULL))
      printTemplateMetadata(file, templates);
    
    i++;
  }
}

