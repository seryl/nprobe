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

#ifdef HAVE_PLUGIN_LICENSE
#include "private/license/license.h"
#endif

/* *********************************************** */


#ifdef MAKE_STATIC_PLUGINS
extern PluginEntryPoint* sipPluginEntryFctn(void);
extern PluginEntryPoint* rtpPluginEntryFctn(void);
extern PluginEntryPoint* dbPluginEntryFctn(void);
#ifdef WIN32
extern PluginEntryPoint* processPluginEntryFctn(void);
#endif
extern PluginEntryPoint* l7BridgePluginEntryFctn(void);
extern PluginEntryPoint* gtpv0PluginEntryFctn(void);
extern PluginEntryPoint* gtpv1PluginEntryFctn(void);
extern PluginEntryPoint* gtpv2PluginEntryFctn(void);
extern PluginEntryPoint* radiusPluginEntryFctn(void);
extern PluginEntryPoint* oraclePluginEntryFctn(void);
extern PluginEntryPoint* httpPluginEntryFctn(void);
extern PluginEntryPoint* smtpPluginEntryFctn(void);
extern PluginEntryPoint* mysqlPluginEntryFctn(void);
extern PluginEntryPoint* bgpPluginEntryFctn(void);
extern PluginEntryPoint* dnsPluginEntryFctn(void);
extern PluginEntryPoint* nflitePluginEntryFctn(void);
extern PluginEntryPoint* radiusPluginEntryFctn(void);
extern PluginEntryPoint* dhcpPluginEntryFctn(void);
#else

#define PLUGIN_DIR_LOCAL "./plugins"
#define PLUGIN_DIR_SYSTEM PREFIX "/lib/nprobe/plugins"

static char *pluginDirs[] = { PLUGIN_DIR_LOCAL,
			      PLUGIN_DIR_SYSTEM,
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

void loadPlugins() {
  static u_int8_t done = 0;
#ifndef MAKE_STATIC_PLUGINS
  int idp = 0;
#ifndef WIN32
  char dirPath[256];
  struct dirent* dp;
  DIR* directoryPointer=NULL;
#endif
#endif

  if(done) return; else done++;

  /* ******************************** */

  /* Register plugins */
  readOnlyGlobals.num_plugins = readOnlyGlobals.num_active_plugins = 0;

#ifdef MAKE_STATIC_PLUGINS
#ifdef ENABLE_PLUGINS
  traceEvent(TRACE_INFO, "Initializing static plugins...");

#ifndef USE_SPARROW
  loadPlugin(NULL, "sipPlugin");
  loadPlugin(NULL, "rtpPlugin");
  loadPlugin(NULL, "httpPlugin");
  loadPlugin(NULL, "smtpPlugin");
  loadPlugin(NULL, "bgpPlugin");
  loadPlugin(NULL, "nflitePlugin");
  loadPlugin(NULL, "dnsPlugin");
  loadPlugin(NULL, "oraclePlugin");
  loadPlugin(NULL, "gtpv0Plugin");
  loadPlugin(NULL, "gtpv1Plugin");
  loadPlugin(NULL, "gtpv2Plugin");
  loadPlugin(NULL, "radiusPlugin");
  loadPlugin(NULL, "dhcpPlugin");
#ifndef WIN32
  /* Win32-only plugins */
  loadPlugin(NULL, "processPlugin");
#endif
 #endif

  loadPlugin(NULL, "dbPlugin");
  loadPlugin(NULL, "mysqlPlugin");

#ifdef HAVE_PF_RING
  loadPlugin(NULL, "l7BridgePlugin");
#endif

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

      /*
	Check if a plugin with version name exists:
	if so we ignore this plugin and load the other one
      */

      snprintf(buf, sizeof(buf), "%s/%s", dirPath, dp->d_name);
      buf[strlen(buf)-strlen(PLUGIN_EXTENSION)] = '\0';

      snprintf(&buf[strlen(buf)], sizeof(buf)-strlen(buf), "-%s%s",
	       version, PLUGIN_EXTENSION);

      if(stat(buf, &st) == 0) {
	traceEvent(TRACE_INFO, "Plugin %s also exists: skipping %s/%s",
		   buf, dirPath, dp->d_name);
      } else
	loadPlugin(dirPath, dp->d_name);
    }

    closedir(directoryPointer);
  }

#endif /* MAKE_STATIC_PLUGINS */
}

/* *********************************************** */

PluginEntryPoint* get_plugin_info(char *short_name) {
  int i = 0;

  while((i < MAX_NUM_PLUGINS) && (readOnlyGlobals.all_plugins[i] != NULL)) {
    if(readOnlyGlobals.all_plugins[i]->enabled || readOnlyGlobals.all_plugins[i]->always_enabled) { 
      if(strcmp(readOnlyGlobals.all_plugins[i]->short_name, short_name) == 0) {
	return(readOnlyGlobals.all_plugins[i]);
      }
    }

    i++;
  }
  
  return(NULL);
}

/* *********************************************** */

void initPlugins() {
  int i;

  loadPlugins();

  readOnlyGlobals.numDeleteFlowFctn = readOnlyGlobals.numPacketFlowFctn = 0;

  i = 0;
  while((i < MAX_NUM_PLUGINS) && (readOnlyGlobals.all_plugins[i] != NULL)) {
    if(readOnlyGlobals.all_plugins[i]->enabled || readOnlyGlobals.all_plugins[i]->always_enabled) {
      /* traceEvent(TRACE_INFO, "-> %s", readOnlyGlobals.all_plugins[i]->name); */
      if(readOnlyGlobals.all_plugins[i]->initFctn != NULL) readOnlyGlobals.all_plugins[i]->initFctn(readOnlyGlobals.argc, readOnlyGlobals.argv);
      if(readOnlyGlobals.all_plugins[i]->deleteFlowFctn != NULL) readOnlyGlobals.numDeleteFlowFctn++;
      if(readOnlyGlobals.all_plugins[i]->packetFlowFctn != NULL) readOnlyGlobals.numPacketFlowFctn++;
    }

    i++;
  }

  traceEvent(TRACE_INFO, "%d plugin(s) loaded [%d delete][%d packet].",
	     i, readOnlyGlobals.numDeleteFlowFctn,
	     readOnlyGlobals.numPacketFlowFctn);
}

/* *********************************************** */

static void unloadPlugins() {
#ifndef WIN32
	int i = 0;

  while(readOnlyGlobals.pluginDlopenHandle[i] != NULL) {
    dlclose(readOnlyGlobals.pluginDlopenHandle[i]);
    i++;
  }
#endif
}

/* *********************************************** */

const struct option* buildCLIOptions() {
  return(NULL);
}

/* *********************************************** */

void termPlugins() {
  int i;

  traceEvent(TRACE_INFO, "Terminating plugins.");

  i = 0;
  while((i < MAX_NUM_PLUGINS) && (readOnlyGlobals.all_plugins[i] != NULL)) {
    if(readOnlyGlobals.all_plugins[i]->enabled && readOnlyGlobals.all_plugins[i]->termFctn) {
      traceEvent(TRACE_INFO, "Terminating %s", readOnlyGlobals.all_plugins[i]->name);
      readOnlyGlobals.all_plugins[i]->termFctn();
    }

    i++;
  }

  unloadPlugins();
}

/* *********************************************** */

void dumpPluginStats(u_int timeDifference) {
  int i = 0;

  while((i < MAX_NUM_PLUGINS) && (readOnlyGlobals.all_plugins[i] != NULL)) {
    if(readOnlyGlobals.all_plugins[i]->enabled && readOnlyGlobals.all_plugins[i]->pluginStatsFctn) {
      readOnlyGlobals.all_plugins[i]->pluginStatsFctn();
    }

    i++;
  }
}

/* *********************************************** */

void dumpPluginTemplates() {
  int i = 0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    V9V10TemplateElementId *templates = readOnlyGlobals.all_plugins[i]->pluginFlowConf();

    if(templates && (templates[0].netflowElementName != NULL)) {
     printf("\nPlugin %s templates:\n", readOnlyGlobals.all_plugins[i]->name);
     printTemplateInfo(templates, 0);
   }

    i++;
  }
}

/* *********************************************** */

void dumpPluginHelp() {
  int i = 0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    if(readOnlyGlobals.all_plugins[i]->helpFctn) {
      printf("[%s]\n", readOnlyGlobals.all_plugins[i]->name);
      readOnlyGlobals.all_plugins[i]->helpFctn();
      printf("\n");
    }

    i++;
  }
}

/* *********************************************** */

void dumpPluginFamilies() {
  int i = 0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    printf("%s\t%s\n",
	   readOnlyGlobals.all_plugins[i]->family ? readOnlyGlobals.all_plugins[i]->family : readOnlyGlobals.all_plugins[i]->short_name,
	   readOnlyGlobals.all_plugins[i]->name
	   );
    i++;
  }
}

/* *********************************************** */

void pluginCallback(u_char callbackType,
		    int packet_if_idx /* -1 = unknown */,
		    FlowHashBucket* bkt,
		    FlowDirection direction,
		    u_int16_t ip_offset, u_short proto, u_char isFragment,
		    u_short numPkts, u_char tos,
		    u_int8_t retransmitted_pkt,
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

  if(readOnlyGlobals.num_active_plugins == 0) return;

  switch(callbackType) {
  case CREATE_FLOW_CALLBACK:
    while(readOnlyGlobals.all_active_plugins[i] != NULL) {
      if((readOnlyGlobals.all_active_plugins[i]->enabled)
	 && (readOnlyGlobals.all_active_plugins[i]->packetFlowFctn != NULL)) {
	readOnlyGlobals.all_active_plugins[i]->packetFlowFctn(1 /* new flow */,
							      packet_if_idx,
							      NULL, bkt,
							      direction,
							      ip_offset, proto, isFragment,
							      numPkts, tos, retransmitted_pkt,
							      vlanId, ehdr,
							      src, sport,
							      dst, dport,
							      len, flags, tcpSeqNum, icmpType,
							      numMplsLabels,
							      mplsLabels,
							      h, p, payload, payloadLen);
      }

      i++;
    }
    break;

  case DELETE_FLOW_CALLBACK:
    if(bkt->ext && bkt->ext->plugin) {
      PluginInformation *plugin = bkt->ext->plugin, *next;

      while(plugin != NULL) {
	if(plugin->pluginPtr == NULL)
	  break;
	else if(plugin->pluginPtr->deleteFlowFctn != NULL) {
	  plugin->pluginPtr->deleteFlowFctn(bkt, plugin->pluginData);
	  next = plugin->next;
	  free(plugin);
	  bkt->ext->plugin = next;
	  plugin = next;
	} else
	  plugin = plugin->next;
      }

      bkt->ext->plugin = NULL;
    }
    break;

  case PACKET_CALLBACK:
    if(bkt->ext && bkt->ext->plugin) {
      PluginInformation *plugin = bkt->ext->plugin;

      while(plugin != NULL) {
	if(plugin->pluginPtr == NULL)
	  break;
	else if((plugin->plugin_used == 1)
		&& (plugin->pluginPtr->packetFlowFctn != NULL)
		&& plugin->pluginPtr->call_packetFlowFctn_for_each_packet) {
	  plugin->pluginPtr->packetFlowFctn(0 /* existing flow */,
					    packet_if_idx,
					    plugin->pluginData,
					    bkt, direction,
					    ip_offset, proto, isFragment,
					    numPkts, tos, retransmitted_pkt,
					    vlanId, ehdr,
					    src, sport,
					    dst, dport,
					    len, flags, tcpSeqNum, icmpType,
					    numMplsLabels,
					    mplsLabels,
					    h, p, payload, payloadLen);
	}

	/*
	  We stop as soon as we have found a plugin that matches this flow

	  Remove the statement below for having multi-plugin matching
	 */
	if(bkt->ext->plugin != NULL)
	  break;

	plugin = plugin->next;
      }
    }
    break;

  default:
    return; /* Unknown callback */
  }
}

/* *********************************************** */

V9V10TemplateElementId* getPluginTemplate(char* template_name, PluginEntryPoint **plugin) {
  int i=0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    if(readOnlyGlobals.all_plugins[i]->getTemplateFctn != NULL) {
      V9V10TemplateElementId *rc = readOnlyGlobals.all_plugins[i]->getTemplateFctn(template_name);

      if(rc != NULL) {
	*plugin = readOnlyGlobals.all_plugins[i];
	return(rc);
      }
    }

    i++;
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

char* expandPluginTemplate(char** template_name) {
  int i=0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    if(readOnlyGlobals.all_plugins[i]->templateShortcut != NULL) {
      char *rc = readOnlyGlobals.all_plugins[i]->templateShortcut(*template_name);

      if(rc != NULL) {
	*template_name = rc;
	return(rc);
      }
    }

    i++;
  }

  return(*template_name);
}

/* *********************************************** */

int checkPluginExport(V9V10TemplateElementId *theTemplate, /* Template being export */
		      FlowDirection direction,             /* 0 = src->dst, 1 = dst->src   */
		      FlowHashBucket *bkt,       /* The flow bucket being export */
		      char *outBuffer,           /* Buffer where data will be exported */
		      uint *outBufferBegin,      /* Index of the slot (0..outBufferMax) where data will be insert */
		      uint *outBufferMax         /* Length of outBuffer */) {
  if(bkt->ext && bkt->ext->plugin) {
    PluginInformation *plugin = bkt->ext->plugin;

    while(plugin != NULL) {
      if(plugin->pluginPtr == NULL)
	break;
      else if(plugin->pluginPtr->pluginExportFctn != NULL) {
	int rc = plugin->pluginPtr->pluginExportFctn(plugin->pluginData, theTemplate, direction, bkt,
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
		     FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len,
		     u_int8_t json_mode) {
  if(bkt->ext->plugin != NULL) {
    PluginInformation *plugin = bkt->ext->plugin;

    while(plugin != NULL) {
      if(plugin->pluginPtr == NULL)
	break;
      else if(plugin->pluginPtr->pluginPrintFctn != NULL) {
	u_int8_t is_string = 0;
	int rc = plugin->pluginPtr->pluginPrintFctn(plugin->pluginData, theTemplate,
						    direction, bkt,
						    line_buffer, line_buffer_len,
						    json_mode, &is_string);

	if(rc >= 0) {
	  if(json_mode && is_string) {
	    /* We need to escape the value */
	    char out_buffer[1024];
	    int i, out = 0;

	    if(line_buffer[0] != '\"') out_buffer[out++] = '"';

	    for(i=0; i<rc; i++) {
	      if(line_buffer[i] == '"') {
		out_buffer[out++] = '\\';
		out_buffer[out++] = '"';
	      } else
		out_buffer[out++] = line_buffer[i];
	    }

	    if(line_buffer[0] != '\"') out_buffer[out++] = '"';
	    out_buffer[out] = '\0';

	    rc = snprintf(line_buffer, line_buffer_len, "%s", out_buffer);
	  }
	  return(rc);
	}
      }

      plugin = plugin->next;
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static void loadPlugin(char *dirName, char *pluginName) {
  char pluginPath[256];
  PluginEntryPoint* pluginInfo;
#ifndef MAKE_STATIC_PLUGINS
#ifndef WIN32
  void *pluginPtr = NULL;
  void *pluginEntryFctnPtr;
  PluginEntryPoint* (*pluginJumpFunc)(void);
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

  pluginJumpFunc = (PluginEntryPoint*(*)(void))pluginEntryFctnPtr;
  pluginInfo = pluginJumpFunc();
#else /* MAKE_STATIC_PLUGINS */
  if(strcmp(pluginName, "sipPlugin") == 0)
    pluginInfo = sipPluginEntryFctn();
  else if(strcmp(pluginName, "rtpPlugin") == 0)
    pluginInfo = rtpPluginEntryFctn();
  else if(strcmp(pluginName, "httpPlugin") == 0)
    pluginInfo = httpPluginEntryFctn();
  else if(strcmp(pluginName, "smtpPlugin") == 0)
    pluginInfo = smtpPluginEntryFctn();
  else if(strcmp(pluginName, "dbPlugin") == 0)
    pluginInfo = dbPluginEntryFctn();
  else if(strcmp(pluginName, "bgpPlugin") == 0)
    pluginInfo = bgpPluginEntryFctn();
  else if(strcmp(pluginName, "nflitePlugin") == 0)
    pluginInfo = nflitePluginEntryFctn();
  else if(strcmp(pluginName, "dnsPlugin") == 0)
    pluginInfo = dnsPluginEntryFctn();
  else if(strcmp(pluginName, "mysqlPlugin") == 0)
    pluginInfo = mysqlPluginEntryFctn();
  else if(strcmp(pluginName, "gtpv0Plugin") == 0)
    pluginInfo = gtpv0PluginEntryFctn();
  else if(strcmp(pluginName, "gtpv1Plugin") == 0)
    pluginInfo = gtpv1PluginEntryFctn();
  else if(strcmp(pluginName, "gtpv2Plugin") == 0)
    pluginInfo = gtpv2PluginEntryFctn();
  else if(strcmp(pluginName, "radiusPlugin") == 0)
    pluginInfo = radiusPluginEntryFctn();
  else if(strcmp(pluginName, "dhcpPlugin") == 0)
    pluginInfo = dhcpPluginEntryFctn();
  else if(strcmp(pluginName, "oraclePlugin") == 0)
    pluginInfo = oraclePluginEntryFctn();
#ifdef HAVE_PF_RING
  else if(strcmp(pluginName, "l7BridgePlugin") == 0)
    pluginInfo = l7BridgePluginEntryFctn();
#endif
#ifndef WIN32
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
      traceEvent(TRACE_WARNING, "Plugin %s (%s/%s) version mismatch [loaded=%s][expected=%s]: %s",
		 pluginInfo->name, dirName, pluginName,
		 pluginInfo->nprobe_revision, nprobe_revision,
		 readOnlyGlobals.ignore_plugin_revision_mismatch ? "ignored" : "discarded");
      if(!readOnlyGlobals.ignore_plugin_revision_mismatch)
        return;
    }

    if(plugin_sanity_check(pluginInfo->name, pluginInfo->pluginFlowConf(),
			   "standard templates", ver9_templates) == -1) {
      traceEvent(TRACE_WARNING, "Plugin %s/%s will be ignored", dirName, pluginName);
    } else {
      int rc = 0;

      for(i=0; i<readOnlyGlobals.num_plugins; i++) {
	rc = plugin_sanity_check(pluginInfo->name, pluginInfo->pluginFlowConf(),
				 readOnlyGlobals.all_plugins[i]->name,
				 readOnlyGlobals.all_plugins[i]->pluginFlowConf());
	if(rc != 0) break;
      }


      if(rc == 0) {
#if defined(HAVE_PLUGIN_LICENSE)
        if((!readOnlyGlobals.demo_mode) && (!readOnlyGlobals.help_mode)) {
          if(pluginInfo->need_license == PLUGIN_NEED_LICENSE) {
            char out_buf[512], license_path[256], *sysId = getSystemId();
            time_t until_then;

	    pluginInfo->pro_version = 0; /* Default */

            snprintf(license_path, sizeof(license_path), "%s%s.%s",
#ifndef WIN32
                     "/etc/",
#else
                     "",
#endif
                     LICENSE_FILE_NAME,
                     pluginInfo->family ? pluginInfo->family : pluginInfo->short_name);

            if(verify_license(version, pluginInfo->family ? pluginInfo->family : pluginInfo->short_name,
                              sysId, license_path, 5, out_buf, sizeof(out_buf), &until_then) != 0) {
	      /* Last resort: let's check the pro version */

	      if(pluginInfo->pro_family) {
		snprintf(license_path, sizeof(license_path), "%s%s.%s",
#ifndef WIN32
			 "/etc/",
#else
			 "",
#endif
			 LICENSE_FILE_NAME, pluginInfo->pro_family);

		if(verify_license(version, pluginInfo->pro_family,
				  sysId, license_path, 5, out_buf, sizeof(out_buf), &until_then) != 0) {
		  goto no_plugin_license;		  
		} else
		  pluginInfo->pro_version = 1;
	      } else {
	      no_plugin_license:
		traceEvent(TRACE_NORMAL, "Unable to enable plugin %s: missing license [%s]",
			   pluginInfo->name, license_path);
		pluginInfo = NULL;
	      }
            }

            free(sysId);
          }
        }
#endif /* HAVE_PLUGIN_LICENSE */

        if(pluginInfo != NULL) {
#if !defined(WIN32) && !defined(MAKE_STATIC_PLUGINS)
          readOnlyGlobals.pluginDlopenHandle[readOnlyGlobals.num_plugins] = pluginPtr;
#endif
          readOnlyGlobals.all_plugins[readOnlyGlobals.num_plugins] = pluginInfo; /* FIX : add PluginEntryPoint to the list */
          readOnlyGlobals.num_plugins++;
        }
      } else {
        traceEvent(TRACE_WARNING, "Plugin %s/%s will be ignored", dirName, pluginName);
      }
    }
  }
}

/* *************************** */

void enablePlugins() {
  int i = 0, found = 0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    if((readOnlyGlobals.stringTemplateV4 == NULL)
       && (readOnlyGlobals.flowDumpFormat == NULL))
      found = 0;
    else {
      if(readOnlyGlobals.all_plugins[i]->enabled && (!readOnlyGlobals.all_plugins[i]->always_enabled)) {
	V9V10TemplateElementId *templates = readOnlyGlobals.all_plugins[i]->pluginFlowConf();

	found = 0;

	if(templates && (templates[0].netflowElementName != NULL)) {
	  int j = 0;

#if 0
	  if(unlikely(readOnlyGlobals.enable_debug)) {
	    for(j=0; templates[j].netflowElementName != NULL; j++)
	      traceEvent(TRACE_NORMAL, "%s", templates[j].netflowElementName);

	    j = 0;
	  }
#endif

	  while(templates[j].netflowElementName != NULL) {
	    if((!templates[j].isOptionTemplate)
	       && (readOnlyGlobals.baseTemplateBufferV4
		   && (((strstr(readOnlyGlobals.baseTemplateBufferV4, templates[j].netflowElementName) != NULL)
		       || ((templates[j].ipfixElementName[0] != '\0') && strstr(readOnlyGlobals.baseTemplateBufferV4, templates[j].ipfixElementName)))
		       || (readOnlyGlobals.flowDumpFormat && (strstr(readOnlyGlobals.flowDumpFormat, templates[j].netflowElementName)
							      || ((templates[j].ipfixElementName[0] != '\0') && strstr(readOnlyGlobals.flowDumpFormat, templates[j].ipfixElementName))))))) {
	      found = 1;
	      break;
	    }

	    j++;
	  }
	}
      }
    }

    if((!found)
       && (!readOnlyGlobals.all_plugins[i]->always_enabled)) {
      traceEvent(TRACE_INFO, "Disabling plugin %s (no template is using it)",
		 readOnlyGlobals.all_plugins[i]->name);
      readOnlyGlobals.all_plugins[i]->enabled = 0;
    } else {
      traceEvent(TRACE_NORMAL, "Enabling plugin %s", readOnlyGlobals.all_plugins[i]->name);
      readOnlyGlobals.all_plugins[i]->enabled = 1;
    }

    i++;
  }
}

/* *************************** */

void setupPlugins() {
  int i = 0;

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    if(readOnlyGlobals.all_plugins[i]->enabled
       && (readOnlyGlobals.all_plugins[i]->setupFctn != NULL)) {
      readOnlyGlobals.all_plugins[i]->setupFctn();
    }
    i++;
  }
}

/* *************************** */

void buildActivePluginsList(V9V10TemplateElementId *template_element_list[]) {
  int plugin_idx = 0;
  readOnlyGlobals.num_active_plugins = 0;

  while(readOnlyGlobals.all_plugins[plugin_idx] != NULL) {
    u_int8_t is_http = 0, is_dns = 0, is_mysql = 0, is_sip = 0, is_oracle = 0,
      is_gtp = 0, is_l7 = 0, is_radius = 0, is_imap = 0, is_smtp = 0, is_pop = 0,
      is_diameter = 0, is_whois = 0, is_dhcp = 0, is_ftp = 0, is_process = 0;

    traceEvent(TRACE_INFO, "Scanning plugin %s", readOnlyGlobals.all_plugins[plugin_idx]->name);

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "http")) {
      is_http = 1;
      if(readOnlyGlobals.enableHttpPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "dns")) {
      is_dns = 1;
      if(readOnlyGlobals.enableDnsPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "gtp")) {
      is_gtp = 1;
      if(readOnlyGlobals.enableGtpPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "radius")) {
      is_radius = 1;
      if(readOnlyGlobals.enableRadiusPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "diameter")) {
      is_diameter = 1;
      if(readOnlyGlobals.enableDiameterPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "smtp")) {
      is_smtp = 1;
      if(readOnlyGlobals.enableSmtpPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "pop")) {
      is_pop = 1;
      if(readOnlyGlobals.enablePopPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "imap")) {
      is_imap = 1;
      if(readOnlyGlobals.enableImapPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "mysql")) {
      is_mysql = 1;
      if(readOnlyGlobals.enableMySQLPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "oracle")) {
      is_oracle = 1;
      if(readOnlyGlobals.enableOraclePlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "dhcp")) {
      is_dhcp = 1;
      if(readOnlyGlobals.enableDhcpPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "ftp")) {
      is_ftp = 1;
      if(readOnlyGlobals.enableFtpPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "sip")) {
      is_sip = 1;
      if(readOnlyGlobals.enableSipPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "l7")) {
      is_l7 = 1;
      if(readOnlyGlobals.enableL7BridgePlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(strcasestr(readOnlyGlobals.all_plugins[plugin_idx]->name, "process")) {
      is_process = 1;
      if(readOnlyGlobals.enableProcessPlugin)
	readOnlyGlobals.all_plugins[plugin_idx]->always_enabled = 1;
    }

    if(readOnlyGlobals.all_plugins[plugin_idx]->always_enabled) {
      readOnlyGlobals.all_active_plugins[readOnlyGlobals.num_active_plugins++] = readOnlyGlobals.all_plugins[plugin_idx];
    } else if(readOnlyGlobals.all_plugins[plugin_idx]->getTemplateFctn != NULL) {
      int j;

      j = 0;
      while(template_element_list[j] != NULL) {
	/* traceEvent(TRACE_INFO, "Searching for: %s", (char*)template_element_list[j]->netflowElementName); */

	if(readOnlyGlobals.all_plugins[plugin_idx]->getTemplateFctn((char*)template_element_list[j]->netflowElementName)) {
	  readOnlyGlobals.all_active_plugins[readOnlyGlobals.num_active_plugins++] = readOnlyGlobals.all_plugins[plugin_idx];

	  if(is_dns)           readOnlyGlobals.enableDnsPlugin = 1;
	  else if(is_gtp)      readOnlyGlobals.enableGtpPlugin = 1;
	  else if(is_radius)   readOnlyGlobals.enableRadiusPlugin = 1;
	  else if(is_diameter) readOnlyGlobals.enableDiameterPlugin = 1;
	  else if(is_http)     readOnlyGlobals.enableHttpPlugin = 1;
	  else if(is_l7)       readOnlyGlobals.enableL7BridgePlugin = 1;
	  else if(is_mysql)    readOnlyGlobals.enableMySQLPlugin = 1;
	  else if(is_oracle)   readOnlyGlobals.enableOraclePlugin = 1;
	  else if(is_whois)    readOnlyGlobals.enableWhoisPlugin = 1;
	  else if(is_dhcp)     readOnlyGlobals.enableDhcpPlugin = 1;
	  else if(is_ftp)      readOnlyGlobals.enableFtpPlugin = 1;
	  else if(is_process)  readOnlyGlobals.enableProcessPlugin = 1;
	  else if(is_sip)      readOnlyGlobals.enableSipPlugin = 1;
	  else if(is_smtp)     readOnlyGlobals.enableSmtpPlugin = 1;
	  else if(is_imap)     readOnlyGlobals.enableImapPlugin = 1;
	  else if(is_pop)      readOnlyGlobals.enablePopPlugin = 1;

	  traceEvent(TRACE_INFO, "Enabling plugin %s", readOnlyGlobals.all_plugins[plugin_idx]->name);
	  break;
	}

	j++;
      }
    }

    plugin_idx++;
  }

  readOnlyGlobals.all_active_plugins[readOnlyGlobals.num_active_plugins] = NULL;

  traceEvent(TRACE_NORMAL, "%d plugin(s) enabled", readOnlyGlobals.num_active_plugins);
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

  while(templates[j].netflowElementName != NULL) {
    if((!templates[j].isOptionTemplate)
       // && (templates[j].templateElementId < 0xA0)
       )
      fprintf(file, "%s\t%d\t%s\t%s\n",
	      templates[j].netflowElementName,
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

  while(readOnlyGlobals.all_plugins[i] != NULL) {
    V9V10TemplateElementId *templates = readOnlyGlobals.all_plugins[i]->pluginFlowConf();

    if(templates && (templates[0].netflowElementName != NULL))
      printTemplateMetadata(file, templates);

    i++;
  }
}

/* ******************************************** */

void pluginIdleThreadTask(void) {
  int i = 0;

  while(readOnlyGlobals.all_active_plugins[i] != NULL) {
    if(readOnlyGlobals.all_active_plugins[i]->idleFctn != NULL)
      readOnlyGlobals.all_active_plugins[i]->idleFctn();

    i++;
  }
}
