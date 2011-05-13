/*
 *  Copyright (C) 2005-11 Luca Deri <deri@ntop.org>
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

#define DEBUG

#define BASE_ID           NTOP_BASE_ID+165
#define FIELD_LEN           8

typedef enum {
  HTTP_PROTO = 0,
  SSL_PROTO,
  SSH_PROTO,
  DNS_PROTO,
  SMTP_PROTO,
  IMAP_PROTO,
  TELNET_PROTO,
  POP_PROTO,
  RADIUS_PROTO,
  NETBIOS_PROTO,
  NBSS_PROTO,
  SNMP_PROTO,
  BOOTP_PROTO,
  UNKNOWN_PROTO
} L7ProtocolId;

/* Forward */
static L7ProtocolId httpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId sslCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId sshCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId dnsCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId smtpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId imapCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId popCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId radiusCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId netbiosCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId snmpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
static L7ProtocolId bootpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);

typedef struct {
  L7ProtocolId protocolId;
  char *protocolName;
  u_int8_t proto;
  L7ProtocolId (*defaultProtocolCheck)(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort);
} L7L7ProtocolId;

L7L7ProtocolId protocols[] = {
  { HTTP_PROTO, "http", IPPROTO_TCP, httpCheck},
  { SSL_PROTO,  "ssl",  IPPROTO_TCP, sslCheck },
  { SSH_PROTO,  "ssh",  IPPROTO_TCP, sshCheck },
  { DNS_PROTO,  "dns",  IPPROTO_UDP, dnsCheck },
  { SMTP_PROTO, "smtp", IPPROTO_TCP, smtpCheck },
  { IMAP_PROTO, "imap", IPPROTO_TCP, imapCheck },
  { POP_PROTO,  "pop",  IPPROTO_TCP, popCheck },
  { TELNET_PROTO,  "telnet",  IPPROTO_TCP, NULL },
  { RADIUS_PROTO,  "radius",  IPPROTO_UDP, radiusCheck },
  { NETBIOS_PROTO,  "netbios",  IPPROTO_UDP, netbiosCheck },
  { NBSS_PROTO,  "netbios-over-tcp",  IPPROTO_TCP, netbiosCheck },
  { SNMP_PROTO,  "snmp",  IPPROTO_UDP, snmpCheck },
  { BOOTP_PROTO,  "bootp/dhcp",  IPPROTO_UDP, bootpCheck },
  { UNKNOWN_PROTO, NULL, 0, NULL }
};

static V9V10TemplateElementId l7Plugin_template[] = {
  { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID, STATIC_FIELD_LEN, FIELD_LEN, ascii_format, dump_as_ascii, "L7_PROTO", "Symbolic layer 7 protocol description" },
  { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL }
};

struct plugin_info {
  char *protocol_name;
  u_int8_t proto_checked;
};

/* *********************************************** */

static PluginInfo l7Plugin; /* Forward */

/* ******************************************* */

void l7Plugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized L7 plugin");
}

/* ******************************************* */

inline int has_port(FlowHashBucket* bkt, u_int port, u_int16_t *knownPort) {
  if((bkt->sport == port) || (bkt->dport == port)) {
    *knownPort = port;
    return(1);
  } else
    return(0);
}

/* *********************************************** */

static char* protocolMatch(FlowHashBucket* bkt) {
  L7ProtocolId protoId = UNKNOWN_PROTO;
  u_int16_t knownPort, checked = 1;

  if(bkt->src2dstPayload || bkt->src2dstPayloadLen) {
    /* bkt->src2dstPayload, bkt->src2dstPayloadLen */
    if(0)
      traceEvent(TRACE_NORMAL, "==> Payload (%d/%d) [%s][%s]",
		 bkt->src2dstPayloadLen, bkt->dst2srcPayloadLen,
		 bkt->src2dstPayload, bkt->dst2srcPayload);

    switch(bkt->proto) {
    case IPPROTO_TCP:
      if((has_port(bkt, 80, &knownPort)
	  || has_port(bkt, 8080, &knownPort)
	  || has_port(bkt, 3128, &knownPort)))
	protoId = httpCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 22, &knownPort))   protoId = sshCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 23, &knownPort))   protoId = TELNET_PROTO;
      else if(has_port(bkt, 25, &knownPort))   protoId = smtpCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 139, &knownPort))  protoId = netbiosCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 110, &knownPort))  protoId = popCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 143, &knownPort))  protoId = imapCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 443, &knownPort))  protoId = sslCheck(bkt, bkt->proto, knownPort);
      else checked = 0;
      break;

    case IPPROTO_UDP:
      if(has_port(bkt, 53, &knownPort)) protoId = dnsCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 67, &knownPort) || has_port(bkt, 68, &knownPort)) protoId = bootpCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 137, &knownPort) || has_port(bkt, 138, &knownPort)) protoId = netbiosCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 161, &knownPort) || has_port(bkt, 162, &knownPort)) protoId = snmpCheck(bkt, bkt->proto, knownPort);
      else if(has_port(bkt, 1813, &knownPort) || has_port(bkt, 1646, &knownPort)) protoId = radiusCheck(bkt, bkt->proto, knownPort);
      else checked = 0;
      break;

    default:
      checked = 0;
      break;
    }

    if(!checked) {
      /* Check if this is a known protocol on a non-standard port */
      int i;

      for(i=0; protocols[i].protocolName != NULL; i++) {
	if((bkt->proto == protocols[i].proto)
	   && (protocols[i].defaultProtocolCheck != NULL)) {
	  /* Try forward first... */
	  protoId = protocols[i].defaultProtocolCheck(bkt, protocols[i].proto, bkt->sport);
	  if(protoId != UNKNOWN_PROTO) break;

	  /* Then try reverse... */
	  protoId = protocols[i].defaultProtocolCheck(bkt, protocols[i].proto, bkt->dport);
	  if(protoId != UNKNOWN_PROTO) break;
	}
      }
    }

#ifdef DEBUG
    if(protoId == UNKNOWN_PROTO)
      traceEvent(TRACE_NORMAL, "Unknown Proto [%d->%d][%s][%s]",
		 bkt->sport, bkt->dport,
		 bkt->src2dstPayload, bkt->dst2srcPayload);
#endif
  }

  return(protocols[protoId].protocolName);
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void l7Plugin_packet(u_char new_bucket, void *pluginData,
			    FlowHashBucket* bkt,
			    FlowDirection flow_direction,
			    u_short proto, u_char isFragment,
			    u_short numPkts, u_char tos,
			    u_short vlanId, struct eth_header *ehdr,
			    IpAddress *src, u_short sport,
			    IpAddress *dst, u_short dport,
			    u_int plen, u_int8_t flags,
			    u_int32_t tcpSeqNum, u_int8_t icmpType,
			    u_short numMplsLabels,
			    u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			    const struct pcap_pkthdr *h, const u_char *p,
			    u_char *payload, int payloadLen) {
  PluginInformation *info;

  // traceEvent(TRACE_INFO, "l7Plugin_packet(%d)", payloadLen)

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&l7Plugin;
    pluginData = info->pluginData = malloc(sizeof(struct plugin_info));

    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else
      memset(info->pluginData, 0, sizeof(struct plugin_info));

    info->next = bkt->plugin;
    bkt->plugin = info;
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void l7Plugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* l7Plugin_get_template(char* template_name) {
  int i;

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, l7Plugin_template[i].templateElementName)) {
      return(&l7Plugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int l7Plugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			   FlowDirection direction,
			   FlowHashBucket *bkt, char *outBuffer,
			   uint* outBufferBegin, uint* outBufferMax) {
  int i;
  struct plugin_info *pinfo = (struct plugin_info*)pluginData;

  if(theTemplate == NULL) return(-1);

  if((pinfo->protocol_name == NULL) && (!pinfo->proto_checked)) {
    char *proto_name = protocolMatch(bkt);

    if(proto_name) {
      traceEvent(TRACE_NORMAL, "*******> Found '%s' protocol flow", proto_name);
      pinfo->protocol_name = proto_name;
    }

    pinfo->proto_checked = 1;
  }

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == l7Plugin_template[i].templateElementId) {
      if((*outBufferBegin)+l7Plugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(l7Plugin_template[i].templateElementId) {
	case BASE_ID:
	  memset(&outBuffer[*outBufferBegin], 0, FIELD_LEN);

	  if(info->protocol_name) {
	    int len = strlen(info->protocol_name);

	    if(len > FIELD_LEN) len = FIELD_LEN;
	    memcpy(&outBuffer[*outBufferBegin], info->protocol_name, len);
	    traceEvent(TRACE_INFO, "-> L7_PROTO: %s", info->protocol_name);
	  }
	  (*outBufferBegin) += l7Plugin_template[i].templateElementLen;
	  break;
	default:
	  return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static int l7Plugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			  FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
			  FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len) {
  int i;

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == l7Plugin_template[i].templateElementId) {

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(l7Plugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)],
		   (line_buffer_len-strlen(line_buffer)),
		   "%s", info->protocol_name ? info->protocol_name : "");
	  break;
	default:
	  return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId* l7Plugin_conf(void) {
  return(l7Plugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo l7Plugin = {
  NPROBE_REVISION,
  "L7 Protocol Recognition",
  "0.1",
  "Handle L7 protocols",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  l7Plugin_init,
  NULL, /* Term */
  l7Plugin_conf,
  l7Plugin_delete,
  1, /* call packetFlowFctn for each packet */
  l7Plugin_packet,
  l7Plugin_get_template,
  l7Plugin_export,
  l7Plugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* l7PluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&l7Plugin);
}

/* *********************************************** */

inline int mystrcasecmp(char *a, char *b) { return(strncasecmp(a, b, strlen(b))); }
inline int mystrcmp(char *a, char *b)     { return(strncmp(a, b, strlen(b)));     }

/* *********************************************** */
/* *********************************************** */

static L7ProtocolId httpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  u_char *clientPayload = (bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_char *serverPayload = (bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;

  if(clientPayload || serverPayload) {
#ifdef DEBUG
    traceEvent(TRACE_NORMAL, "httpCheck()");
#endif

    if(clientPayload) {
      if((!mystrcmp((char*)clientPayload, "GET "))
	 || (!mystrcmp((char*)clientPayload, "POST "))
	 || (!mystrcmp((char*)clientPayload, "HEAD "))
	 || (!mystrcmp((char*)clientPayload, "PUT "))
	 || (!mystrcmp((char*)clientPayload, "DELETE "))
	 || (!mystrcmp((char*)clientPayload, "TRACE "))
	 || (!mystrcmp((char*)clientPayload, "CONNECT "))
	 || (!mystrcmp((char*)clientPayload, "OPTIONS "))
	 ) {
	/* if((!serverPayload) || (!mystrcmp((char*)serverPayload, "HTTP"))) */
	  return(HTTP_PROTO);
      }
    } else {
      if(!mystrcmp((char*)serverPayload, "HTTP"))
	return(HTTP_PROTO);
    }
  }

  return(UNKNOWN_PROTO); /* Default */
}

/* *********************************************** */

static L7ProtocolId sslCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "sslCheck()");
#endif

  return(UNKNOWN_PROTO); /* Default */
}

/* *********************************************** */

static L7ProtocolId sshCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "sshCheck()");
#endif

  if(serverPayload) {
    if(!mystrcasecmp(serverPayload, "SSH-")) {
      int a, b;

      if((sscanf(&serverPayload[4], "%d.%d-", &a, &b) == 2)
	 || (sscanf(&serverPayload[4], "%d-", &a) == 1))
	return(SSH_PROTO);
    }
  }

  return(UNKNOWN_PROTO); /* Default */
}

/* *********************************************** */

static u_int8_t isValidDNS(u_char* payload) {
  u_int16_t num_questions, answer_rrs, authority_rrs, additional_rrs;

  num_questions = ((payload[4] & 0xFF) << 8) + (payload[5] & 0xFF);
  answer_rrs = ((payload[6] & 0xFF) << 8) + (payload[7] & 0xFF);
  authority_rrs = ((payload[8] & 0xFF) << 8) + (payload[9] & 0xFF);
  additional_rrs = ((payload[10] & 0xFF) << 8) + (payload[11] & 0xFF);

#ifdef DEBUG
  if(0)
  traceEvent(TRACE_NORMAL, "isValidDNS(%u/%u/%u/%u)",
	     num_questions, answer_rrs, authority_rrs, additional_rrs);
#endif

  if((num_questions > 5)
     || (answer_rrs > 5)
     || (authority_rrs > 5)
     || (additional_rrs > 5))
    return(0);

  return(1);
}

static L7ProtocolId dnsCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  u_char *requestPayload = (bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_char *responsePayload = (bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_int minPayload = min(32, readOnlyGlobals.maxPayloadLen);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "dnsCheck()");
#endif

  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);
  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);

  if(requestPayload && (!isValidDNS(requestPayload))) return(UNKNOWN_PROTO);
  else if(responsePayload && (!isValidDNS(responsePayload))) return(UNKNOWN_PROTO);
  else return(DNS_PROTO);
}

/* *********************************************** */

static u_int8_t isValidNETBIOS(u_char* payload, u_int16_t proto, u_int16_t port) {
  if(proto == IPPROTO_UDP) { 
    /* Check if this is a datagram request */
    u_int16_t netbios_port = ((payload[8] & 0xFF) << 8) + (payload[9] & 0xFF);
    u_int16_t num_questions, answer_rrs, authority_rrs, additional_rrs;

    if(port == netbios_port) return(1);

    /* Looks like DNS */
    num_questions = ((payload[4] & 0xFF) << 8) + (payload[5] & 0xFF);
    answer_rrs = ((payload[6] & 0xFF) << 8) + (payload[7] & 0xFF);
    authority_rrs = ((payload[8] & 0xFF) << 8) + (payload[9] & 0xFF);
    additional_rrs = ((payload[10] & 0xFF) << 8) + (payload[11] & 0xFF);

#ifdef DEBUG
    if(0)
      traceEvent(TRACE_NORMAL, "isValidNETBIOS(%u/%u/%u/%u)",
		 num_questions, answer_rrs, authority_rrs, additional_rrs);
#endif

    if((num_questions > 5)
       || (answer_rrs > 5)
       || (authority_rrs > 5)
       || (additional_rrs > 5))
      return(0);

    return(1);
  } else {
    /* TCP */
    /*
      00 -  SESSION MESSAGE
      81 -  SESSION REQUEST
      82 -  POSITIVE SESSION RESPONSE
      83 -  NEGATIVE SESSION RESPONSE
      84 -  RETARGET SESSION RESPONSE
      85 -  SESSION KEEP ALIVE
    */
    switch(payload[0]) {
    case 0x00:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
      return(1);
      break;
    }
    
    return(0);
  }
}

static L7ProtocolId netbiosCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  u_char *requestPayload = (bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_char *responsePayload = (bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_int minPayload = min(32, readOnlyGlobals.maxPayloadLen);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "netbiosCheck()");
#endif

  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);
  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);

  if(requestPayload && (!isValidNETBIOS(requestPayload, proto, knownPort))) return(UNKNOWN_PROTO);
  else if(responsePayload && (!isValidNETBIOS(responsePayload, proto, knownPort))) return(UNKNOWN_PROTO);
  else return(NETBIOS_PROTO);
}

/* *********************************************** */

static u_int8_t isValidRadiusCode(u_int8_t code) {
  if((code >= 1) && (code <= 5)) return(1);
  else if((code >= 11) && (code <= 13)) return(1);
  else if(code == 255) return(1);

  return(0);
}

static u_int8_t isValidRadius(u_char* payload) {
  u_int8_t code = payload[0];
  u_int8_t packet_id = payload[1];
  u_int16_t len = ((payload[2] & 0xFF) << 8) + (payload[3] & 0xFF);

  if((!isValidRadiusCode(code))
     || (packet_id > 128)
     || (len > 1024))
    return(0);

  return(1);
}

static L7ProtocolId radiusCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  u_char *requestPayload = (bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_char *responsePayload = (bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload;
  u_int minPayload = min(32, readOnlyGlobals.maxPayloadLen);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "radiusCheck()");
#endif

  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);
  if((bkt->dst2srcPayloadLen > 0) && (bkt->dst2srcPayloadLen < minPayload)) return(UNKNOWN_PROTO);

  if(requestPayload && (!isValidRadius(requestPayload))) return(UNKNOWN_PROTO);
  else if(responsePayload && (!isValidRadius(responsePayload))) return(UNKNOWN_PROTO);
  else return(RADIUS_PROTO);
}

/* *********************************************** */

static L7ProtocolId smtpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char *clientPayload = (char*)((bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "smtpCheck()");
#endif

  if((!serverPayload) || (!clientPayload)) return(UNKNOWN_PROTO);
  if(mystrcmp((char*)serverPayload, "220")) return(UNKNOWN_PROTO);
  if(mystrcmp((char*)clientPayload, "EHLO ")) return(UNKNOWN_PROTO);
  else return(SMTP_PROTO);
}

/* *********************************************** */

static L7ProtocolId imapCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char *clientPayload = (char*)((bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char a[32], b[32];

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "imapCheck()");
#endif

  if((!serverPayload) || (!clientPayload)) return(UNKNOWN_PROTO);
  if(mystrcmp((char*)serverPayload, "* OK ")) return(UNKNOWN_PROTO);
  if(sscanf(clientPayload, "%s %s", a, b) != 2) return(UNKNOWN_PROTO);
  else return(IMAP_PROTO);
}

/* *********************************************** */

static L7ProtocolId popCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char *clientPayload = (char*)((bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char a[32];

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "popCheck()");
#endif

  if((!serverPayload) || (!clientPayload)) return(UNKNOWN_PROTO);
  else if(mystrcmp((char*)serverPayload, "+OK ")) return(UNKNOWN_PROTO);
  else if(sscanf(clientPayload, "USER %s", a) != 1) return(UNKNOWN_PROTO);
  else return(POP_PROTO);
}

/* *********************************************** */

static u_int8_t isValidSnmp(u_char* payload) {
  if((payload[0] == 0x30) /* SEQUENCE */
     && (payload[2] == 0x02) && (payload[3] == 0x01) && (payload[4] < 0x02 /* SNMPv3 */))
    return(1);
  else
    return(0);
}

static L7ProtocolId snmpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char *clientPayload = (char*)((bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "snmpCheck()");
#endif

  if((!serverPayload) && (!clientPayload)) return(UNKNOWN_PROTO);
  else if(serverPayload && isValidSnmp((u_char*)serverPayload)) return(SNMP_PROTO);
  else if(clientPayload && isValidSnmp((u_char*)clientPayload)) return(SNMP_PROTO);

  return(UNKNOWN_PROTO); /* Default */
}

/* *********************************************** */

static u_int8_t isValidBootp(u_char* payload) {
  if(((payload[0] == 0x01 /* Request */) || (payload[0] == 0x02 /* Reply */))
     && (payload[1] == 0x01 /* Ethernet */)
     && (payload[2] == 0x06 /* MAC Address len */))
    return(1);
  else
    return(0);
}

static L7ProtocolId bootpCheck(FlowHashBucket* bkt, u_int8_t proto, u_int16_t knownPort) {
  char *serverPayload = (char*)((bkt->sport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);
  char *clientPayload = (char*)((bkt->dport == knownPort) ? bkt->src2dstPayload : bkt->dst2srcPayload);

#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "bootpCheck()");
#endif

  if((!serverPayload) && (!clientPayload)) return(UNKNOWN_PROTO);
  else if(serverPayload && isValidBootp((u_char*)serverPayload)) return(BOOTP_PROTO);
  else if(clientPayload && isValidBootp((u_char*)clientPayload)) return(BOOTP_PROTO);

  return(UNKNOWN_PROTO); /* Default */
}

/* *********************************************** */
