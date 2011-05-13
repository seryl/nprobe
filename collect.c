/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2007-11 Luca Deri <deri@ntop.org>
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

//#define DEBUG_FLOWS 
//#define CISCO_DEBUG
#define LEN_SMALL_WORK_BUFFER 2048


/* forward */
void* netFlowCollectLoop(void* notUsed);

#define MAX_PACKET_LEN   256

struct generic_netflow_record {
  /* v5 */
  IpAddress srcaddr;    /* Source IP Address */
  IpAddress dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t sentPkts, rcvdPkts;
  u_int32_t sentOctets, rcvdOctets;
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int32_t dst_as;     /* dst peer/origin Autonomous System */
  u_int32_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */

  /* v9 */
  u_int16_t vlanId;

  /* Latency extensions */
  u_int32_t nw_latency_sec, nw_latency_usec;

  /* VoIP Extensions */
  char sip_call_id[50], sip_calling_party[50], sip_called_party[50];

  /* Cisco */
  u_int8_t hasSampling;
  u_int16_t packet_len /* 103 */, original_packet_len /* 312 */, packet_offset /* 102 */;
  u_int32_t samplingPopulation /* 310 */, observationPointId /* 300 */;
  u_int16_t selectorId /* 302 */;
  u_char packet[MAX_PACKET_LEN] /* 104 */;
};

/* ********************************************************* */

/*
   Cisco ASA
   http://www.cisco.com/en/US/docs/security/asa/asa81/netflow/netflow.html#wp1028202
*/

/* ********************************************************* */

int createNetFlowListener(u_short collectorInPort) {
  int sockopt = 1;
  struct sockaddr_in sockIn;

  readWriteGlobals->collectionStats.num_dissected_flow_packets = 0;
  readOnlyGlobals.collectorInSocket = readOnlyGlobals.collectorInSctpSocket = readOnlyGlobals.remoteInSocket = -1;
  memset(readWriteGlobals->up_to_512_templates, 0, sizeof(readWriteGlobals->up_to_512_templates));
  readWriteGlobals->over_512_templates = NULL;

  if(collectorInPort > 0) {
    int i;

    /*
      Check if for some configuration error we'll be sending flows to
      ourselves, that creates a waterfall effect
    */
    for(i=0; i<readOnlyGlobals.numCollectors; i++) {
      if((readOnlyGlobals.netFlowDest[i].u.v4Address.sin_port == htons(collectorInPort))
	 && (readOnlyGlobals.netFlowDest[i].u.v4Address.sin_addr.s_addr == inet_addr("127.0.0.1"))) {
	traceEvent(TRACE_ERROR, "Bad configuration: flows will be sent to the collection port");
	traceEvent(TRACE_ERROR, "causing a waterfall effect: flow collection will be disabled");
#if 0
	readOnlyGlobals.numCollectors = 0;
	return(-1);
#endif
      }
    }

    errno = 0;
    readOnlyGlobals.collectorInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((readOnlyGlobals.collectorInSocket < 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 readOnlyGlobals.collectorInSocket, strerror(errno), errno);
      return(-1);
    } else
      maximize_socket_buffer(readOnlyGlobals.collectorInSocket, SO_RCVBUF);

#ifdef HAVE_SCTP
    readOnlyGlobals.collectorInSctpSocket = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

    if((readOnlyGlobals.collectorInSctpSocket < 0) || (errno != 0)) {
      traceEvent(TRACE_INFO, "Unable to create a SCTP socket - returned %d, error is '%s'(%d)",
		 readOnlyGlobals.collectorInSocket, strerror(errno), errno);
    }
#endif

    traceEvent(TRACE_INFO, "Created a UDP socket (%d)", readOnlyGlobals.collectorInSocket);

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0)
      traceEvent(TRACE_INFO, "Created a SCTP socket (%d)", readOnlyGlobals.collectorInSctpSocket);
#endif

    setsockopt(readOnlyGlobals.collectorInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              = (int)htons(collectorInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if((bind(readOnlyGlobals.collectorInSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0)
#ifdef HAVE_SCTP
       || ((readOnlyGlobals.collectorInSctpSocket > 0)
	   && (bind(readOnlyGlobals.collectorInSctpSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0))
#endif
       ) {
      traceEvent(TRACE_ERROR, "Flow collector port %d already in use", collectorInPort);
      close(readOnlyGlobals.collectorInSocket);
      readOnlyGlobals.collectorInSocket = 0;
#ifdef HAVE_SCTP
      if(readOnlyGlobals.collectorInSctpSocket) close(readOnlyGlobals.collectorInSctpSocket);
      readOnlyGlobals.collectorInSctpSocket = 0;
#endif
      return(0);
    }

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0) {
      if(listen(readOnlyGlobals.collectorInSctpSocket, 100) == -1) {
	traceEvent(TRACE_ERROR, "Listen on SCTP socket failed [%s]", strerror(errno));
      }
    }
#endif

    traceEvent(TRACE_NORMAL, "Flow collector listening on port %d", collectorInPort);

    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      unsigned long id = i;

      pthread_create(&readOnlyGlobals.collectThread[i], NULL, netFlowCollectLoop, (void*)id);
    }
  }

  return(0);
}

/* ********************************************************* */

void closeNetFlowListener() {
  if(readOnlyGlobals.collectorInSocket != -1)     close(readOnlyGlobals.collectorInSocket);
  if(readOnlyGlobals.collectorInSctpSocket != -1) close(readOnlyGlobals.collectorInSctpSocket);
}

/* ********************************************************* */

int createRemoteListener(u_short remoteInPort) {
  int sockopt = 1;
  struct sockaddr_in sockIn;

  if(remoteInPort > 0) {
    errno = 0;
    readOnlyGlobals.remoteInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((readOnlyGlobals.remoteInSocket <= 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 readOnlyGlobals.remoteInSocket, strerror(errno), errno);
      return(-1);
    }

    traceEvent(TRACE_INFO, "Created a UDP socket (%d)", readOnlyGlobals.remoteInSocket);

    setsockopt(readOnlyGlobals.remoteInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              = (int)htons(remoteInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(readOnlyGlobals.remoteInSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(TRACE_ERROR, "Remote collector port %d already in use", remoteInPort);
      close(readOnlyGlobals.remoteInSocket);
      readOnlyGlobals.remoteInSocket = 0;
      return(0);
    }
  }

  return(0);
}

/* ********************************************************* */

void closeRemoteListener(void) {
  if(readOnlyGlobals.remoteInSocket != -1) close(readOnlyGlobals.remoteInSocket);
}

/* *************************** */

static void deEndianRecord(struct generic_netflow_record *record) {
  record->last = ntohl(record->last), record->first = ntohl(record->first);

  if(record->srcaddr.ipVersion == 4) {
    record->srcaddr.ipType.ipv4 = ntohl(record->srcaddr.ipType.ipv4);
    record->dstaddr.ipType.ipv4 = ntohl(record->dstaddr.ipType.ipv4);
  }

  record->sentPkts = ntohl(record->sentPkts), record->rcvdPkts = ntohl(record->rcvdPkts);
  record->srcport = ntohs(record->srcport), record->dstport = ntohs(record->dstport);
  record->sentOctets = ntohl(record->sentOctets), record->rcvdOctets = ntohl(record->rcvdOctets);
  record->input = ntohs(record->input), record->output = ntohs(record->output);
  record->src_as = htonl(record->src_as), record->dst_as = htonl(record->dst_as);
}

/* *************************** */

static void handleGenericFlow(u_int32_t netflow_device_ip,
			      time_t recordActTime, time_t recordSysUpTime,
			      struct generic_netflow_record *record) {
  struct pcap_pkthdr h;
  time_t firstSeen, lastSeen;
  time_t initTime;

  pthread_rwlock_wrlock(&readWriteGlobals->collectorCounterLock);
  readWriteGlobals->collectionStats.num_flows_processed++;
  pthread_rwlock_unlock(&readWriteGlobals->collectorCounterLock);

  initTime = recordActTime-(recordSysUpTime/1000);
  firstSeen = (ntohl(record->first)/1000) + initTime;
  lastSeen  = (ntohl(record->last)/1000) + initTime;

  /* Sanity check */
  if(readOnlyGlobals.initialSniffTime.tv_sec == 0) {
    // readOnlyGlobals.initialSniffTime.tv_sec = firstSeen, readOnlyGlobals.initialSniffTime.tv_usec = 0;
    readOnlyGlobals.initialSniffTime.tv_sec = time(NULL), readOnlyGlobals.initialSniffTime.tv_usec = 0;
  }
  
  if(firstSeen < readOnlyGlobals.initialSniffTime.tv_sec)
    firstSeen = readOnlyGlobals.initialSniffTime.tv_sec;

  if(lastSeen < readOnlyGlobals.initialSniffTime.tv_sec)
    lastSeen = readOnlyGlobals.initialSniffTime.tv_sec;

  memset(&h, 0, sizeof(h));
  h.ts.tv_sec = readWriteGlobals->now;

#if 0
  traceEvent(TRACE_INFO,
	     "Called addPktToHash() [firstSeen=%u][lastSeen=%u][initial=%u]",
	     firstSeen, lastSeen, readOnlyGlobals.initialSniffTime.tv_sec);
#endif

  record->first = record->last = h.ts.tv_sec;

  if(record->sentPkts && record->sentOctets)
    queueParsedPkt(record->proto,
		   0 /* no fragments */,
		   0 /* no sample */,
		   record->sentPkts,
		   record->tos,
		   record->vlanId,
		   0, /* tunnel_id */
		   NULL, /* Ethernet */
		   &record->srcaddr,
		   record->srcport,
		   &record->dstaddr,
		   record->dstport,
		   0, NULL, 0, NULL, 0, /* Tunnel info */
		   record->sentOctets,
		   record->tcp_flags, 0, /* TCP seq num */
		   0,
		   0,
		   0, NULL, /* MPLS */
		   record->input, record->output,
		   &h, NULL, 0, 0, 0, /* payload */
		   firstSeen,
		   record->src_as, record->dst_as,
		   record->src_mask, record->dst_mask,
		   netflow_device_ip);

  if(record->rcvdPkts && record->rcvdOctets) {
    queueParsedPkt(record->proto,
		   0 /* no fragments */,
		   0 /* no sample */,
		   record->rcvdPkts,
		   record->tos,
		   record->vlanId,
		   0, /* tunnel_id */
		   NULL, /* Ethernet */
		   &record->dstaddr,
		   record->dstport,
		   &record->srcaddr,
		   record->srcport,
		   0, NULL, 0, NULL, 0, /* Tunnel info */
		   record->rcvdOctets,
		   record->tcp_flags, 0, /* TCP seq num */
		   0,
		   0,
		   0, NULL, /* MPLS */
		   record->output, record->input,
		   &h, NULL, 0, 0, 0, /* payload */
		   firstSeen,
		   record->dst_as, record->src_as,
		   record->dst_mask, record->src_mask,
		   netflow_device_ip);
  }
}

/* ********************************************************* */

void dissectNetFlow(u_int32_t netflow_device_ip,
		    char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  int flowVersion;
  time_t recordActTime = 0, recordSysUpTime = 0;
  struct generic_netflow_record record;

  pthread_rwlock_wrlock(&readWriteGlobals->collectorCounterLock);
  readWriteGlobals->collectionStats.num_dissected_flow_packets++;
  pthread_rwlock_unlock(&readWriteGlobals->collectorCounterLock);

  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  flowVersion = ntohs(the5Record.flowHeader.version);

#ifdef DEBUG_FLOWS
  if(1)
    traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(len=%d) [tot flow packets=%u]", bufferLen,
	       readWriteGlobals->collectionStats.num_dissected_flow_packets);
#endif

#ifdef DEBUG_FLOWS
  if(1)
    traceEvent(TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  /*
    Convert V7 flows into V5 flows in order to make ntop
    able to handle V7 flows.

    Courtesy of Bernd Ziller <bziller@ba-stuttgart.de>
  */
  if((flowVersion == 1) || (flowVersion == 7)) {
    int numFlows, i;
    NetFlow1Record the1Record;
    NetFlow7Record the7Record;

    if(flowVersion == 1) {
      memcpy(&the1Record, buffer, bufferLen > sizeof(the1Record) ?
	     sizeof(the1Record): bufferLen);
      numFlows = ntohs(the1Record.flowHeader.count);
      if(numFlows > V1FLOWS_PER_PAK) numFlows = V1FLOWS_PER_PAK;
      recordActTime   = ntohl(the1Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the1Record.flowHeader.sysUptime);
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ?
	     sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      if(numFlows > V7FLOWS_PER_PAK) numFlows = V7FLOWS_PER_PAK;
      recordActTime   = ntohl(the7Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the7Record.flowHeader.sysUptime);
    }

#ifdef DEBUG_FLOWS
    if(1)
      traceEvent(TRACE_INFO, "NETFLOW: +++++++ flows=%d",  numFlows);
#endif

    the5Record.flowHeader.version = htons(5);
    the5Record.flowHeader.count = htons(numFlows);

    /* rest of flowHeader will not be used */
    for(i=0; i<numFlows; i++) {
      if(flowVersion == 7) {
	the5Record.flowRecord[i].srcaddr   = the7Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the7Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the7Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the7Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the7Record.flowRecord[i].dPkts;
	the5Record.flowRecord[i].dOctets   = the7Record.flowRecord[i].dOctets;
	the5Record.flowRecord[i].proto     = the7Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the7Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the7Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the7Record.flowRecord[i].last;
	the5Record.flowRecord[i].tcp_flags = the7Record.flowRecord[i].tcp_flags;
	/* rest of flowRecord will not be used */
      } else {
	/*
	  Some NetFlow v1 implementations (e.g. Extreme Networks) are
	  limited and most of the NetFlow fields are empty. In particular
	  the following fields are empty:
	  - input
	  - output
	  - dOctets
	  - first
	  - last
	  - tos
	  - tcp_flags

	  In this case we add a patch for filling some of the fields
	  in order to let ntop digest this flow.
	*/

	the5Record.flowRecord[i].srcaddr   = the1Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the1Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the1Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the1Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the1Record.flowRecord[i].dPkts;

	if(ntohl(the1Record.flowRecord[i].dOctets) == 0) {
	  /* We assume that all packets are 512 bytes long */
	  u_int32_t tmp = ntohl(the1Record.flowRecord[i].dPkts);
	  the5Record.flowRecord[i].dOctets = htonl(tmp*512);
	} else
	  the5Record.flowRecord[i].dOctets = the1Record.flowRecord[i].dOctets;

	the5Record.flowRecord[i].proto     = the1Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the1Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the1Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the1Record.flowRecord[i].last;
	/* rest of flowRecord will not be used */
      }
    }
  }  /* DON'T ADD a else here ! */

  if((flowVersion == 9) || (flowVersion == 10)) {
    /* NetFlowV9/IPFIX Record */
    u_char foundRecord = 0, done = 0;
    u_short numEntries, displ;
    V9IpfixSimpleTemplate template;
    int i;
    u_char handle_ipfix;

    if(flowVersion == 9) handle_ipfix = 0; else handle_ipfix = 1;

    if(handle_ipfix) {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader)-4; // FIX
#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "IPFIX Length: %d", numEntries);
#endif
    } else {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader);
    }

    recordActTime = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);
    /*     NTOHL(recordActTime); NTOHL(recordSysUpTime); */

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      V9V10TemplateField *fields = NULL;
      int16_t stillToProcess; /* Do not change to uint: this way I can catch template length issues */

      /* 1st byte */
#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "[displ=%d][%02X %02X %02X]",
		 displ, buffer[displ] & 0xFF,
		 buffer[displ+1] & 0xFF,
		 buffer[displ+2] & 0xFF);
#endif

      if(buffer[displ] == 0) {
	u_int8_t isOptionTemplate = (u_char)buffer[displ+1];

	/* Template */
	if(handle_ipfix
	   && (isOptionTemplate == 2 /* Template Flowset */)) {
	  /*
	    IPFIX (isOptionTemplate)

	    A value of 2 is reserved for the
	    Template Set.  A value of 3 is reserved for the Option Template
	    Set.  All other values from 4 to 255 are reserved for future use.
	    Values above 255 are used for Data Sets.  The Set ID values of 0
	    and 1 are not used for historical reasons
	  */

	  /* This trick is necessary as only option template flowsets
	     have to be handled differently from other templates
	  */
	  isOptionTemplate = 0;
	}

#ifdef DEBUG_FLOWS
	traceEvent(TRACE_INFO, "Found Template [displ=%d]", displ);
	traceEvent(TRACE_INFO, "Found Template Type: %s", isOptionTemplate ? "Option" : "Flow");
#endif

	if(bufferLen > (displ+sizeof(V9TemplateHeader))) {
	  V9TemplateHeader header;
	  u_int8_t templateDone = 0;

	  memcpy(&header, &buffer[displ], sizeof(V9TemplateHeader));
	  header.templateFlowset = ntohs(header.templateFlowset), header.flowsetLen = ntohs(header.flowsetLen);
	  stillToProcess = header.flowsetLen - sizeof(V9TemplateHeader);
	  displ += sizeof(V9TemplateHeader);

	  while((bufferLen >= (displ+stillToProcess)) && (!templateDone)) {
	    FlowSetV9Ipfix *cursor = NULL;
	    u_short len = 0;
	    int fieldId;
	    u_char goodTemplate = 0;
	    u_int accumulatedLen = 0;

	    memset(&template, 0, sizeof(template));
	    template.isOptionTemplate = isOptionTemplate, template.netflow_device_ip = netflow_device_ip;

	    if(isOptionTemplate) {
	      memcpy(&template.templateId, &buffer[displ], 2);
	      template.templateId = htons(template.templateId), template.fieldCount = (header.flowsetLen - 14)/4;

	      if(handle_ipfix) {
		u_int16_t tot_field_count, tot_scope_field_count;

		displ += 2 /*, len += 2 */;
		memcpy(&tot_field_count, &buffer[displ], 2); tot_field_count = htons(tot_field_count);
		displ += 2 /* , len += 2 */;
		memcpy(&tot_scope_field_count, &buffer[displ], 2); tot_scope_field_count = htons(tot_scope_field_count);
		displ += 2 /* , len += 2 */;
		template.scopeFieldCount = tot_scope_field_count;

		if(tot_field_count >= tot_scope_field_count) {
		  u_int num = tot_scope_field_count * 4; /* FIX: check PEN here */
		  displ += num /* , len += num */;
		} else {
		  traceEvent(TRACE_WARNING,
			     "It looks looks like the template is broken (tot_field_count=%d, tot_scope_field_count=%d) "
			     "[num_dissected_flows=%u][templateType=%d]",
			     tot_field_count, tot_scope_field_count,
			     readWriteGlobals->collectionStats.num_dissected_flow_packets, isOptionTemplate);
		  displ += 4 /* , len += 4 */; /* Using default skip */
		}
	      } else {
		memcpy(&template.v9ScopeLen, &buffer[displ+8], 2);
		template.v9ScopeLen = htons(template.v9ScopeLen);
		displ += 10, /* len = 0, */ stillToProcess -= 10;
	      }
	    } else {
	      V9TemplateDef templateDef;

	      memcpy(&templateDef, &buffer[displ], sizeof(V9TemplateDef));
	      displ += sizeof(V9TemplateDef), len = 0, stillToProcess -= sizeof(V9TemplateDef);

	      template.templateId = htons(templateDef.templateId), template.fieldCount = htons(templateDef.fieldCount);
	    }

	    if(template.fieldCount > 128) {
	      traceEvent(TRACE_WARNING, "Too many template fields (%d): skept", template.fieldCount);
	      goodTemplate = 0;
	    } else {
	      if(handle_ipfix) {
		fields = (V9V10TemplateField*)malloc(template.fieldCount * sizeof(V9V10TemplateField));
		if(fields == NULL) {
		  traceEvent(TRACE_WARNING, "Not enough memory");
		  break;
		}

		if(((template.fieldCount * 4) + sizeof(FlowSet) + 4 /* templateFlowSet + FlowsetLen */) >  header.flowsetLen) {
		  traceEvent(TRACE_WARNING, "Bad length [expected=%d][real=%d]",
			     template.fieldCount * 4,
			     numEntries + sizeof(FlowSet));
		} else {
		  goodTemplate = 1;

		  /* Check the template before handling it */
		  for(fieldId=0; fieldId < template.fieldCount; fieldId++) {
#ifdef DEBUG_FLOWS
		    u_int8_t pen_len = 0;
#endif
		    u_int8_t is_enterprise_specific = (buffer[displ+len] & 0x80) ? 1 : 0;
		    V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		    len += 4; /* Field Type (2) + Field Length (2) */

		    if(is_enterprise_specific) {
#ifdef DEBUG_FLOWS
		      pen_len = 4;
#endif
		      len += 4; /* PEN (Private Enterprise Number) */
		    }

		    fields[fieldId].fieldId = htons(set->templateId) & 0x7FFF;
		    fields[fieldId].fieldLen = htons(set->flowsetLen);
		    fields[fieldId].isPenField = is_enterprise_specific;
		    accumulatedLen += fields[fieldId].fieldLen;

#ifdef DEBUG_FLOWS
		    traceEvent(TRACE_NORMAL, "[%d] fieldId=%d/PEN=%d/len=%d [tot=%d]",
			       1+fieldId, fields[fieldId].fieldId,
			       is_enterprise_specific, fields[fieldId].fieldLen, len);
#endif
		  }

		  template.flowsetLen = len;
		}
	      } else {
		/* NetFlow */
		fields = (V9V10TemplateField*)malloc(template.fieldCount * sizeof(V9V10TemplateField));
		if(fields == NULL) {
		  traceEvent(TRACE_WARNING, "Not enough memory");
		  break;
		}

		goodTemplate = 1;
		template.flowsetLen = 4 * template.fieldCount;

#ifdef DEBUG_FLOWS
		traceEvent(TRACE_NORMAL, "Template [id=%d] fields: %d", template.templateId, template.fieldCount);
#endif

		/* Check the template before handling it */
		for(fieldId=0;fieldId < template.fieldCount; fieldId++) {
		  V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		  fields[fieldId].fieldId = htons(set->templateId);
		  fields[fieldId].fieldLen = htons(set->flowsetLen);
		  fields[fieldId].isPenField = (fields[fieldId].fieldId >= NTOP_BASE_ID) ? 1 : 0;
		  len += 4; /* Field Type (2) + Field Length (2) */
		  accumulatedLen +=  fields[fieldId].fieldLen;
#ifdef DEBUG_FLOWS
		  if(1)
		    traceEvent(TRACE_NORMAL, "[%d] fieldId=%d (%s)/fieldLen=%d/totLen=%d/templateLen=%d",
			       1+fieldId, fields[fieldId].fieldId,
			       getStandardFieldId(fields[fieldId].fieldId), fields[fieldId].fieldLen,
			       accumulatedLen, len);
#endif
		}
	      }
	    }

	    if(template.flowsetLen > 1500) {
	      goodTemplate = 0;
	    }

	    pthread_rwlock_wrlock(&readWriteGlobals->collectorRwLock);

	    if(goodTemplate) {
	      readWriteGlobals->collectionStats.num_good_templates_received++;

	      if(template.templateId < 512) {
		/* Direct template access */
		cursor = readWriteGlobals->up_to_512_templates[template.templateId];
	      } else {
		/* Sequential list access */
		cursor = readWriteGlobals->over_512_templates;

		while(cursor != NULL) {
		  if(cursor->templateInfo.templateId == template.templateId) {
		    break;
		  } else
		    cursor = cursor->next;
		}
	      }

	      if(cursor != NULL) {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> Redefined existing template [id=%d]",
			   template.templateId);
#endif

		free(cursor->fields);
	      } else {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> Found new flow template definition [id=%d]", template.templateId);
#endif

		cursor = (FlowSetV9Ipfix*)malloc(sizeof(FlowSetV9Ipfix));
		if(template.templateId < 512)
		  readWriteGlobals->up_to_512_templates[template.templateId] = cursor, cursor->next = NULL;
		else {
		  cursor->next = readWriteGlobals->over_512_templates;
		  readWriteGlobals->over_512_templates = cursor;
		}
	      }

	      cursor->templateInfo.flowsetLen = len + sizeof(header);
	      cursor->templateInfo.templateId = template.templateId;
	      cursor->templateInfo.fieldCount = template.fieldCount;
	      cursor->templateInfo.v9ScopeLen = template.v9ScopeLen;
	      cursor->templateInfo.scopeFieldCount  = template.scopeFieldCount;
	      cursor->templateInfo.isOptionTemplate = template.isOptionTemplate;
	      cursor->flowLen                 = accumulatedLen;
	      cursor->fields                  = fields;

#ifdef DEBUG_FLOWS
	      traceEvent(TRACE_INFO, ">>>>> Defined flow template [id=%d][flowLen=%d][fieldCount=%d]",
			 cursor->templateInfo.templateId,
			 cursor->flowLen, cursor->templateInfo.fieldCount);
#endif

	      readWriteGlobals->collectionStats.num_known_templates++;
	    } else {
#ifdef DEBUG_FLOWS
	      traceEvent(TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
#endif
	      readWriteGlobals->collectionStats.num_bad_templates_received++;
	    }
	    pthread_rwlock_unlock(&readWriteGlobals->collectorRwLock);

	    displ += len, stillToProcess -= len;

#ifdef DEBUG_FLOWS
	    traceEvent(TRACE_INFO, "Moving %d bytes forward: new offset is %d [stillToProcess=%d]", len, displ, stillToProcess);
#endif
	    if(stillToProcess < 4)  {
	      /* Pad */
	      displ += stillToProcess;
	      stillToProcess = 0;
	    }

	    if(stillToProcess <= 0) templateDone = 1;
	  }
	}
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(TRACE_INFO, "Found FlowSet [displ=%d]", displ);
#endif
	foundRecord = 1;
      }

      if(foundRecord) {
	V9FlowSet fs;

	if(bufferLen > (displ+sizeof(V9FlowSet))) {
	  FlowSetV9Ipfix *cursor;
	  u_short tot_len = 4;  /* 4 bytes header */

	  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

	  fs.flowsetLen = ntohs(fs.flowsetLen);
	  fs.templateId = ntohs(fs.templateId);

	  pthread_rwlock_rdlock(&readWriteGlobals->collectorRwLock);

	  if(fs.templateId < 512) {
	    /* Direct template access */
	    cursor = readWriteGlobals->up_to_512_templates[fs.templateId];
	  } else {
	    /* Sequential list access */
	    cursor = readWriteGlobals->over_512_templates;

	    while(cursor != NULL) {
	      if((cursor->templateInfo.templateId == fs.templateId)
		 && (cursor->templateInfo.netflow_device_ip == netflow_device_ip)) {
		break;
	      } else
		cursor = cursor->next;
	    }
	  }

	  if(cursor != NULL) {
	    /* Template found */
	    int fieldId, init_displ, scopeOffset = (4 * cursor->templateInfo.scopeFieldCount) + cursor->templateInfo.v9ScopeLen;
	    int end_flow;
	    V9V10TemplateField *fields = cursor->fields;
	    u_int32_t multiplier = 1, packet_offset = 0;

	    init_displ = displ + scopeOffset;
	    displ += sizeof(V9FlowSet) + scopeOffset;

#ifdef DEBUG_FLOWS
	    if(1)
	      traceEvent(TRACE_INFO, ">>>>> Rcvd flow with known template %d [%d...%d]",
			 fs.templateId, displ, fs.flowsetLen);
#endif

	    end_flow = init_displ + fs.flowsetLen-scopeOffset;
	    tot_len += scopeOffset;

	    while(displ < end_flow) {
	      u_short accum_len = 0, real_field_len, real_field_len_offset;

	      if(end_flow-displ < 4) break;

	      /* Defaults */
	      memset(&record, 0, sizeof(record));
	      record.vlanId = NO_VLAN; /* No VLAN */
	      record.nw_latency_sec = record.nw_latency_usec = htonl(0);

#ifdef DEBUG_FLOWS
	      if(0) {
		u_int i, begin = displ, end = init_displ + fs.flowsetLen-scopeOffset;

		traceEvent(TRACE_INFO, ">>>>> Stats [%d...%d]", begin, end);

		for(i=begin; i<end; i++)
		  traceEvent(TRACE_INFO, "%02X [%d]", buffer[i] & 0xFF, i);
	      }
#endif

	      for(fieldId=0; fieldId<cursor->templateInfo.fieldCount; fieldId++) {
		if(!(displ < end_flow)) break; /* Flow too short */

		if(handle_ipfix && (fields[fieldId].fieldLen == 65535)) {
		  /* IPFIX Variable lenght field */
		  u_int8_t len8 = buffer[displ];

		  if(len8 < 255)
		    real_field_len = len8, real_field_len_offset = 1;
		  else {
		    u_int16_t len16;

		    memcpy(&len16, &buffer[displ+1], 2);
		    len16 = ntohs(len16);
		    len16 += 1 /* 255 */ + 2 /* len */;
		    real_field_len = len16, real_field_len_offset = 3;
		  }
		} else
		  real_field_len = fields[fieldId].fieldLen, real_field_len_offset = 0;

#ifdef DEBUG_FLOWS
		if(cursor->templateInfo.isOptionTemplate) {
		  traceEvent(TRACE_NORMAL, ">>>>> Dissecting flow field "
			     "[optionTemplate=%d][displ=%d/%d][template=%d][fieldId=%d][fieldLen=%d][isPenField=%d][field=%d/%d] [%d...%d] [accum_len=%d]",
			     cursor->templateInfo.isOptionTemplate, displ, fs.flowsetLen,
			     fs.templateId, fields[fieldId].fieldId,
			     real_field_len,
			     fields[fieldId].isPenField,
			     fieldId, cursor->templateInfo.fieldCount,
			     displ, (init_displ + fs.flowsetLen), accum_len);
		}
#endif


		if(fields[fieldId].isPenField == 0) {
		  switch(fields[fieldId].fieldId) {
		  case 1: /* IN_BYTES Incoming flow bytes (src->dst) */
		    memcpy(&record.sentOctets, &buffer[displ], 4);
		    break;
		  case 2: /* IN_PKTS */
		    memcpy(&record.sentPkts, &buffer[displ], 4);
		    break;
		  case 4: /* PROT */
		    memcpy(&record.proto, &buffer[displ], 1);
		    break;
		  case 5: /* TOS */
		    memcpy(&record.tos, &buffer[displ], 1);
		    break;
		  case 6: /* TCP_FLAGS */
		    memcpy(&record.tcp_flags, &buffer[displ], 1);
		    break;
		  case 7: /* L4_SRC_PORT */
		    memcpy(&record.srcport, &buffer[displ], 2);
		    break;
		  case 8: /* IPV4_SRC_ADDR */
		    record.srcaddr.ipVersion = 4;
		    memcpy(&record.srcaddr.ipType.ipv4, &buffer[displ], 4);
		    break;
		  case 9: /* IPV4_SRC_MASK */
		    memcpy(&record.src_mask, &buffer[displ], 1);
		    break;
		  case 10: /* INPUT_SNMP */
		    if(fields[fieldId].fieldLen == 4) {
		      u_int32_t val;

		      memcpy(&val, &buffer[displ], 4);
		      record.input = htons((u_int16_t)ntohl(val));
		    } else
		      memcpy(&record.input, &buffer[displ], 2);
		    break;
		  case 11: /* L4_DST_PORT */
		    memcpy(&record.dstport, &buffer[displ], 2);
		    break;
		  case 12: /* IPV4_DST_ADDR */
		    record.dstaddr.ipVersion = 4;
		    memcpy(&record.dstaddr.ipType.ipv4, &buffer[displ], 4);
		    break;
		  case 13: /* IPV4_DST_MASK */
		    memcpy(&record.dst_mask, &buffer[displ], 1);
		    break;
		  case 14: /* OUTPUT SNMP */
		    if(fields[fieldId].fieldLen == 4) {
		      u_int32_t val;

		      memcpy(&val, &buffer[displ], 4);
		      record.output = htons((u_int16_t)ntohl(val));
		    } else
		      memcpy(&record.output, &buffer[displ], 2);
		    break;
		  case 15: /* IP_NEXT_HOP */
		    memcpy(&record.nexthop, &buffer[displ], 4);
		    break;
		  case 16: /* SRC_AS */
		    /* Fix for handling 16+32 AS numbers */
		    if(fields[fieldId].fieldLen == 2) {
		      u_int16_t sixteen;
		      u_int32_t thirtytwo;

		      memcpy(&sixteen, &buffer[displ], 2);
		      thirtytwo = ntohs(sixteen);
		      record.src_as = htonl(thirtytwo);
		    } else
		      memcpy(&record.src_as, &buffer[displ], 4);
		    break;
		  case 17: /* DST_AS */
		    /* Fix for handling 16+32 AS numbers */
		    if(fields[fieldId].fieldLen == 2) {
		      u_int16_t sixteen;
		      u_int32_t thirtytwo;

		      memcpy(&sixteen, &buffer[displ], 2);
		      thirtytwo = ntohs(sixteen);
		      record.src_as = htonl(thirtytwo);
		    } else
		      memcpy(&record.dst_as, &buffer[displ], 4);
		    break;
		  case 21: /* LAST_SWITCHED */
		    memcpy(&record.last, &buffer[displ], 4);
		    break;
		  case 22: /* FIRST SWITCHED */
		    memcpy(&record.first, &buffer[displ], 4);
		    break;
		  case 23: /* OUT_BYTES Outgoing flow bytes (dst->src) */
		  case 85: /* NF_F_FLOW_BYTES */
		    memcpy(&record.rcvdOctets, &buffer[displ], 4);

                    if(fields[fieldId].fieldId == 85) {
                      /* In ASA We don't have the number of packets so in order
                         to let ntop not discard this flow we need to put a reasonable
                         value there (avg 512 bytes packet)
		      */
                      record.rcvdPkts = htonl(1 + (ntohl(record.rcvdOctets)/512));
                    }
		    break;
		  case 24: /* OUT_PKTS */
		    memcpy(&record.rcvdPkts, &buffer[displ], 4);
		    break;
		  case 27: /* IPV6_SRC_ADDR */
		    record.srcaddr.ipVersion = 6, memcpy(&record.srcaddr.ipType.ipv6, &buffer[displ], 16);
 		    break;
		  case 28: /* IPV6_DST_ADDR */
		    record.dstaddr.ipVersion = 6, memcpy(&record.dstaddr.ipType.ipv6, &buffer[displ], 16);
		    break;

		  case 58: /* SRC_VLAN */
		  case 59: /* DST_VLAN */
		    memcpy(&record.vlanId, &buffer[displ], 2);
		    record.vlanId = ntohs(record.vlanId);
		    break;

		    /* Cisco */
		  case 102:
		    memcpy(&record.packet_offset, &buffer[displ], 2);
                    record.packet_offset = ntohs(record.packet_offset);
#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[102] packet_offset=%d", record.packet_offset);
#endif
		    break;
		  case 103:
		    memcpy(&record.packet_len, &buffer[displ], 2);
                    record.packet_len = ntohs(record.packet_len);
#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[103] packet_len=%d", record.packet_len);
#endif
		    break;
		  case 104:
		    {
		      if(record.packet_len == 0)
			record.packet_len = min(real_field_len+packet_offset, MAX_PACKET_LEN);

		      if(packet_offset > 0) memset(record.packet, 0, packet_offset);
		      memcpy(&record.packet[packet_offset], &buffer[displ+real_field_len_offset], record.packet_len);
#ifdef CISCO_DEBUG
		      traceEvent(TRACE_NORMAL, "[104] packet found [len=%d][packet_offset=%d][real_field_len_offset=%d] [%02X %02X %02X]",
				 record.packet_len, packet_offset, real_field_len_offset,
				 record.packet[0], record.packet[1], record.packet[2]);
#endif
		    }
		    break;

		  case 300:
		    memcpy(&record.observationPointId, &buffer[displ], 4);
		    record.observationPointId = htonl(record.observationPointId);
#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[300] observationPointId=%d", record.observationPointId);
#endif
		    break;

		  case 302:
		    memcpy(&record.selectorId, &buffer[displ], 2);
		    record.selectorId = htons(record.selectorId);
		    record.hasSampling++;

		  if(record.hasSampling) {
		    SelectorsList *head = readWriteGlobals->selectors;

#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "Searching selectorId = %d", record.selectorId);
#endif

		    while(head) {
		      // traceEvent(TRACE_NORMAL, "%d <-> %d", head->selectorId, record.selectorId);
		      
		      if((head->selectorId == record.selectorId)
			 && (head->netflow_device_ip == netflow_device_ip)) {
			multiplier = head->samplingPopulation, packet_offset = head->packet_offset;
#ifdef CISCO_DEBUG
			traceEvent(TRACE_NORMAL, "multiplier = %d / packet_offset = %d", multiplier, packet_offset);
#endif
			break;
		      } else {
			head = head->next;
		      }
		    } /* while */		    
		  }

#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[302] selectorId=%d [%02X %02X]",
			       record.selectorId,
			       buffer[displ] & 0xFF, buffer[displ+1] & 0xFF);
#endif
		    break;

		  case 310:
		    memcpy(&record.samplingPopulation, &buffer[displ], 4);
		    record.samplingPopulation = htonl(record.samplingPopulation);

		    if(record.samplingPopulation == 0xFFFFFFFF) {
#ifdef CISCO_DEBUG
		      traceEvent(TRACE_WARNING, "Found samplingPopulation=%04X for selectorId %d: round it to 1", 
				 record.samplingPopulation, record.selectorId);
#endif
		      record.samplingPopulation = 1;
		    }

		    record.hasSampling++;
#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[310] samplingPopulation=%d [%02X %02X %02X %02X]",
			       record.samplingPopulation,
			       buffer[displ] & 0xFF, buffer[displ+1] & 0xFF,
			       buffer[displ+2] & 0xFF, buffer[displ+3] & 0xFF);
#endif
		    break;

		  case 312:
		    memcpy(&record.original_packet_len, &buffer[displ], 2);
		    record.original_packet_len = htons(record.original_packet_len);
#ifdef CISCO_DEBUG
		    traceEvent(TRACE_NORMAL, "[312] original_packet_len=%d", record.original_packet_len);
#endif
		    break;
		  }
		} else {
		  /* PEN fields */
		  switch(fields[fieldId].fieldId) {
		  case NTOP_BASE_ID+82: /* NW_LATENCY_SEC */
		    memcpy(&record.nw_latency_sec, &buffer[displ], 4);
		    break;
		  case NTOP_BASE_ID+83: /* NW_LATENCY_USEC */
		    memcpy(&record.nw_latency_usec, &buffer[displ], 4);
		    break;

		    /* VoIP Extensions */
		  case NTOP_BASE_ID+130: /* SIP_CALL_ID */
		    memcpy(&record.sip_call_id, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
		    traceEvent(TRACE_INFO, "SIP: sip_call_id=%s", record.sip_call_id);
#endif
		    break;
		  case NTOP_BASE_ID+131: /* SIP_CALLING_PARTY */
		    memcpy(&record.sip_calling_party, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
		    traceEvent(TRACE_INFO, "SIP: sip_calling_party=%s", record.sip_calling_party);
#endif
		    break;
		  case NTOP_BASE_ID+132: /* SIP_CALLED_PARTY */
		    memcpy(&record.sip_called_party, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
		    traceEvent(TRACE_INFO, "SIP: sip_called_party=%s", record.sip_called_party);
#endif
		    break;
		  }
		}

		accum_len += real_field_len+real_field_len_offset, displ += real_field_len+real_field_len_offset;
	      } /* for */

	      if(cursor->templateInfo.isOptionTemplate) {
		if(record.hasSampling == 2) {
		  SelectorsList *prev = NULL, *head = readWriteGlobals->selectors, *found = NULL;

		  while(head) {
		    if((head->selectorId == record.selectorId)
		       && (head->netflow_device_ip == netflow_device_ip)) {
		      found = head;
		      break;
		    } else if(head->selectorId > record.selectorId) {
		      break;
		    } else {
		      prev = head;
		      head = head->next;
		    }
		  } /* while */

		  if(found == NULL) {
		    /* Not found */
		    SelectorsList *selector = (SelectorsList*)malloc(sizeof(SelectorsList));

		    if(selector) {
		      selector->selectorId = record.selectorId, selector->samplingPopulation = record.samplingPopulation;
		      selector->packet_offset = record.packet_offset, selector->netflow_device_ip = netflow_device_ip, selector->next = head;

#ifdef CISCO_DEBUG
		      if(1)
			traceEvent(TRACE_NORMAL, "Adding selectorId=%u,samplingPopulation=%u",
				   selector->selectorId, selector->samplingPopulation);
#endif

		      if(prev == NULL)
			readWriteGlobals->selectors = selector;
		      else
			prev->next = selector;
		    } else {
		      traceEvent(TRACE_WARNING, "Not enough memory");
		    }
		  } else
		    found->samplingPopulation = record.samplingPopulation;
		}

		tot_len += accum_len;
	      } else {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO,
			   ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d][packet_len=%d]",
			   accum_len, record.packet_len);
#endif

		if(record.packet_len > 0) {
		  struct pcap_pkthdr pkthdr;

		  pkthdr.ts.tv_sec = time(NULL);
		  pkthdr.ts.tv_usec = 0;
		  pkthdr.caplen = record.packet_len;
		  pkthdr.len = max(record.packet_len, record.original_packet_len);

#ifdef CISCO_DEBUG
		  traceEvent(TRACE_NORMAL,
			     "[CISCO] Received pkt %d [len: caplen=%d/len=%d][offset: %d][multiplier=%d][observationPointId: %d][selectorId: %d][interfaces: %d->%d]",
			     readWriteGlobals->collectionStats.num_dissected_flow_packets,
			     pkthdr.caplen, pkthdr.len, packet_offset,
			     multiplier, record.observationPointId, record.selectorId,
			     ntohs(record.input), ntohs(record.output));
#endif

		  // traceEvent(TRACE_INFO, "Packet len: %u", record.packet_len);

		  decodePacket(&pkthdr, record.packet, 
			       1 /* sampledPacket */, (multiplier == 0) ? 1 : multiplier,
			       ntohs(record.input), ntohs(record.output),
			       ntohl(netflow_device_ip)); /* Pass the packet to nProbe */

		  tot_len += accum_len;
		} else {
		  /*
		    IMPORTANT NOTE

		    handleGenericFlow handles monodirectional flows, whereas
		    v9 flows and bidirectional. This means that if there's some
		    bidirectional traffic, handleGenericFlow is called twice.
		  */
		  deEndianRecord(&record); /* This must be called once per handleGenericFlow() call */

		  handleGenericFlow(netflow_device_ip, recordActTime, recordSysUpTime, &record);

#ifdef DEBUG_FLOWS
		  traceEvent(TRACE_INFO,
			     ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d]",
			     accum_len);
#endif

		  tot_len += accum_len;

		  if(record.rcvdPkts > 0) {
		    IpAddress tmp_addr;
		    u_int16_t tmp_port;
		    u_int32_t tmp_pkts, tmp_bytes;

		    /* Swap records */
		    tmp_pkts = record.sentPkts, tmp_bytes = record.sentOctets;
		    record.sentPkts = record.rcvdPkts, record.sentOctets = record.rcvdOctets;
		    record.rcvdPkts = tmp_pkts, record.sentOctets = tmp_bytes;

		    memcpy(&tmp_addr, &record.srcaddr, sizeof(IpAddress));
		    memcpy(&record.srcaddr, &record.dstaddr, sizeof(IpAddress));
		    memcpy(&record.dstaddr, &tmp_addr, sizeof(IpAddress));

		    tmp_port = record.srcport;
		    record.srcport = record.dstport;
		    record.dstport = tmp_port;

		    handleGenericFlow(netflow_device_ip, recordActTime, recordSysUpTime, &record);
		  }
		}
	      }
	    } /* while */

#ifdef DEBUG_FLOWS
	    traceEvent(TRACE_INFO, ">>>>> tot_len=%d / fs.flowsetLen=%d", tot_len, fs.flowsetLen);
#endif

	    if(tot_len < fs.flowsetLen) {
	      u_short padding = fs.flowsetLen - tot_len;

	      if(padding > 4) {
		traceEvent(TRACE_WARNING,
			   "Template len mismatch [tot_len=%d][flow_len=%d][padding=%d][num_dissected_flow_packets=%d]",
			   tot_len, fs.flowsetLen, padding, readWriteGlobals->collectionStats.num_dissected_flow_packets);
	      } else {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> %d bytes padding [tot_len=%d][flow_len=%d]",
			   padding, tot_len, fs.flowsetLen);
#endif
		displ += padding;
	      }
	    }
	  } else {
#ifdef DEBUG_FLOWS
	    traceEvent(TRACE_NORMAL, ">>>>> Rcvd flow with UNKNOWN template %d [displ=%d][len=%d]",
		       fs.templateId, displ, fs.flowsetLen);
#endif
	    readWriteGlobals->collectionStats.num_flows_unknown_template++;
	    displ += fs.flowsetLen;
	  }

	  pthread_rwlock_unlock(&readWriteGlobals->collectorRwLock);
	}
      }
    } /* for */
  } else if(the5Record.flowHeader.version == htons(5)) {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    recordActTime   = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);

    if(numFlows > V5FLOWS_PER_PAK) numFlows = V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    if(1) traceEvent(TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);
#endif

    /*
      Reset the record so that fields that are not contained
      into v5 records are set to zero
    */
    memset(&record, 0, sizeof(record));
    record.vlanId = NO_VLAN; /* No VLAN */
    record.nw_latency_sec = record.nw_latency_usec = htonl(0);

    for(i=0; i<numFlows; i++) {
      record.srcaddr.ipType.ipv4 = the5Record.flowRecord[i].srcaddr, record.srcaddr.ipVersion = 4;
      record.dstaddr.ipType.ipv4 = the5Record.flowRecord[i].dstaddr, record.dstaddr.ipVersion = 4;
      record.nexthop    = the5Record.flowRecord[i].nexthop;
      record.input      = the5Record.flowRecord[i].input;
      record.output     = the5Record.flowRecord[i].output;
      record.sentPkts   = the5Record.flowRecord[i].dPkts;
      record.sentOctets = the5Record.flowRecord[i].dOctets;
      record.first      = the5Record.flowRecord[i].first;
      record.last       = the5Record.flowRecord[i].last;
      record.tos        = the5Record.flowRecord[i].tos;
      record.srcport    = the5Record.flowRecord[i].srcport;
      record.dstport    = the5Record.flowRecord[i].dstport;
      record.tcp_flags  = the5Record.flowRecord[i].tcp_flags;
      record.proto      = the5Record.flowRecord[i].proto;
      record.dst_as     = htonl(ntohs(the5Record.flowRecord[i].dst_as));
      record.src_as     = htonl(ntohs(the5Record.flowRecord[i].src_as));
      record.dst_mask   = the5Record.flowRecord[i].dst_mask;
      record.src_mask   = the5Record.flowRecord[i].src_mask;

      deEndianRecord(&record);
      handleGenericFlow(netflow_device_ip, recordActTime,
			recordSysUpTime, &record);
    }
  }
}

/* ********************************************************* */

void* netFlowCollectLoop(void* notUsed) {
  fd_set netflowMask;
  int rc, len;
#ifdef DEBUG_FLOWS
  int deviceId = 0;
#endif
  u_char buffer[2048];
  struct sockaddr_in fromHost;
  unsigned long thread_id = (unsigned long)notUsed;

  /* traceEvent(TRACE_NORMAL, "netFlowMainLoop(%u) thread...", thread_id); */

  readOnlyGlobals.datalink = DLT_EN10MB;

  while(!readWriteGlobals->shutdownInProgress) {
    int maxSock = readOnlyGlobals.collectorInSocket;

    FD_ZERO(&netflowMask);
    FD_SET(readOnlyGlobals.collectorInSocket, &netflowMask);

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0) {
      FD_SET(readOnlyGlobals.collectorInSctpSocket, &netflowMask);
      if(readOnlyGlobals.collectorInSctpSocket > maxSock)
	maxSock = readOnlyGlobals.collectorInSctpSocket;
    }
#endif

    rc = select(maxSock+1, &netflowMask, NULL, NULL, NULL);
    if(readWriteGlobals->shutdownInProgress) break;

    if(rc > 0) {
      if(FD_ISSET(readOnlyGlobals.collectorInSocket, &netflowMask)){
	len = sizeof(fromHost);
	rc = recvfrom(readOnlyGlobals.collectorInSocket,
		      (char*)&buffer, sizeof(buffer),
		      0, (struct sockaddr*)&fromHost, (socklen_t*)&len);
      }
#ifdef HAVE_SCTP
      else {
	struct msghdr msg;
	struct iovec iov[2];
	char controlVector[256];

	memset(controlVector, 0, sizeof(controlVector));
	iov[0].iov_base = buffer;
	iov[0].iov_len  = sizeof(buffer);
	iov[1].iov_base = NULL;
	iov[1].iov_len  = 0;
	msg.msg_name = (caddr_t)&fromHost;
	msg.msg_namelen = sizeof(fromHost);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
#ifndef SOLARIS
	msg.msg_control = (caddr_t)controlVector;
	msg.msg_controllen = sizeof(controlVector);
#endif
	rc = recvmsg(readOnlyGlobals.collectorInSctpSocket, &msg, 0);
      }
#endif

#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
		 rc,  deviceId);
#endif

      if(rc > 0) {
#ifdef MAX_NETFLOW_PACKET_BUFFER
        gettimeofday(&netflowStartOfRecordProcessing, NULL);
#endif

	readWriteGlobals->now = time(NULL), readWriteGlobals->collectedPkts[thread_id]++;

	if((buffer[0] == '\0') && (buffer[1] == '\0'))
	  dissectSflow(buffer, rc, &fromHost); /* sFlow */
	else
	  dissectNetFlow(fromHost.sin_addr.s_addr, (char*)buffer, rc);

#ifdef DEBUG
	traceEvent(TRACE_NORMAL, "Received %d flows", readOnlyGlobals.num_collected_pkts);

	if(readOnlyGlobals.num_collected_pkts == 100) {
	  readWriteGlobals->shutdownInProgress = 1; /* DEBUG */
	  cleanup();
	}
#endif
      }
    }
  }

  return(NULL);
}
