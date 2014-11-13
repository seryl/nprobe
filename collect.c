/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2007-14 Luca Deri <deri@ntop.org>
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

#define DEBUG_FLOWS
//#define CISCO_DEBUG
#define LEN_SMALL_WORK_BUFFER 2048


/* forward */
void* netFlowCollectLoop(void* notUsed);

/* ********************************************************* */

/*
   Cisco ASA
   http://www.cisco.com/en/US/docs/security/asa/asa81/netflow/netflow.html#wp1028202
*/

/* ********************************************************* */

int createNetFlowListener(u_int16_t collectorInPort) {
  int sockopt = 1;
  struct sockaddr_in sockInV4;
  struct sockaddr_in6 sockInV6;

  readWriteGlobals->collectionStats.num_dissected_flow_packets = 0;
  readOnlyGlobals.collectorInSocketv4 = readOnlyGlobals.collectorInSocketv6 = readOnlyGlobals.collectorInSctpSocket = -1;
  readWriteGlobals->v9_ipfix_templates = NULL;

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
	readOnlyGlobals.numCollectors = 0;
	return(-1);
      }
    }

    errno = 0;
    readOnlyGlobals.collectorInSocketv4 = socket(AF_INET, SOCK_DGRAM, 0);
    if((readOnlyGlobals.collectorInSocketv4 < 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDPv4 socket - returned %d, error is '%s'(%d)",
		 readOnlyGlobals.collectorInSocketv4, strerror(errno), errno);
      return(-1);
    } else
      maximize_socket_buffer(readOnlyGlobals.collectorInSocketv4, SO_RCVBUF);

    errno = 0;
    readOnlyGlobals.collectorInSocketv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if((readOnlyGlobals.collectorInSocketv6 < 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDPv6 socket - returned %d, error is '%s'(%d); IPv6 disabled",
		 readOnlyGlobals.collectorInSocketv6, strerror(errno), errno);
      readOnlyGlobals.collectorInSocketv6 = 0;
    } else
      maximize_socket_buffer(readOnlyGlobals.collectorInSocketv6, SO_RCVBUF);

#ifdef HAVE_SCTP
    errno = 0;
    readOnlyGlobals.collectorInSctpSocket = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

    if((readOnlyGlobals.collectorInSctpSocket < 0) || (errno != 0)) {
      traceEvent(TRACE_INFO, "Unable to create a SCTP socket - returned %d, error is '%s'(%d); SCTP disabled",
		 readOnlyGlobals.collectorInSocketv4, strerror(errno), errno);
    }
#endif

    traceEvent(TRACE_INFO, "Created UDP sockets");

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0)
      traceEvent(TRACE_INFO, "Created a SCTP socket (%d)", readOnlyGlobals.collectorInSctpSocket);
#endif

    setsockopt(readOnlyGlobals.collectorInSocketv4, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    if(readOnlyGlobals.collectorInSocketv6 > 0)
      setsockopt(readOnlyGlobals.collectorInSocketv6, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockInV4.sin_family            = AF_INET;
    sockInV4.sin_port              = (int)htons(collectorInPort);
    sockInV4.sin_addr.s_addr       = INADDR_ANY;

    memset(&sockInV6, 0, sizeof(sockInV6));
#ifdef HAVE_SIN6_LEN
#ifndef WIN32
    sockInV6.sin6_len    = sizeof(struct sockaddr_in6);
#endif
#endif

    sockInV6.sin6_family = AF_INET6;
    sockInV6.sin6_port = htons(collectorInPort);
    sockInV6.sin6_addr = in6addr_any;

    if((bind(readOnlyGlobals.collectorInSocketv4, (struct sockaddr *)&sockInV4, sizeof(sockInV4)) < 0)
       || ((readOnlyGlobals.collectorInSocketv6 > 0)
	   && (bind(readOnlyGlobals.collectorInSocketv6, (struct sockaddr *)&sockInV6, sizeof(sockInV6)) < 0))
#ifdef HAVE_SCTP
       || ((readOnlyGlobals.collectorInSctpSocket > 0)
	   && (bind(readOnlyGlobals.collectorInSctpSocket, (struct sockaddr *)&sockInV4, sizeof(sockInV4)) < 0))
#endif
       ) {
      traceEvent(TRACE_ERROR, "Flow collector UDP port %d already in use ? [%s/%d]",
		 collectorInPort, strerror(errno), errno);
      close(readOnlyGlobals.collectorInSocketv4);
      readOnlyGlobals.collectorInSocketv4 = 0;

      if(readOnlyGlobals.collectorInSocketv6 > 0)
	close(readOnlyGlobals.collectorInSocketv6);

      readOnlyGlobals.collectorInSocketv6 = 0;
#ifdef HAVE_SCTP
      if(readOnlyGlobals.collectorInSctpSocket) close(readOnlyGlobals.collectorInSctpSocket);
      readOnlyGlobals.collectorInSctpSocket = 0;
#endif
      exit(0);
    }

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0) {
      if(listen(readOnlyGlobals.collectorInSctpSocket, 100) == -1) {
	traceEvent(TRACE_ERROR, "Listen on SCTP socket failed [%s]", strerror(errno));
      }
    }
#endif

    traceEvent(TRACE_NORMAL, "Flow collector listening on port %d (IPv4/v6)", collectorInPort);

    for(i=0; i<readOnlyGlobals.numProcessThreads; i++) {
      unsigned long id = i;

      pthread_create(&readOnlyGlobals.collectThread[i], NULL, netFlowCollectLoop, (void*)id);
    }
  }

  return(0);
}

/* ********************************************************* */

void closeNetFlowListener() {
  if(readOnlyGlobals.collectorInSocketv4 != -1)   close(readOnlyGlobals.collectorInSocketv4);
  if(readOnlyGlobals.collectorInSctpSocket != -1) close(readOnlyGlobals.collectorInSctpSocket);
}

/* ********************************************************* */

static void deEndianRecord(struct generic_netflow_record *record) {
  record->last = ntohl(record->last), record->first = ntohl(record->first);

  if(record->srcaddr.ipVersion == 4) {
    record->srcaddr.ipType.ipv4 = ntohl(record->srcaddr.ipType.ipv4);
    record->dstaddr.ipType.ipv4 = ntohl(record->dstaddr.ipType.ipv4);
    record->nexthop.ipType.ipv4 = ntohl(record->nexthop.ipType.ipv4);
  }

  record->sentPkts = ntohl(record->sentPkts), record->rcvdPkts = ntohl(record->rcvdPkts);
  record->srcport = ntohs(record->srcport), record->dstport = ntohs(record->dstport);
  record->sentOctets = ntohl(record->sentOctets), record->rcvdOctets = ntohl(record->rcvdOctets);
  record->input = ntohs(record->input), record->output = ntohs(record->output);
  record->src_as = htonl(record->src_as), record->dst_as = htonl(record->dst_as);
  record->icmpType = ntohs(record->icmpType);
}

/* *************************** */

static u_int8_t _matchAS(u_int32_t as, ASlist *l) {
  while(l != NULL)
    if(l->asn == as) return(1); else l = l->next;

  return(0);
}

/* *************************** */

static u_int8_t matchAS(struct generic_netflow_record *record, ASlist *l) {
  return(_matchAS(record->dst_as, l) || _matchAS(record->src_as, l));
}

/* *************************** */

static u_int8_t _matchPrefix(IpAddress *addr, NetList *l) {
  if(addr->ipVersion != 4) return(0); /* IPv4 only so far */

  while(l != NULL) {
    if(l->net == (addr->ipType.ipv4 & l->mask))
      return(1);
    else
      l = l->next;
  }

  return(0);
}

/* *************************** */

static u_int8_t matchPrefix(struct generic_netflow_record *record, NetList *l) {
  return(_matchPrefix(&record->srcaddr, l) || _matchPrefix(&record->dstaddr, l));
}

/* *************************** */

static void handleGenericFlow(u_int16_t thread_id, u_int32_t netflow_device_ip,
			      u_int32_t recordActTime, u_int32_t recordSysUpTime,
			      struct generic_netflow_record *record) {
  struct pcap_pkthdr h;
  u_int32_t firstSeen, lastSeen;
  u_int32_t initTime, subflow_id;
  u_int8_t found;
  FlowHashBucket *bkt = NULL;

  if(readOnlyGlobals.flowCollection.keepProbesUnmerged)
    subflow_id = netflow_device_ip;
  else
    subflow_id = 0;

  /* Check if there are some ingress filters applied */
  if(readOnlyGlobals.flowCollection.not_as_list
     || readOnlyGlobals.flowCollection.as_list) {
    if(readOnlyGlobals.flowCollection.not_as_list
       && matchAS(record, readOnlyGlobals.flowCollection.not_as_list)) {
    flow_discard:
      //traceEvent(TRACE_INFO, "Discarding ingress flow");
      return;
    }

    if(readOnlyGlobals.flowCollection.as_list
       && (!matchAS(record, readOnlyGlobals.flowCollection.as_list))) {
      goto flow_discard;
    }
  }

  if(readOnlyGlobals.flowCollection.not_prefix_list
     || readOnlyGlobals.flowCollection.prefix_list) {
    if(readOnlyGlobals.flowCollection.not_prefix_list
       && matchPrefix(record, readOnlyGlobals.flowCollection.not_prefix_list)) {
      goto flow_discard;
    }

    if(readOnlyGlobals.flowCollection.prefix_list
       && (!matchPrefix(record, readOnlyGlobals.flowCollection.prefix_list))) {
      goto flow_discard;
    }
  }

  pthread_rwlock_wrlock(&readWriteGlobals->collectorCounterLock);
  readWriteGlobals->collectionStats.num_flows_processed++;
  pthread_rwlock_unlock(&readWriteGlobals->collectorCounterLock);

  if((record->firstEpoch > 0) && (record->lastEpoch > 0)) {
    firstSeen = ntohl(record->firstEpoch), lastSeen = ntohl(record->lastEpoch);
    if(((firstSeen < 1300618407 /* Dummy date */) || (lastSeen < 1300618407 /* Dummy date */))){
      time_t now = time(NULL);

      firstSeen = now - (lastSeen - firstSeen);
      lastSeen = now;
    }
  } else {
    initTime = recordActTime-(recordSysUpTime/1000);
    /* No need to call ntohl() below as this has already been done by deEndianRecord */
    firstSeen = (record->first/1000) + initTime;
    lastSeen  = (record->last/1000) + initTime;
  }

  /* Sanity check */
  if(readOnlyGlobals.initialSniffTime.tv_sec == 0) {
    // readOnlyGlobals.initialSniffTime.tv_sec = firstSeen, readOnlyGlobals.initialSniffTime.tv_usec = 0;
    readOnlyGlobals.initialSniffTime.tv_sec = time(NULL), readOnlyGlobals.initialSniffTime.tv_usec = 0;
  }

#if 0
  /*
    The check below has been removed as if the router and
    the collector PC are not in sync, we'll end up
    overwriting all the timestamps
  */
  if(firstSeen < readOnlyGlobals.initialSniffTime.tv_sec)
    readOnlyGlobals.initialSniffTime.tv_sec = firstSeen, readOnlyGlobals.initialSniffTime.tv_usec = 0;
#endif

  memset(&h, 0, sizeof(h));
  // h.ts.tv_sec = readWriteGlobals->now;
  h.ts.tv_sec = lastSeen;

  /* We avoid that probes with bad time spoil our probe */
  if(h.ts.tv_sec > readWriteGlobals->now)
    h.ts.tv_sec = readWriteGlobals->now;

#if 0
  traceEvent(TRACE_INFO,
	     "Called addPktToHash() [firstSeen=%u][lastSeen=%u][initial=%u]",
	     firstSeen, lastSeen, readOnlyGlobals.initialSniffTime.tv_sec);
#endif

  record->first = record->last = h.ts.tv_sec;

  /* In ASA or other units sometimes the number of packets is not emitted and thus we need to guess it */
  if((record->sentPkts == 0) && (record->sentOctets > 0))
    record->sentPkts = max(1, record->sentOctets / 512); /* We assume packet size ~512 bytes */

  if((record->rcvdPkts == 0) && (record->rcvdOctets > 0))
    record->rcvdPkts = max(1, record->rcvdOctets / 512); /* We assume packet size ~512 bytes */

  if(record->sentPkts && record->sentOctets)
    bkt = processFlowPacket(thread_id,
			    -1 /* Unknown input interface */,
			    1 /* RX packet */,
			    subflow_id, record->proto,
			    0 /* no fragments */,
			    0 /* unknown ip_offset */,
			    0 /* no sample */,
			    record->sentPkts,
			    record->tos,
			    record->maxTTL,
			    record->vlanId,
			    0, /* tunnel_id */
			    0, /* gtp offset */
			    NULL, /* Ethernet */
			    &record->srcaddr,
			    record->srcport,
			    &record->dstaddr,
			    record->dstport,
			    0, NULL, 0, NULL, 0, /* Tunnel info */
			    record->sentOctets,
			    record->tcp_flags,
			    0 /* TCP Win */, 0, /* TCP seq num */ 0 /* TCP ack num */,
			    0 /* TCP MSS */, 0 /* TCP win scale */,
			    record->icmpType,
			    0,
			    0, NULL, /* MPLS */
			    record->input, record->output,
			    &h, NULL, 0, 0, 0, /* payload */
			    firstSeen,
			    record->src_as, record->dst_as,
			    record->src_mask, record->dst_mask,
			    netflow_device_ip, 0,
			    record->engine_type, record->engine_id,
			    NULL, NULL, record);
  else if(!(record->rcvdPkts && record->rcvdOctets))
    traceEvent(TRACE_INFO, "Received flow with invalid count [sentPkts: %u][sentOctets: %u]: discarded [num_flows: %u]",
	       record->sentPkts, record->sentOctets,
	       readWriteGlobals->collectionStats.num_dissected_flow_packets);

  if(record->rcvdPkts && record->rcvdOctets) {
    bkt = processFlowPacket(thread_id,
			    -1 /* Unknown input interface */,
			    1 /* RX packet */,
			    subflow_id, record->proto,
			    0 /* no fragments */,
			    0 /* unknown ip_offset */,
			    0 /* no sample */,
			    record->rcvdPkts,
			    record->tos,
			    0, /* ttl */
			    record->vlanId,
			    0, /* tunnel_id */
			    0, /* gtp offset */
			    NULL, /* Ethernet */
			    &record->dstaddr,
			    record->dstport,
			    &record->srcaddr,
			    record->srcport,
			    0, NULL, 0, NULL, 0, /* Tunnel info */
			    record->rcvdOctets,
			    record->tcp_flags,
			    0 /* TCP Win */, 0, /* TCP seq num */ 0, /* TCP ack num */
			    0 /* TCP MSS */, 0 /* TCP win scale */,
			    record->icmpType,
			    0,
			    0, NULL, /* MPLS */
			    record->output, record->input,
			    &h, NULL, 0, 0, 0, /* payload */
			    firstSeen,
			    record->dst_as, record->src_as,
			    record->dst_mask, record->src_mask,
			    netflow_device_ip, 0,
			    record->engine_type, record->engine_id,
			    NULL, NULL, record);
  } else if(record->rcvdPkts || record->rcvdOctets)
    traceEvent(TRACE_INFO, "Received flow with invalid count [rcvdPkts: %u][rcvdOctets: %u]: discarded [num_flows: %u]",
	       record->rcvdPkts, record->rcvdOctets,
	       readWriteGlobals->collectionStats.num_dissected_flow_packets);

  if(bkt && bkt->ext && record->nexthop.ipVersion) {
    if(bkt->ext->nextHop.ipVersion == 0) /* Not yet set */
      memcpy(&bkt->ext->nextHop, &record->nexthop, sizeof(IpAddress));
  }  

  /*
    NOTE

    idleThreadTask() must be called after we have manipulated
    the bkt pointer as in case --disable-cache is used, it might
    have been freed by idleThreadTask() and thus the bkt pointer
    would be invalid
  */
  idleThreadTask(thread_id, 4);
}

/* ********************************************************* */

static u_int32_t getField3264to32(V9V10TemplateField *field, char *buffer, u_int32_t divide_by) {
  u_int32_t val32;
  u_int64_t val64;

  switch(field->fieldLen) {
  case 4:
    memcpy(&val32, buffer, 4);
    break;
  case 8:
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "%02X %02X %02X %02X %02X %02X %02X %02X\n",
		 buffer[0] & 0xFF, buffer[1] & 0xFF, buffer[2] & 0xFF, buffer[3] & 0xFF,
		 buffer[4] & 0xFF, buffer[5] & 0xFF, buffer[6] & 0xFF, buffer[7] & 0xFF);

    memcpy(&val64, buffer, 8);

    val64 = _ntohll(val64) / divide_by;
    val32 = htonl((u_int32_t)val64); /* Re-endian */
    break;
  default:
    traceEvent(TRACE_WARNING, "Field %d has unknown length %d",
               field->fieldId, field->fieldLen);
    val32 = 0;
  }

  return(val32);
}

/* ********************************************************* */

u_int8_t dissectCustomField(struct generic_netflow_record *record,
			    char *buffer, int bufferLen,
			    u_int16_t displ, V9V10TemplateField *field,
			    u_int32_t netflow_device_ip,
			    u_int32_t *multiplier,
			    u_int32_t *packet_offset,
			    u_int8_t *skip_flow) {
  u_int32_t fieldId, len;
  
  switch(field->enterpriseId) {
  case 3054: /* IXIA */
    fieldId = 35822+field->fieldId;
    break;

  case 35632: /* ntop */
    fieldId = NTOP_BASE_ID+field->fieldId;
    break;
   
  default:
    fieldId = field->fieldId;
    break;
  }

#if 0
  traceEvent(TRACE_NORMAL, "%s() %u->%u [%u]",
	     __FUNCTION__, field->fieldId, fieldId, field->enterpriseId);
#endif

  switch(fieldId) {
  case 300:
    memcpy(&record->cisco.observationPointId, &buffer[displ], 4);
    record->cisco.observationPointId = htonl(record->cisco.observationPointId);
#ifdef CISCO_DEBUG
    traceEvent(TRACE_NORMAL, "[300] observationPointId=%d", record->cisco.observationPointId);
#endif
    break;

  case 302:
    memcpy(&record->cisco.selectorId, &buffer[displ], 2);
    record->cisco.selectorId = htons(record->cisco.selectorId);
    record->cisco.hasSampling++;

    if(record->cisco.hasSampling) {
      SelectorsList *head = readWriteGlobals->selectors;

#ifdef CISCO_DEBUG
      traceEvent(TRACE_NORMAL, "Searching selectorId = %d", record->cisco.selectorId);
#endif

      while(head) {
	// traceEvent(TRACE_NORMAL, "%d <-> %d", head->selectorId, record->cisco.selectorId);

	if((head->selectorId == record->cisco.selectorId)
	   && (head->netflow_device_ip == netflow_device_ip)) {
	  *multiplier = head->samplingPopulation, *packet_offset = head->packet_offset;
#ifdef CISCO_DEBUG
	  traceEvent(TRACE_NORMAL, "multiplier = %d / packet_offset = %d",
		     *multiplier, *packet_offset);
#endif
	  break;
	} else {
	  head = head->next;
	}
      } /* while */
    }

#ifdef CISCO_DEBUG
    traceEvent(TRACE_NORMAL, "[302] selectorId=%d [%02X %02X]",
	       record->cisco.selectorId,
	       buffer[displ] & 0xFF, buffer[displ+1] & 0xFF);
#endif
    break;

  case 310:
    memcpy(&record->cisco.samplingPopulation, &buffer[displ], 4);
    record->cisco.samplingPopulation = htonl(record->cisco.samplingPopulation);

    if(record->cisco.samplingPopulation == 0xFFFFFFFF) {
#ifdef CISCO_DEBUG
      traceEvent(TRACE_WARNING, "Found samplingPopulation=%04X for selectorId %d: round it to 1",
		 record->cisco.samplingPopulation, record->cisco.selectorId);
#endif
      record->cisco.samplingPopulation = 1;
    }

    record->cisco.hasSampling++;
#ifdef CISCO_DEBUG
    traceEvent(TRACE_NORMAL, "[310] samplingPopulation=%d [%02X %02X %02X %02X]",
	       record->cisco.samplingPopulation,
	       buffer[displ] & 0xFF, buffer[displ+1] & 0xFF,
	       buffer[displ+2] & 0xFF, buffer[displ+3] & 0xFF);
#endif
    break;

  case 233: /* ASA Firewall Event */
    // traceEvent(TRACE_NORMAL, "[233] %u", buffer[displ] & 0xFF);
    if((buffer[displ] & 0xFF) != 0x02 /* Flow Deleted */)
      *skip_flow = 1; /*
			We skip flow creation as many attributes
			are missing and use flow deletion that is richer
		      */
    break;

  case 242: /* New FPGA */
  case 312: /* Old FPGA */
    memcpy(&record->cisco.original_packet_len, &buffer[displ], 2);
    record->cisco.original_packet_len = htons(record->cisco.original_packet_len);
#ifdef CISCO_DEBUG
    traceEvent(TRACE_NORMAL, "[312] original_packet_len=%d", record->cisco.original_packet_len);
#endif
    break;

    /* IXIA */
  case 35932:
    record->ixia.l7_application_id = ntohl(*((u_int32_t*)&buffer[displ]));
    break;

  case 35933:
    len = min(field->fieldLen, sizeof(record->ixia.l7_application_name)-1);
    strncpy(record->ixia.l7_application_name, &buffer[displ], len);
    record->ixia.l7_application_name[len] = '\0';
    break;

  case 35942:
    len = min(field->fieldLen, sizeof(record->ixia.src_ip_country)-1);
    strncpy(record->ixia.src_ip_country, &buffer[displ], len);
    record->ixia.src_ip_country[len] = '\0';
    break;

  case 35947:
    len = min(field->fieldLen, sizeof(record->ixia.src_ip_city)-1);
    strncpy(record->ixia.src_ip_city, &buffer[displ], len);
    record->ixia.src_ip_city[len] = '\0';
    break;

  case 35962:
    len = min(field->fieldLen, sizeof(record->ixia.dst_ip_country)-1);
    strncpy(record->ixia.dst_ip_country, &buffer[displ], len);
    record->ixia.dst_ip_country[len] = '\0';
    break;

  case 35967:
    len = min(field->fieldLen, sizeof(record->ixia.dst_ip_city)-1);
    strncpy(record->ixia.dst_ip_city, &buffer[displ], len);
    record->ixia.dst_ip_city[len] = '\0';
    break;

  case 35983:
    len = min(field->fieldLen, sizeof(record->ixia.os_device_name)-1);
    strncpy(record->ixia.os_device_name, &buffer[displ], len);
    record->ixia.os_device_name[len] = '\0';
    break;

  case 35998:
    record->rcvdOctets = getField3264to32(field, &buffer[displ], 1);
    break;

  case 35999:
    record->rcvdPkts = getField3264to32(field, &buffer[displ], 1);
    break;

    /* ntop */
  case NTOP_BASE_ID+82: /* NW_LATENCY_SEC */
    memcpy(&record->ntop.nw_latency_sec, &buffer[displ], 4);
    break;
  case NTOP_BASE_ID+83: /* NW_LATENCY_USEC */
    memcpy(&record->ntop.nw_latency_usec, &buffer[displ], 4);
    break;

    /* VoIP Extensions */
  case NTOP_BASE_ID+130: /* SIP_CALL_ID */
    memcpy(&record->ntop.sip_call_id, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "SIP: sip_call_id=%s", record->ntop.sip_call_id);
#endif
    break;
  case NTOP_BASE_ID+131: /* SIP_CALLING_PARTY */
    memcpy(&record->ntop.sip_calling_party, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "SIP: sip_calling_party=%s", record->ntop.sip_calling_party);
#endif
    break;
  case NTOP_BASE_ID+132: /* SIP_CALLED_PARTY */
    memcpy(&record->ntop.sip_called_party, &buffer[displ], 50);
#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "SIP: sip_called_party=%s", record->ntop.sip_called_party);
#endif
    break;

  default:
    return(0);
  }

  return(1);
}

/* ********************************************************* */

void dissectNetFlow(u_int32_t netflow_device_ip,
		    char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  int flowVersion;
  u_int32_t recordActTime = 0, recordSysUpTime = 0;
  struct generic_netflow_record record;

  pthread_rwlock_wrlock(&readWriteGlobals->collectorCounterLock);
  readWriteGlobals->collectionStats.num_dissected_flow_packets++;
  pthread_rwlock_unlock(&readWriteGlobals->collectorCounterLock);

  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  flowVersion = ntohs(the5Record.flowHeader.version);

#ifdef DEBUG_FLOWS
  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(len=%d) [tot flow packets=%u]", bufferLen,
	       readWriteGlobals->collectionStats.num_dissected_flow_packets);
#endif

#ifdef DEBUG_FLOWS
  if(readOnlyGlobals.enable_debug)
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
      if(numFlows > DEFAULT_V1FLOWS_PER_PACKET) numFlows = DEFAULT_V1FLOWS_PER_PACKET;
      recordActTime   = ntohl(the1Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the1Record.flowHeader.sysUptime);
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ?
	     sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      if(numFlows > DEFAULT_V7FLOWS_PER_PACKET) numFlows = DEFAULT_V1FLOWS_PER_PACKET;
      recordActTime   = ntohl(the7Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the7Record.flowHeader.sysUptime);
    }

#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
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
    u_int16_t numEntries, displ;
    V9IpfixSimpleTemplate template;
    int i;
    u_char handle_ipfix;
    u_int32_t observation_domain_id = 0;
    u_int8_t engine_type, engine_id;
    u_int32_t sourceId;
    u_int8_t skip_flow = 0;

    if(flowVersion == 9) handle_ipfix = 0; else handle_ipfix = 1;

    if(handle_ipfix) {
      struct flow_ipfix_hdr* ipfixh = (struct flow_ipfix_hdr*)&the5Record;

      observation_domain_id = ntohl(ipfixh->observationDomainId);
      engine_type = observation_domain_id >> 8;
      engine_id   = observation_domain_id & 0xFF;

      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader)-4; // FIX
      if(readOnlyGlobals.enable_debug) traceEvent(TRACE_INFO, "IPFIX Length: %d", numEntries);
    } else {
      V9FlowHeader *v9hdr = (V9FlowHeader*)&the5Record;

      observation_domain_id = sourceId = ntohl(v9hdr->sourceId);
      engine_type = sourceId >> 8;
      engine_id   = sourceId & 0xFF;

      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader);
    }

    recordActTime = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);
    /*     NTOHL(recordActTime); NTOHL(recordSysUpTime); */

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      V9V10TemplateField *fields = NULL;
      int16_t stillToProcess; /* Do not change to uint: this way I can catch template length issues */

      /* 1st byte */
      if(readOnlyGlobals.enable_debug)
	traceEvent(TRACE_INFO, "[displ=%d][%02X %02X %02X]",
		   displ, buffer[displ] & 0xFF,
		   buffer[displ+1] & 0xFF,
		   buffer[displ+2] & 0xFF);

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

	if(readOnlyGlobals.enable_debug) {
	  traceEvent(TRACE_INFO, "Found Template [displ=%d][sourceId: %u]", displ, sourceId);
	  traceEvent(TRACE_INFO, "Found Template Type: %s", isOptionTemplate ? "Option" : "Flow");
	}

	if(bufferLen > (displ+sizeof(V9TemplateHeader))) {
	  V9TemplateHeader header;
	  u_int8_t templateDone = 0;

	  memcpy(&header, &buffer[displ], sizeof(V9TemplateHeader));
	  header.templateFlowset = ntohs(header.templateFlowset), header.flowsetLen = ntohs(header.flowsetLen);
	  stillToProcess = header.flowsetLen - sizeof(V9TemplateHeader);
	  displ += sizeof(V9TemplateHeader);

	  while((bufferLen >= (displ+stillToProcess)) && (!templateDone)) {
	    FlowSetV9Ipfix *cursor = NULL;
	    u_int16_t len = 0;
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

		displ += 2, stillToProcess -= 2 /*, len += 2 */;
		memcpy(&tot_field_count, &buffer[displ], 2); tot_field_count = htons(tot_field_count);
		displ += 2, stillToProcess -= 2 /* , len += 2 */;
		memcpy(&tot_scope_field_count, &buffer[displ], 2); tot_scope_field_count = htons(tot_scope_field_count);
		displ += 2, stillToProcess -= 2 /* , len += 2 */;
		template.scopeFieldCount = tot_scope_field_count;

		if(tot_field_count >= tot_scope_field_count) {
		  u_int num = tot_scope_field_count * 4; /* FIX: check PEN here */
		  u_int field_num = (tot_field_count-tot_scope_field_count) * 4;
		  u_int delta = num + field_num;

		  displ += delta, stillToProcess -= delta /* , len += num */;
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
	      traceEvent(TRACE_WARNING, "Too many template fields (%d): skept [pktId: %u]",
			 template.fieldCount,
			 readWriteGlobals->collectionStats.num_dissected_flow_packets);
	      goodTemplate = 0;
	    } else if(template.fieldCount == 0) {
              traceEvent(TRACE_WARNING, "No fields defined on template %d: skept [pktId: %u]",
			 template.templateId,
			 readWriteGlobals->collectionStats.num_dissected_flow_packets);
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

		  if(bufferLen < (displ+stillToProcess)) {
		    traceEvent(TRACE_INFO, "Broken flow format (bad length) [received: %u][displ: %u][stillToProcess: %u][available: %u]",
			       bufferLen, displ, stillToProcess, (displ+stillToProcess));
		    return;
		  }

		  /* Check the template before handling it */
		  for(fieldId=0; fieldId < template.fieldCount; fieldId++) {
		    u_int32_t enterprise_id = 0;
		    u_int8_t is_enterprise_specific = (buffer[displ+len] & 0x80) ? 1 : 0;
		    V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		    len += 4; /* Field Type (2) + Field Length (2) */

		    if(is_enterprise_specific) {
		      enterprise_id = ntohl(*(u_int32_t*)&buffer[displ+len]);
		      
		      len += 4; /* PEN (Private Enterprise Number) */
		    }

		    fields[fieldId].fieldId = htons(set->templateId) & 0x7FFF;
		    fields[fieldId].fieldLen = htons(set->flowsetLen);
		    fields[fieldId].isPenField = is_enterprise_specific;
		    fields[fieldId].enterpriseId = enterprise_id;

		    if(fields[fieldId].fieldLen != (u_int16_t)-1) /* Variable lenght fields */
		      accumulatedLen += fields[fieldId].fieldLen;

		    if(readOnlyGlobals.enable_debug)
		      traceEvent(TRACE_NORMAL, "[%d] fieldId=%d/PEN=%d/len=%d [tot=%d]",
				 1+fieldId, fields[fieldId].fieldId,
				 is_enterprise_specific, fields[fieldId].fieldLen, len);
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

		if(readOnlyGlobals.enable_debug)
		  traceEvent(TRACE_NORMAL, "Template [id=%d] fields: %d", template.templateId, template.fieldCount);

		/* Check the template before handling it */
		for(fieldId=0;fieldId < template.fieldCount; fieldId++) {
		  V9FlowSet *set = (V9FlowSet*)&buffer[displ+len];

		  fields[fieldId].fieldId = htons(set->templateId);
		  fields[fieldId].fieldLen = htons(set->flowsetLen);
		  fields[fieldId].isPenField = (fields[fieldId].fieldId >= NTOP_BASE_ID) ? 1 : 0;
		  fields[fieldId].enterpriseId = 0;

		  len += 4; /* Field Type (2) + Field Length (2) */
		  accumulatedLen +=  fields[fieldId].fieldLen;

		  if(readOnlyGlobals.enable_debug)
		    traceEvent(TRACE_NORMAL, "[%d] fieldId=%d (%s)/fieldLen=%d/totLen=%d/templateLen=%d [%02X %02X %02X %02X]",
			       1+fieldId, fields[fieldId].fieldId,
			       getStandardFieldId(fields[fieldId].fieldId), fields[fieldId].fieldLen,
			       accumulatedLen, len,
			       buffer[displ+len-4] & 0xFF,
			       buffer[displ+len-3] & 0xFF,
			       buffer[displ+len-2] & 0xFF,
			       buffer[displ+len-1] & 0xFF);
		}
	      }
	    }

	    if((template.flowsetLen > 1500) || (accumulatedLen > 1500)) {
	      goodTemplate = 0;
	    }

	    pthread_rwlock_wrlock(&readWriteGlobals->collectorRwLock);

	    if(goodTemplate) {
	      readWriteGlobals->collectionStats.num_good_templates_received++;

	      /* Sequential list access */
	      cursor = readWriteGlobals->v9_ipfix_templates;

	      while(cursor != NULL) {
		if((cursor->templateInfo.templateId == template.templateId)
		   && (cursor->templateInfo.flowVersion == flowVersion)
		   && (cursor->templateInfo.netflow_device_ip == netflow_device_ip)
		   && (cursor->templateInfo.observation_domain_id_source_id == observation_domain_id))
		  break;
		else
		  cursor = cursor->next;
	      }

	      if(cursor != NULL) {
		if(readOnlyGlobals.enable_debug)
		  traceEvent(TRACE_INFO, ">>>>> Redefined existing template [id=%d]",
			     template.templateId);

		free(cursor->fields);
	      } else {
		if(readOnlyGlobals.enable_debug)
		  traceEvent(TRACE_INFO, ">>>>> Found new flow template definition [id=%d]", template.templateId);

		cursor = (FlowSetV9Ipfix*)malloc(sizeof(FlowSetV9Ipfix));
		cursor->next = readWriteGlobals->v9_ipfix_templates;
		readWriteGlobals->v9_ipfix_templates = cursor;
	      }

	      cursor->templateInfo.flowVersion = flowVersion;
	      cursor->templateInfo.flowsetLen = len + sizeof(header);
	      cursor->templateInfo.templateId = template.templateId;
	      cursor->templateInfo.fieldCount = template.fieldCount;
	      cursor->templateInfo.v9ScopeLen = template.v9ScopeLen;
	      cursor->templateInfo.scopeFieldCount  = template.scopeFieldCount;
	      cursor->templateInfo.isOptionTemplate = template.isOptionTemplate;
	      cursor->templateInfo.netflow_device_ip = netflow_device_ip;
	      cursor->templateInfo.observation_domain_id_source_id = observation_domain_id;
	      cursor->flowLen                 = accumulatedLen;
	      cursor->fields                  = fields;

	      if(readOnlyGlobals.enable_debug)
		traceEvent(TRACE_INFO, ">>>>> Defined flow template [id=%d][flowLen=%d][fieldCount=%d]",
			   cursor->templateInfo.templateId,
			   cursor->flowLen, cursor->templateInfo.fieldCount);

	      readWriteGlobals->collectionStats.num_known_templates++;
	    } else {
	      if(readOnlyGlobals.enable_debug)
		traceEvent(TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
	      readWriteGlobals->collectionStats.num_bad_templates_received++;
	    }
	    pthread_rwlock_unlock(&readWriteGlobals->collectorRwLock);

	    displ += len, stillToProcess -= len;

	    if(readOnlyGlobals.enable_debug)
	      traceEvent(TRACE_INFO, "Moving %d bytes forward: new offset is %d [stillToProcess=%d]",
			 len, displ, stillToProcess);
	    if(stillToProcess < 4)  {
	      /* Pad */
	      displ += stillToProcess;
	      stillToProcess = 0;
	    }

	    if(stillToProcess <= 0) templateDone = 1;
	  }
	}
      } else {
	if(readOnlyGlobals.enable_debug)
	  traceEvent(TRACE_INFO, "Found FlowSet [displ=%d]", displ);
	foundRecord = 1;
      }

      if(foundRecord) {
	V9FlowSet fs;

	if(bufferLen > (displ+sizeof(V9FlowSet))) {
	  FlowSetV9Ipfix *cursor;
	  u_int16_t tot_len = 4;  /* 4 bytes header */

	  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

	  fs.flowsetLen = ntohs(fs.flowsetLen);
	  fs.templateId = ntohs(fs.templateId);

	  pthread_rwlock_rdlock(&readWriteGlobals->collectorRwLock);

	  /* Sequential list access */
	  cursor = readWriteGlobals->v9_ipfix_templates;

	  while(cursor != NULL) {
	    if((cursor->templateInfo.templateId == fs.templateId)
	       && (cursor->templateInfo.flowVersion == flowVersion)
	       && (cursor->templateInfo.netflow_device_ip == netflow_device_ip)
	       && (cursor->templateInfo.observation_domain_id_source_id == observation_domain_id)) {
	      break;
	    } else
	      cursor = cursor->next;
	  }

	  if(cursor != NULL) {
	    /* We process only flows, not option templates */

	    if(cursor->templateInfo.isOptionTemplate == 0) {
	      /* Template found */
	      int fieldId, init_displ, scopeOffset = (4 * cursor->templateInfo.scopeFieldCount) + cursor->templateInfo.v9ScopeLen;
	      int end_flow;
	      V9V10TemplateField *fields = cursor->fields;
	      u_int32_t multiplier = 1, packet_offset = 0;

	      init_displ = displ + scopeOffset;
	      displ += sizeof(V9FlowSet) + scopeOffset;

	      if(readOnlyGlobals.enable_debug)
		traceEvent(TRACE_INFO, ">>>>> Rcvd flow with known template %d [%d...%d]",
			   fs.templateId, displ, fs.flowsetLen);

	      end_flow = init_displ + fs.flowsetLen-scopeOffset;
	      tot_len += scopeOffset;

	      while(displ < end_flow) {
		u_int16_t accum_len = 0, real_field_len, real_field_len_offset;

		if(end_flow-displ < 4) break;

		/* Defaults */
		memset(&record, 0, sizeof(record));
		record.vlanId = NO_VLAN; /* No VLAN */
		record.ntop.nw_latency_sec = record.ntop.nw_latency_usec = htonl(0);
		record.engine_type = engine_type, record.engine_id = engine_id;

#ifdef DEBUG_FLOWS
		if(0) {
		  if(readOnlyGlobals.enable_debug){
		    u_int i, begin = displ, end = init_displ + fs.flowsetLen-scopeOffset;

		    traceEvent(TRACE_INFO, ">>>>> Stats [%d...%d]", begin, end);

		    for(i=begin; i<end; i++)
		      traceEvent(TRACE_INFO, "%02X [%d]", buffer[i] & 0xFF, i);
		  }
		}
#endif

		skip_flow = 0;

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

		  if(readOnlyGlobals.enable_debug) {
		    /* if(cursor->templateInfo.isOptionTemplate) */ {
		      traceEvent(TRACE_NORMAL, ">>>>> Dissecting flow field "
				 "[optionTemplate=%d][displ=%d/%d][template=%d][fieldId=%d][fieldLen=%d]"
				 "[isPenField=%d][field=%d/%d] [%d...%d] [accum_len=%d] [%02X %02X %02X %02X]",
				 cursor->templateInfo.isOptionTemplate, displ, fs.flowsetLen,
				 fs.templateId, fields[fieldId].fieldId,
				 real_field_len,
				 fields[fieldId].isPenField,
				 fieldId, cursor->templateInfo.fieldCount,
				 displ, (init_displ + fs.flowsetLen), accum_len,
				 buffer[displ] & 0xFF, buffer[displ+1] & 0xFF,
				 buffer[displ+2] & 0xFF, buffer[displ+3] & 0xFF);
		    }
		  }

		  if(fields[fieldId].isPenField == 0) {
		    /*
		      See
		      http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
		    */

		    switch(fields[fieldId].fieldId) {
		    case 1: /* IN_BYTES Incoming flow bytes (src->dst) */
		    case 231: /* Initiator octets */
		      record.sentOctets = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      record.sentOctets *= readOnlyGlobals.flowCollection.sampleRate;
		      break;
		    case 2: /* IN_PKTS */
		      record.sentPkts = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      record.sentPkts *= readOnlyGlobals.flowCollection.sampleRate;
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
		    case TCP_SRC_PORT:
		      memcpy(&record.srcport, &buffer[displ], 2);
		      break;
		    case 8: /* IPV4_SRC_ADDR */
		      if(record.srcaddr.ipVersion != 6) {
			record.srcaddr.ipVersion = 4;
			memcpy(&record.srcaddr.ipType.ipv4, &buffer[displ], 4);
		      }
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
		    case TCP_DST_PORT:
		      memcpy(&record.dstport, &buffer[displ], 2);
		      break;
		    case 12: /* IPV4_DST_ADDR */
		      if(record.dstaddr.ipVersion != 6) {
			record.dstaddr.ipVersion = 4;
			memcpy(&record.dstaddr.ipType.ipv4, &buffer[displ], 4);
		      }
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
		    case 15: /* IPV4_NEXT_HOP */
		    case 18: /* BGP_NEXT_HOP */
		      record.nexthop.ipVersion = 4;
		      memcpy(&record.nexthop.ipType.ipv4, &buffer[displ], 4);
		      break;
		    case 62: /* IPV6_NEXT_HOP */
		      record.nexthop.ipVersion = 6, memcpy(&record.nexthop.ipType.ipv6, &buffer[displ], 16);
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
		    case 232: /* Responder octets */
		      record.rcvdOctets = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      record.rcvdOctets *= readOnlyGlobals.flowCollection.sampleRate;
		      break;
		    case 24: /* OUT_PKTS */
		      record.rcvdPkts = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      record.rcvdPkts *= readOnlyGlobals.flowCollection.sampleRate;
		      break;
		    case 27: /* IPV6_SRC_ADDR */
		      if(record.dstaddr.ipVersion != 4)
			record.srcaddr.ipVersion = 6, memcpy(&record.srcaddr.ipType.ipv6, &buffer[displ], 16);
		      break;

		    case 28: /* IPV6_DST_ADDR */
		      if(record.dstaddr.ipVersion != 4)
			record.dstaddr.ipVersion = 6, memcpy(&record.dstaddr.ipType.ipv6, &buffer[displ], 16);
		      break;

		    case 32: /* ICMP_TYPE */
		      memcpy(&record.icmpType, &buffer[displ], 2);
		      break;

		    case 38: /* ENGINE_TYPE */
		      memcpy(&record.engine_type, &buffer[displ], 1);
		      break;

		    case 39: /* ENGINE_ID */
		      memcpy(&record.engine_id, &buffer[displ], 1);
		      break;

		    case 48: /* FLOW_SAMPLER_ID */
		      /* 1 byte - Identifier shown in "show flow-sampler" */
		      break;

		    case 51: /* FLOW_CLASS - Cisco proprietary (1 byte) */
		      break;
		    case 52: /* MIN_TTL */
		      memcpy(&record.minTTL, &buffer[displ], 1);
		      break;
		    case 53: /* MAX_TTL */
		      memcpy(&record.maxTTL, &buffer[displ], 1);
		      break;
		    case 58: /* SRC_VLAN */
		    case 59: /* DST_VLAN */
		      memcpy(&record.vlanId, &buffer[displ], 2);
		      record.vlanId = ntohs(record.vlanId);
		      break;

		    case 60: /* IP_PROTOCOL_VERSION */
		      record.srcaddr.ipVersion = buffer[displ];
		      record.dstaddr.ipVersion = buffer[displ];
		      break;

		    case 61: /* DIRECTION */
		      /* 1 byte - Flow direction: 0 - ingress flow, 1 - egress flow */
		      break;

		    case 85: /* NF_F_FLOW_BYTES - IPFIX: octetTotalCount */
		      record.rcvdOctets = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      if(flowVersion == 9) {
			/* In ASA We don't have the number of packets so in order
			   to let ntop not discard this flow we need to put a reasonable
			   value there (avg 512 bytes packet)
			*/
			record.rcvdPkts = htonl(1 + (ntohl(record.rcvdOctets)/512));
		      }
		      break;

		    case 86: /* IPFIX: packetTotalCount */
		      record.rcvdPkts = getField3264to32(&fields[fieldId], &buffer[displ], 1);
		      break;

		      /* Cisco */
		    case 95: /* NBAR Application Id */
		      memcpy(&record.cisco.nbar2_application_id, &buffer[displ], 4);
                      record.cisco.nbar2_application_id = htonl(record.cisco.nbar2_application_id);
#ifdef CISCO_DEBUG
		      traceEvent(TRACE_NORMAL, "[NBAR2] nbar2_application_id=%u",
				 record.cisco.nbar2_application_id);
#endif
		      break;

		    case 102:
		      memcpy(&record.cisco.packet_offset, &buffer[displ], 2);
		      record.cisco.packet_offset = ntohs(record.cisco.packet_offset);
#ifdef CISCO_DEBUG
		      traceEvent(TRACE_NORMAL, "[102] packet_offset=%d", record.cisco.packet_offset);
#endif
		      break;

		    case 103:
		      memcpy(&record.cisco.packet_len, &buffer[displ], 2);
		      record.cisco.packet_len = ntohs(record.cisco.packet_len);
#ifdef CISCO_DEBUG
		      traceEvent(TRACE_NORMAL, "[103] packet_len=%d", record.cisco.packet_len);
#endif
		      break;

		    case 104: /* SAMPLED_PACKET_ID */
		      if(0) { /* Not used */
			u_int16_t packet_id;

			memcpy(&packet_id, &buffer[displ], 2);
			packet_id = ntohs(packet_id);
			traceEvent(TRACE_NORMAL, "[104] packet_id=%u", packet_id);
		      }
		      break;

		    case 150: /* flowStartSeconds */
		      memcpy(&record.firstEpoch, &buffer[displ], 4);
		      break;
		    case 151: /* flowEndSeconds */
		      memcpy(&record.lastEpoch, &buffer[displ], 4);
		      break;

		    case 152: /* flowStartMilliseconds */
		      record.firstEpoch = getField3264to32(&fields[fieldId], &buffer[displ], 1000);
		      break;

		    case 153: /* flowEndMilliSeconds */
		      record.lastEpoch = getField3264to32(&fields[fieldId], &buffer[displ], 1000);
		      break;

		    case 278: /* ConnectionCountNew */
		    case 279: /* ConnectionSumDuration */
		      /* Not interesting for nProbe */
		      break;

		    default:
		      goto handle_custom_field;
		    }
		  } else {
		    /* PEN fields */
		  handle_custom_field:
		    if(dissectCustomField(&record, buffer, bufferLen, displ, &fields[fieldId], netflow_device_ip,
					  &multiplier, &packet_offset, &skip_flow) == 0) {
#ifdef DEBUG_FLOWS
		      if(readOnlyGlobals.enable_debug)
			traceEvent(TRACE_WARNING, "Missing support for flow fieldId %d [len=%d/isPenField=%d]",
				   fields[fieldId].fieldId, fields[fieldId].fieldLen, fields[fieldId].isPenField);
#endif
		    }
		  }

		  accum_len += real_field_len+real_field_len_offset, displ += real_field_len+real_field_len_offset;
		} /* for */

		if(cursor->templateInfo.isOptionTemplate) {
		  if(record.cisco.hasSampling == 2) {
		    SelectorsList *prev = NULL, *head = readWriteGlobals->selectors, *found = NULL;

		    while(head) {
		      if((head->selectorId == record.cisco.selectorId)
			 && (head->netflow_device_ip == netflow_device_ip)) {
			found = head;
			break;
		      } else if(head->selectorId > record.cisco.selectorId) {
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
			selector->selectorId = record.cisco.selectorId, selector->samplingPopulation = record.cisco.samplingPopulation;
			selector->packet_offset = record.cisco.packet_offset, selector->netflow_device_ip = netflow_device_ip, selector->next = head;

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
		      found->samplingPopulation = record.cisco.samplingPopulation;
		  }

		  tot_len += accum_len;
		} else {
#ifdef DEBUG_FLOWS
		  if(readOnlyGlobals.enable_debug) {
		    char buf[64], buf1[64];

		    record.srcaddr.ipType.ipv4 = ntohl(record.srcaddr.ipType.ipv4);
		    record.dstaddr.ipType.ipv4 = ntohl(record.dstaddr.ipType.ipv4);

		    traceEvent(TRACE_INFO,
			       ">>>> NETFLOW: [%s] %s:%d -> %s:%d [%u/%u]",
			       proto2name(record.proto),
			       _intoa(record.srcaddr, buf, sizeof(buf)), ntohs(record.srcport),
			       _intoa(record.dstaddr, buf1, sizeof(buf1)), ntohs(record.dstport),
			       ntohl(record.sentPkts), ntohl(record.rcvdPkts));
		    record.srcaddr.ipType.ipv4 = htonl(record.srcaddr.ipType.ipv4);
		    record.dstaddr.ipType.ipv4 = htonl(record.dstaddr.ipType.ipv4);

		    traceEvent(TRACE_INFO,
			       ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d][packet_len=%d]",
			       accum_len, record.cisco.packet_len);
		  }
#endif

		  if(!skip_flow) {
		    if(record.cisco.packet_len > 0) {
		      struct pcap_pkthdr pkthdr;

		      pkthdr.ts.tv_sec = time(NULL);
		      pkthdr.ts.tv_usec = 0;
		      pkthdr.caplen = record.cisco.packet_len;
		      pkthdr.len = max(record.cisco.packet_len, record.cisco.original_packet_len);

#ifdef CISCO_DEBUG
		      traceEvent(TRACE_NORMAL,
				 "[CISCO] Received pkt %d [len: caplen=%d/len=%d][offset: %d][multiplier=%d][observationPointId: %d][selectorId: %d][interfaces: %d->%d]",
				 readWriteGlobals->collectionStats.num_dissected_flow_packets,
				 pkthdr.caplen, pkthdr.len, packet_offset,
				 multiplier, record.cisco.observationPointId, record.cisco.selectorId,
				 ntohs(record.input), ntohs(record.output));
#endif

		      // traceEvent(TRACE_INFO, "Packet len: %u", record.cisco.packet_len);

		      decodePacket(0 /* dummy threadId */,
				   -1 /* unknown input idx */,
				   &pkthdr, record.cisco.packet, 1 /* RX packet */,
				   1 /* sampledPacket */, (multiplier == 0) ? 1 : multiplier,
				   ntohs(record.input), ntohs(record.output),
				   ntohl(netflow_device_ip), 0); /* Pass the packet to nProbe */
		    } else {
		      /*
			IMPORTANT NOTE

			handleGenericFlow handles monodirectional flows, whereas
			v9 flows and bidirectional. This means that if there's some
			bidirectional traffic, handleGenericFlow is called twice.
		      */
		      deEndianRecord(&record); /* This must be called once per handleGenericFlow() call */

		      /* handleGenericFlow handles both directions so there's no need to revert
			 this flow and call handleGenericFlow() again */
		      handleGenericFlow(0 /* fake threadId */, netflow_device_ip, recordActTime, recordSysUpTime, &record);

#ifdef DEBUG_FLOWS
		      if(readOnlyGlobals.enable_debug)
			traceEvent(TRACE_INFO,
				   ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d]",
				   accum_len);
#endif
		    }
		  }

		  tot_len += accum_len;
		}

		if(accum_len == 0) {
		  traceEvent(TRACE_ERROR, "INTERNAL ERROR: invalid accum_len");
		  break;
		}
	      } /* while */

#ifdef DEBUG_FLOWS
	      if(readOnlyGlobals.enable_debug)
		traceEvent(TRACE_INFO, ">>>>> tot_len=%d / fs.flowsetLen=%d", tot_len, fs.flowsetLen);
#endif

	      if(tot_len < fs.flowsetLen) {
		u_int16_t padding = fs.flowsetLen - tot_len;

		if(padding > 4) {
		  traceEvent(TRACE_WARNING,
			     "Template len mismatch [tot_len=%d][flow_len=%d][padding=%d][num_dissected_flow_packets=%d]",
			     tot_len, fs.flowsetLen, padding, readWriteGlobals->collectionStats.num_dissected_flow_packets);
		} else {
#ifdef DEBUG_FLOWS
		  if(readOnlyGlobals.enable_debug)
		    traceEvent(TRACE_INFO, ">>>>> %d bytes padding [tot_len=%d][flow_len=%d]",
			       padding, tot_len, fs.flowsetLen);
#endif
		  displ += padding;
		}
	      }
	    } else {
	      /* Skipping options template */
	      displ += fs.flowsetLen;
	    }
	  } else {
#ifdef DEBUG_FLOWS
	    if(readOnlyGlobals.enable_debug)
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

    if(numFlows > readOnlyGlobals.num_v5flows_per_packet) numFlows = readOnlyGlobals.num_v5flows_per_packet;

#ifdef DEBUG_FLOWS
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);
#endif

    /*
      Reset the record so that fields that are not contained
      into v5 records are set to zero
    */
    memset(&record, 0, sizeof(record));
    record.vlanId = NO_VLAN; /* No VLAN */
    record.ntop.nw_latency_sec = record.ntop.nw_latency_usec = htonl(0);

    for(i=0; i<numFlows; i++) {
      record.srcaddr.ipType.ipv4 = the5Record.flowRecord[i].srcaddr, record.srcaddr.ipVersion = 4;
      record.dstaddr.ipType.ipv4 = the5Record.flowRecord[i].dstaddr, record.dstaddr.ipVersion = 4;
      record.nexthop.ipType.ipv4  = the5Record.flowRecord[i].nexthop, record.nexthop.ipVersion = 4;
      record.input       = the5Record.flowRecord[i].input;
      record.output      = the5Record.flowRecord[i].output;
      record.sentPkts    = the5Record.flowRecord[i].dPkts;
      record.sentOctets  = the5Record.flowRecord[i].dOctets;
      record.first       = the5Record.flowRecord[i].first;
      record.last        = the5Record.flowRecord[i].last;
      record.tos         = the5Record.flowRecord[i].tos;
      record.srcport     = the5Record.flowRecord[i].srcport;
      record.dstport     = the5Record.flowRecord[i].dstport;
      record.tcp_flags   = the5Record.flowRecord[i].tcp_flags;
      record.proto       = the5Record.flowRecord[i].proto;
      record.dst_as      = htonl(ntohs(the5Record.flowRecord[i].dst_as));
      record.src_as      = htonl(ntohs(the5Record.flowRecord[i].src_as));
      record.dst_mask    = the5Record.flowRecord[i].dst_mask;
      record.src_mask    = the5Record.flowRecord[i].src_mask;
      record.engine_type = the5Record.flowHeader.engine_type;
      record.engine_id   = the5Record.flowHeader.engine_id;

      deEndianRecord(&record);
      record.sentPkts   *= readOnlyGlobals.flowCollection.sampleRate;
      record.sentOctets *= readOnlyGlobals.flowCollection.sampleRate;

      handleGenericFlow(0 /* fake threadId */,
			netflow_device_ip, recordActTime,
			recordSysUpTime, &record);
    }
  }
}

/* ********************************************************* */

void* netFlowCollectLoop(void* notUsed) {
  fd_set netflowMask;
  int len;
#ifdef DEBUG_FLOWS
  int deviceId = 0;
#endif
  u_char buffer[2048];
  /* Run idle task if this is the only ingress interface */
  u_int8_t runIdleTask = ((readOnlyGlobals.captureDev != NULL) && (strcmp(readOnlyGlobals.captureDev, "none") == 0)) ? 1 : 0;
  struct sockaddr_in fromHostV4;
  struct sockaddr_in6 fromHostV6;
  unsigned long thread_id = (unsigned long)notUsed;

  /* traceEvent(TRACE_NORMAL, "netFlowMainLoop(%u) thread...", thread_id); */

  readOnlyGlobals.datalink = DLT_EN10MB;

  if(readOnlyGlobals.pcapPtr || readOnlyGlobals.pcapFile)
    readOnlyGlobals.numProcessThreads++;

  while(!readWriteGlobals->shutdownInProgress) {
    int maxSock = max(readOnlyGlobals.collectorInSocketv4, readOnlyGlobals.collectorInSocketv6);
    struct timeval wait_time;
    int rc;

    FD_ZERO(&netflowMask);
    FD_SET(readOnlyGlobals.collectorInSocketv4, &netflowMask);

    if(readOnlyGlobals.collectorInSocketv6 > 0)
      FD_SET(readOnlyGlobals.collectorInSocketv6, &netflowMask);

#ifdef HAVE_SCTP
    if(readOnlyGlobals.collectorInSctpSocket > 0) {
      FD_SET(readOnlyGlobals.collectorInSctpSocket, &netflowMask);
      if(readOnlyGlobals.collectorInSctpSocket > maxSock)
	maxSock = readOnlyGlobals.collectorInSctpSocket;
    }
#endif

    wait_time.tv_sec = 1, wait_time.tv_usec = 0;
    rc = select(maxSock+1, &netflowMask, NULL, NULL, &wait_time);
    if(readWriteGlobals->shutdownInProgress) break;

    if(rc > 0) {
      if(FD_ISSET(readOnlyGlobals.collectorInSocketv4, &netflowMask)){
	len = sizeof(fromHostV4);
	rc = recvfrom(readOnlyGlobals.collectorInSocketv4,
		      (char*)&buffer, sizeof(buffer),
		      0, (struct sockaddr*)&fromHostV4, (socklen_t*)&len);

	if(readOnlyGlobals.enable_debug)
	  traceEvent(TRACE_NORMAL, "NETFLOW_DEBUG: Received %u bytes flow", rc);
      } else if((readOnlyGlobals.collectorInSocketv6 > 0)
		&& FD_ISSET(readOnlyGlobals.collectorInSocketv6, &netflowMask)) {
	len = sizeof(fromHostV6);
	rc = recvfrom(readOnlyGlobals.collectorInSocketv6,
		      (char*)&buffer, sizeof(buffer),
		      0, (struct sockaddr*)&fromHostV6, (socklen_t*)&len);
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
	msg.msg_name = (caddr_t)&fromHostV4;
	msg.msg_namelen = sizeof(fromHostV4);
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
      if(readOnlyGlobals.enable_debug)
	traceEvent(TRACE_INFO, "NETFLOW_DEBUG: Received sFlow/NetFlow packet(len=%d)(deviceId=%d)",
		   rc,  deviceId);
#endif

      if(rc > 0) {
#ifdef MAX_NETFLOW_PACKET_BUFFER
        gettimeofday(&netflowStartOfRecordProcessing, NULL);
#endif

	fromHostV4.sin_addr.s_addr = ntohl(fromHostV4.sin_addr.s_addr);
	readWriteGlobals->now = time(NULL), readWriteGlobals->collectedPkts[thread_id]++;

	if((buffer[0] == '\0')
	   && (buffer[1] == '\0')
	   && (buffer[2] == '\0')
	   && ((buffer[3] == 2)    /* sFlow v2 */
	       || (buffer[3] == 5) /* sFlow v5 */)
	   )
	  dissectSflow(buffer, rc, &fromHostV4); /* sFlow */
	else
	  dissectNetFlow(fromHostV4.sin_addr.s_addr, (char*)buffer, rc);

#ifdef DEBUG
	traceEvent(TRACE_NORMAL, "Received %d flows", readOnlyGlobals.num_collected_pkts);

	if(readOnlyGlobals.num_collected_pkts == 100) {
	  readWriteGlobals->shutdownInProgress = 1; /* DEBUG */
	  cleanup();
	}
#endif
      }
    } else {
      if(runIdleTask) idleThreadTask(0, 4);
    }
  }

  return(NULL);
}

/* ********************************************************* */

void handleCollectionFilter(char *_filter) {
  /*
    Format

    !as12345
    as12345
    192.168.0.0/24
    !192.168.0.0/24
   */
  u_int8_t not_filter;
  char *filter;

  if((_filter == NULL) || (_filter[0] == '\0')) return;

  traceEvent(TRACE_INFO, "Processing collection filter %s", _filter);

  if(_filter[0] == '!')
    not_filter = 1, filter = &_filter[1];
  else
    not_filter = 0, filter = _filter;

  if(strncmp(filter, "as", 2) == 0) {
    u_int32_t asn = atol(&filter[2]);
    ASlist *el;

    if(asn == 0)
      goto invalid_filter;

    el = (ASlist*)malloc(sizeof(ASlist));

    if(el == NULL) {
      traceEvent(TRACE_WARNING, "Not enough memory");
    } else {
      el->asn = atol(&filter[2]);
      el->next = not_filter ? readOnlyGlobals.flowCollection.not_as_list : readOnlyGlobals.flowCollection.as_list;

      if(not_filter)
	readOnlyGlobals.flowCollection.not_as_list = el;
      else
	readOnlyGlobals.flowCollection.as_list = el;
    }
  } else {
    /* 192.168.0.0/24 */
    char *mask = strchr(filter, '/');
    u_int bits;
    in_addr_t addr;
    NetList *el;

    if(mask == NULL) {
    invalid_filter:
      traceEvent(TRACE_WARNING, "Invalid filter %s specified", _filter);
      return;
    } else
      bits = atol(&mask[1]), mask[0] = '\0';

    addr = inet_addr(filter);

    if((bits == 0) || (addr == 0))
      goto invalid_filter;

    el = (NetList*)malloc(sizeof(NetList));

    if(el == NULL) {
      traceEvent(TRACE_WARNING, "Not enough memory");
    } else {
      el->net = ntohl(addr), el->mask = 0xffffffff << (32 - bits);
      el->next = not_filter ? readOnlyGlobals.flowCollection.not_prefix_list : readOnlyGlobals.flowCollection.prefix_list;

      if(not_filter)
	readOnlyGlobals.flowCollection.not_prefix_list = el;
      else
	readOnlyGlobals.flowCollection.prefix_list = el;
    }
  }
}

/* ********************************************************* */

static void freeASlist(ASlist *l) {
  while(l) {
    ASlist *next = l->next;
    free(l);
    l = next;
  }
}

/* ********************************************************* */

static void freeNetList(NetList *l) {
  while(l) {
    NetList *next = l->next;
    free(l);
    l = next;
  }
}

/* ********************************************************* */

void freeCollectionFilters() {
  freeASlist(readOnlyGlobals.flowCollection.not_as_list);
  freeASlist(readOnlyGlobals.flowCollection.as_list);

  freeNetList(readOnlyGlobals.flowCollection.not_prefix_list);
  freeNetList(readOnlyGlobals.flowCollection.prefix_list);
}
