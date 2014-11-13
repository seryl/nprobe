/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2002-14 Luca Deri <deri@ntop.org>
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

#ifdef HAVE_VOIP_EXTENSIONS
#include "plugins/hep.c"
#endif

#ifdef WIN32
#define MSG_DONTWAIT 0
#endif

/* ****************************************************** */

static void checkDumpExport(FlowHashBucket *myBucket,
			    FlowDirection direction) {
  if(readOnlyGlobals.enableHttpPlugin
     || readOnlyGlobals.enableProcessPlugin
     || readOnlyGlobals.enableDnsPlugin
     || readOnlyGlobals.enableMySQLPlugin
     || readOnlyGlobals.enableSipPlugin
     || readOnlyGlobals.enableOraclePlugin
     || readOnlyGlobals.enableWhoisPlugin
     || readOnlyGlobals.enableGtpPlugin
     || readOnlyGlobals.enableRadiusPlugin
     || readOnlyGlobals.enableDiameterPlugin
     || readOnlyGlobals.enableSmtpPlugin
     || readOnlyGlobals.enableImapPlugin
     || readOnlyGlobals.enablePopPlugin
     || readOnlyGlobals.enableL7BridgePlugin
     ) {
    /* Dummy: used to dump flows on disk */
    checkPluginExport(NULL, direction, myBucket, NULL, NULL, NULL);
  }
}

/* ****************************************************** */

static int exportBucketToNetflowV5(FlowHashBucket *myBucket,
				   FlowDirection direction) {

  if(direction == src2dst_direction /* src -> dst */) {
    if(myBucket->core.tuple.flowCounters.pktSent == 0) return(0); /* Nothing to export */

    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input     = htons(ifIdx(myBucket, 1));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output    = htons(ifIdx(myBucket, 0));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr   = htonl(myBucket->core.tuple.key.k.ipKey.src.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr   = htonl(myBucket->core.tuple.key.k.ipKey.dst.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].nexthop   = (myBucket->ext && (myBucket->ext->nextHop.ipVersion == 4)) ? htonl(myBucket->ext->nextHop.ipType.ipv4) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts     = htonl(myBucket->core.tuple.flowCounters.pktSent);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets   = htonl(myBucket->core.tuple.flowCounters.bytesSent);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first     = htonl(msTimeDiff(&myBucket->core.tuple.flowTimers.firstSeenSent,
												    &readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last      = htonl(msTimeDiff(&myBucket->core.tuple.flowTimers.lastSeenSent,
												    &readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport   = htons(myBucket->core.tuple.key.k.ipKey.sport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport   = htons(myBucket->core.tuple.key.k.ipKey.dport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos       = myBucket->ext ? myBucket->ext->src2dstTos : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as    = myBucket->ext ? htons(getAS(&myBucket->core.tuple.key.k.ipKey.src, &myBucket->ext->srcInfo)) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as    = myBucket->ext ? htons(getAS(&myBucket->core.tuple.key.k.ipKey.dst, &myBucket->ext->dstInfo)) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_mask  = myBucket->ext ? ip2mask(&myBucket->core.tuple.key.k.ipKey.src, &myBucket->ext->srcInfo) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_mask  = myBucket->ext ? ip2mask(&myBucket->core.tuple.key.k.ipKey.dst, &myBucket->ext->dstInfo) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags = myBucket->ext ? (u_int8_t)myBucket->ext->protoCounters.tcp.src2dstTcpFlags : 0;

    readWriteGlobals->flowExportStats.totExportedFlowBytes += myBucket->core.tuple.flowCounters.bytesSent;
    readWriteGlobals->flowExportStats.totExportedFlowPkts  += myBucket->core.tuple.flowCounters.pktSent;
  } else {
    if(myBucket->core.tuple.flowCounters.pktRcvd == 0) return(0); /* Nothing to export */

    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input     = htons(ifIdx(myBucket, 0));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output    = htons(ifIdx(myBucket, 1));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr   = htonl(myBucket->core.tuple.key.k.ipKey.dst.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr   = htonl(myBucket->core.tuple.key.k.ipKey.src.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].nexthop   = (myBucket->ext && (myBucket->ext->nextHop.ipVersion == 4)) ? htonl(myBucket->ext->nextHop.ipType.ipv4) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts     = htonl(myBucket->core.tuple.flowCounters.pktRcvd);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets   = htonl(myBucket->core.tuple.flowCounters.bytesRcvd);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first     = htonl(msTimeDiff(&myBucket->core.tuple.flowTimers.firstSeenRcvd,
												    &readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last      = htonl(msTimeDiff(&myBucket->core.tuple.flowTimers.lastSeenRcvd,
												    &readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport   = htons(myBucket->core.tuple.key.k.ipKey.dport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport   = htons(myBucket->core.tuple.key.k.ipKey.sport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos       = myBucket->ext ? myBucket->ext->dst2srcTos : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as    = myBucket->ext ? htons(getAS(&myBucket->core.tuple.key.k.ipKey.dst, &myBucket->ext->dstInfo)) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as    = myBucket->ext ? htons(getAS(&myBucket->core.tuple.key.k.ipKey.src, &myBucket->ext->srcInfo)) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_mask  = myBucket->ext ? ip2mask(&myBucket->core.tuple.key.k.ipKey.dst, &myBucket->ext->dstInfo) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_mask  = myBucket->ext ? ip2mask(&myBucket->core.tuple.key.k.ipKey.src, &myBucket->ext->srcInfo) : 0;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags = myBucket->ext ? (u_int8_t)myBucket->ext->protoCounters.tcp.dst2srcTcpFlags : 0;

    readWriteGlobals->flowExportStats.totExportedFlowBytes += myBucket->core.tuple.flowCounters.bytesRcvd;
    readWriteGlobals->flowExportStats.totExportedFlowPkts  += myBucket->core.tuple.flowCounters.pktRcvd;
  }

  readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].proto = (u_int8_t)myBucket->core.tuple.key.k.ipKey.proto;

  readWriteGlobals->flowExportStats.totExportedFlows++;

#ifdef HAVE_MYSQL
  if(readOnlyGlobals.db_initialized) {
    char sql[2048];
    unsigned int first, last;

    first = (ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first) / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;
    last  = (ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last) / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;

    // traceEvent(TRACE_ERROR, "====> %u / %u [num_collectors=%u]", first, last, readOnlyGlobals.numCollectors);

    /* When you change DEFAULT_V9_TEMPLATE please also update the variable below */
    snprintf(sql, sizeof(sql),
	     "INSERT INTO `%sflows` (PROTOCOL, IPV4_SRC_ADDR, IPV4_DST_ADDR, INPUT_SNMP, OUTPUT_SNMP, IN_PKTS, "
	     "IN_BYTES, FIRST_SWITCHED, LAST_SWITCHED, L4_SRC_PORT, L4_DST_PORT, SRC_TOS, SRC_AS, DST_AS, TCP_FLAGS) "
	     "VALUES ('%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u')",
	     get_db_table_prefix(),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].proto,
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets),
	     first,
	     last,
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos,
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags);

    exec_sql_query(sql, 1);
  }
#endif

  return(1);
}

/* ****************************************************** */

static int exportBucketToNetflowV9(FlowHashBucket *myBucket,
				   FlowDirection direction) {
  u_int flowBufBegin, flowBufMax, templateIndex;
  int numElements;
  u_int8_t isV4Flow;
#if defined(HAVE_MYSQL)
  char *the_buffer;
  u_int the_len;
#endif
  PluginInformation *head;

  if(myBucket->ext == NULL) return(0);

  head = myBucket->ext->plugin;

  isV4Flow = ((!myBucket->core.tuple.key.is_ip_flow /* Non-IP traffic */)
	      || (myBucket->core.tuple.key.k.ipKey.src.ipVersion == 4)
	      || (readOnlyGlobals.templateBuffers[V6_TEMPLATE_INDEX].v9TemplateElementList[0] == NULL))
    ? 1 : 0;

  //if(isV4Flow == 0) traceEvent(TRACE_NORMAL, "V6");

  templateIndex = isV4Flow ? V4_TEMPLATE_INDEX : V6_TEMPLATE_INDEX;
  flowBufMax = readOnlyGlobals.maxNetFlowPacketPayloadLen;

  if(direction == src2dst_direction /* src -> dst */) {
    if(myBucket->core.tuple.flowCounters.pktSent == 0) return(0); /* Nothing to export */

    readWriteGlobals->flowExportStats.totExportedFlowBytes += myBucket->core.tuple.flowCounters.bytesSent;
    readWriteGlobals->flowExportStats.totExportedFlowPkts  += myBucket->core.tuple.flowCounters.pktSent;
  } else {
    if(myBucket->core.tuple.flowCounters.pktRcvd == 0) return(0); /* Nothing to export */

    readWriteGlobals->flowExportStats.totExportedFlowBytes += myBucket->core.tuple.flowCounters.bytesRcvd;
    readWriteGlobals->flowExportStats.totExportedFlowPkts  += myBucket->core.tuple.flowCounters.pktRcvd;
  }

  readWriteGlobals->flowExportStats.totExportedFlows++;

  /*
     templateIndex is the default template to use but in case there is a
     better match we ought to use it
  */

  while(head) {
    if(head->plugin_used) {
      templateIndex = isV4Flow ? head->pluginPtr->v4TemplateIdx : head->pluginPtr->v6TemplateIdx;
      /* 1 match is enough ! */
      break;
    } else
      head = head->next;
  }

  flowBufBegin = readOnlyGlobals.templateBuffers[templateIndex].bufferLen;

  if(readOnlyGlobals.enable_debug) {
#if 1
    traceEvent(TRACE_INFO, "Export flow using templateId=%u", readOnlyGlobals.idTemplate + templateIndex);
#else
    traceEvent(TRACE_INFO, "--->>> To dump flow [templateIndex=%u][tot=%u][max=%u]",
	       readOnlyGlobals.idTemplate + templateIndex, flowBufBegin, readOnlyGlobals.templateBuffers[templateIndex].bufferLen);
#endif
  }

  flowPrintf(readOnlyGlobals.templateBuffers[templateIndex].v9TemplateElementList,
	     readOnlyGlobals.templateBuffers[templateIndex].templatePlugin,
	     isV4Flow ? 1 /* IPv4 */ : 0 /* IPv6 */,
	     readOnlyGlobals.templateBuffers[templateIndex].buffer,
	     &flowBufBegin, &flowBufMax,
	     &numElements, 0, myBucket, direction, 0, 0, 0 /* No JSON */);

#if defined(HAVE_MYSQL)
  the_buffer = &readOnlyGlobals.templateBuffers[templateIndex].buffer[readOnlyGlobals.templateBuffers[templateIndex].bufferLen];
  the_len = flowBufBegin - readOnlyGlobals.templateBuffers[templateIndex].bufferLen;

  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "--->>> Dumped flow [templateIndex=%u][the_len=%u][tot=%u][max=%u]",
	       readOnlyGlobals.idTemplate + templateIndex, the_len, flowBufBegin,
	       readOnlyGlobals.templateBuffers[templateIndex].bufferLen);
#endif

#ifdef HAVE_MYSQL
  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "Dumping data onto MySQL using template Id %u", readOnlyGlobals.idTemplate + templateIndex);

  dump_flow2db(readOnlyGlobals.templateBuffers[templateIndex].v9TemplateElementList, the_buffer, the_len);
#endif

  readOnlyGlobals.templateBuffers[templateIndex].bufferLen = flowBufBegin;
  readWriteGlobals->queuedDataToExport += flowBufBegin;

  return(1);
}

/* ****************************************************** */

#define HAVE_PORT(p,q) ((myBucket->core.tuple.key.k.ipKey.proto == q) && ((myBucket->core.tuple.key.k.ipKey.sport == p) || (myBucket->core.tuple.key.k.ipKey.dport == p)))

/* ****************************************************** */

static void execBucketExpiracyActions(FlowHashBucket *myBucket) {
  if((myBucket->core.l7.proto_type == NDPI_PROTO_TYPE)
     && (myBucket->core.l7.proto.ndpi.ndpi_proto != NDPI_PROTOCOL_UNKNOWN))
    add_to_lru_cache_num(&readWriteGlobals->l7Cache, getLRUCacheKey(myBucket),
		     myBucket->core.l7.proto.ndpi.ndpi_proto);
}

/* ****************************************************** */

void setBucketExpired(FlowHashBucket *myBucket) {
  if(myBucket->core.bucket_expired) return;
  execBucketExpiracyActions(myBucket);
  myBucket->core.bucket_expired = 1;
}

/* ****************************************************** */

int exportBucketToNetflow(FlowHashBucket *myBucket,
			  FlowDirection direction) {
  int rc = 0;

#ifdef TIME_PROTECTION
  {
    struct tm expireDate;

#define EXPIRE_DAY    30
#define EXPIRE_MONTH  8
#define EXPIRE_YEAR   2005

    memset(&expireDate, 0, sizeof(expireDate));
    expireDate.tm_mday = EXPIRE_DAY;
    expireDate.tm_mon  = EXPIRE_MONTH-1;
    expireDate.tm_year = EXPIRE_YEAR-1900;

    if(time(NULL) > mktime(&expireDate)) {
      traceEvent(TRACE_ERROR, "Sorry: this copy of nProbe is expired.\n");
      exit(0);
    }
  }
#endif

  if(readOnlyGlobals.demo_mode) {
    if(readWriteGlobals->flowExportStats.totExportedFlows > MAX_DEMO_FLOWS) {
      static u_char msg_shown = 0;

      if(!msg_shown) {
	traceEvent(TRACE_ERROR, "***************************************************************************\n");
	traceEvent(TRACE_ERROR, "* NOTE: You have reached the max demo %d flows export: no more exports *\n",
	       MAX_DEMO_FLOWS);
	traceEvent(TRACE_ERROR, "* NOTE: no additional flows will be exported by this nProbe instance      *\n");
	traceEvent(TRACE_ERROR, "***************************************************************************\n\n");
	msg_shown = 1;
      }

      readOnlyGlobals.demo_expired = 1;
      return(0);
    }
  }

  if(readOnlyGlobals.drop_flow_no_plugin
     && (!(myBucket->ext && myBucket->ext->plugin)))
    return(0);

#ifdef HAVE_TEMPLATE_EXTENSIONS
  notifyFlow(myBucket, direction);
#endif

  if(myBucket->core.dont_export_flow)
    return(1);

  switch(readOnlyGlobals.biflowsExportPolicy) {
  case export_all_flows:
    /* Nothing to do */
    break;
  case export_bidirectional_flows_only:
    if((myBucket->core.tuple.flowCounters.pktSent == 0)
       || (myBucket->core.tuple.flowCounters.pktRcvd == 0))
      return(1);
    break;
  case export_monodirectional_flows_only:
    if((myBucket->core.tuple.flowCounters.pktSent > 0)
       && (myBucket->core.tuple.flowCounters.pktRcvd > 0))
      return(1);
    break;
  }

  if(direction == src2dst_direction) {
    if(myBucket->core.tuple.flowCounters.pktSent == 0)
      return(1);
  } else {
    if(myBucket->core.tuple.flowCounters.pktRcvd == 0)
      return(1);
  }

  if(readOnlyGlobals.dontSentBidirectionalV9Flows) {
    if(((myBucket->ext->swap_flow == 0) && (direction == dst2src_direction))
       || ((myBucket->ext->swap_flow == 1) && (direction == src2dst_direction)))
      return(0);
  }

  if((direction == dst2src_direction) && readOnlyGlobals.dontSentBidirectionalV9Flows)
    return(0);

  if(!readOnlyGlobals.none_specified) fillASInfo(myBucket);

  if((readOnlyGlobals.numCollectors > 0)
     /*
       We need the two statements below as otherwise nothing will be saved in the DB/fastbit
      */
     || readOnlyGlobals.db_initialized
     ) {
    if(readOnlyGlobals.netFlowVersion == 5) {
      if(myBucket->core.tuple.key.k.ipKey.src.ipVersion == 4)
	rc = exportBucketToNetflowV5(myBucket, direction);
      else {
	static char msgPrinted = 0;

	if(!msgPrinted) {
	  traceEvent(TRACE_WARNING, "Unable to export non-IPv4 flows using NetFlow v5. Dropped.");
	  msgPrinted = 1;
	}
      }
    } else
      rc = exportBucketToNetflowV9(myBucket, direction);
  } else
    rc = 1;

  checkDumpExport(myBucket, direction);

  if(rc) {
    struct pluginEntryPoint *plg = NULL;

    if(myBucket->ext && myBucket->ext->plugin && myBucket->ext->plugin->pluginPtr)
      plg = myBucket->ext->plugin->pluginPtr;

    if((readOnlyGlobals.tcpsender.tcp_connect
#ifdef HAVE_VOIP_EXTENSIONS
	|| (readOnlyGlobals.hep.sock != -1)
#endif
#ifdef HAVE_ZMQ
	|| readOnlyGlobals.zmq.publisher
#endif
	)
       && (!readOnlyGlobals.demo_expired)
       ) {
      char line_buffer[4096] = { '\0' };
      u_int line_buffer_len = sizeof(line_buffer), len;

      flowBufferPrintf(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList,
		       plg, myBucket, direction,
		       line_buffer, line_buffer_len,
		       1 /* JSON */);

      /* Extend it with the flow_id */
      len = strlen(line_buffer);
      if(len < (sizeof(line_buffer)-10)) {
	char sampling_buf[64], label[32];

	if(readOnlyGlobals.json_symbolic_labels)
	  snprintf(label, sizeof(label), "%s", "SAMPLING_INTERVAL");
	else
	  snprintf(label, sizeof(label), "%u", SAMPLING_INTERVAL);

	if(readOnlyGlobals.pktSampleRate > 1)
	  snprintf(sampling_buf, sizeof(sampling_buf), ",\"%s\":%u",
		   label, readOnlyGlobals.pktSampleRate);
	else
	  sampling_buf[0] = '\0';

	if(readOnlyGlobals.json_symbolic_labels)
	  snprintf(label, sizeof(label), "%s", "TOTAL_FLOWS_EXP");
	else
	  snprintf(label, sizeof(label), "%u", TOTAL_FLOWS_EXP);

	snprintf(&line_buffer[len-1], (sizeof(line_buffer)-len-1), "%s,\"%s\":%u}",
		 sampling_buf, label,
		 ++readWriteGlobals->flowExportStats.totJSONExports);
      }

#ifdef HAVE_ZMQ
      if(readOnlyGlobals.zmq.publisher) sendZMQ(line_buffer, 0);
#endif

      if(readOnlyGlobals.tcpsender.tcp_connect) {
	if(readOnlyGlobals.tcpsender.tcp_socket == -1)
	  readOnlyGlobals.tcpsender.tcp_socket = connect_to_server((struct sockaddr*)&readOnlyGlobals.tcpsender.tcp_servaddr);

	if(readOnlyGlobals.tcpsender.tcp_socket >= 0) {
	  int l = strlen(line_buffer);

	  line_buffer[l] = '\n';
	  line_buffer[l+1] = '\0';
	  if(send_tcp(readOnlyGlobals.tcpsender.tcp_socket, line_buffer, strlen(line_buffer)) == -1) {
	    // traceEvent(TRACE_WARNING, "Send error [%s/%u]\n", strerror(errno), errno);
	    close_socket(readOnlyGlobals.tcpsender.tcp_socket);
	    readOnlyGlobals.tcpsender.tcp_socket = -1;
	  } else
	    traceEvent(TRACE_INFO, "[TCP] %s", line_buffer);
	}
      }


#ifdef HAVE_VOIP_EXTENSIONS
      if(readOnlyGlobals.hep.sock != -1) {
	int rc = send_json_hepv3(myBucket, time(NULL),
				 line_buffer, strlen(line_buffer));

	if(rc > 0)
	  traceEvent(TRACE_INFO, "[HEP] [len: %u][%s]", rc, line_buffer);
	else
	  traceEvent(TRACE_ERROR, "[HEP] Error %d [%s/%u]", rc, strerror(errno), errno);
      }
#endif

    }

    if(readOnlyGlobals.traceMode == 2)
      printFlow(myBucket, direction);

    if(likely(!readOnlyGlobals.demo_expired)) {
      /*
	We need locks as both exportBucket() and idleThreadTask()
	can manipulate the dump files simultanously
      */
      pthread_rwlock_wrlock(&readWriteGlobals->dumpFileLock);

      if(!readOnlyGlobals.simulateStorage) {
	if(readOnlyGlobals.dumpFormat == binary_core_flow_format) {
	  if(readWriteGlobals->flowFd) {
	    int rc = fwrite(&myBucket->core.tuple, 1, sizeof(myBucket->core.tuple), readWriteGlobals->flowFd);

	    if(rc != sizeof(myBucket->core.tuple))
	      traceEvent(TRACE_WARNING, "Expected to send %d bytes, but sent only %d bytes",
			 sizeof(myBucket->core.tuple), rc);
	  }
	} else {
	  if((readOnlyGlobals.dumpFormat != binary_format)
	     && (readOnlyGlobals.dumpFormat != binary_core_flow_format)
	     && (readWriteGlobals->flowFd
#ifdef HAVE_SQLITE
		 || (readWriteGlobals->sqlite3Handler != NULL)
#endif
		 )
	     && (readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[0] != NULL)) {
	    flowFilePrintf(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList,
			   plg, readWriteGlobals->flowFd, myBucket, direction);
	  }
	}
      }
      pthread_rwlock_unlock(&readWriteGlobals->dumpFileLock);
    }

    readWriteGlobals->numFlows++, readWriteGlobals->totFlows++,
      readWriteGlobals->totFlowsRate++, readWriteGlobals->totFlowsSinceLastExport++;

    checkNetFlowExport(0);
  }

  return(rc);
}

/* ****************************************************** */

void checkNetFlowExport(int forceExport) {
  int emitFlow, deltaFlows = 0, flowExpired = 0, sendTemplate = 0;

  if(((readWriteGlobals->numFlows == 0)
      || (readOnlyGlobals.numCollectors == 0))
     && (readOnlyGlobals.dumpFormat != binary_format)) {
    int i;

    readWriteGlobals->numFlows = 0; /*
				       Fake flow export so that everything works
				       but flows are not exported
				    */

    for(i=0; i<readOnlyGlobals.numActiveTemplates; i++)
      readOnlyGlobals.templateBuffers[i].bufferLen = 0;

    return;
  }

  /*
     We need to avoid that periodic flow export can interfere
     with checkNetFlowExport() called after that a flow has been exported
  */
  pthread_rwlock_wrlock(&readWriteGlobals->checkExportLock);

#ifdef DEBUG
  traceEvent(TRACE_ERROR, "====> [queuedDataToExport=%u][templateFlowSize=%u]",
	     readWriteGlobals->queuedDataToExport, readOnlyGlobals.templateFlowSize);
#endif

  if(((readOnlyGlobals.netFlowVersion == 9) || (readOnlyGlobals.netFlowVersion == 10))
     && (readOnlyGlobals.numCollectors > 1) && (!readOnlyGlobals.reflectorMode) /* Round-robin mode */
     && (readOnlyGlobals.packetsBeforeSendingTemplates == 0) /* It's time to send the template */
     ) {
    if(readOnlyGlobals.netFlowVersion == 9) {
      initNetFlowV9Header(&readWriteGlobals->theV9Header);
      readWriteGlobals->theV9Header.count = htons(3);
    } else
      initIPFIXHeader(&readWriteGlobals->theIPFIXHeader);

    sendNetFlowV9V10(0, 1, 1);

    readOnlyGlobals.packetsBeforeSendingTemplates = readOnlyGlobals.numCollectors*readOnlyGlobals.templatePacketsDelta;
  } else {
    if((readOnlyGlobals.netFlowVersion == 9 || readOnlyGlobals.netFlowVersion == 10)
       && (readOnlyGlobals.packetsBeforeSendingTemplates == 0))
      deltaFlows = readOnlyGlobals.templateFlowSize, sendTemplate = 1;
  }

  emitFlow = ((deltaFlows+readWriteGlobals->numFlows) >= readOnlyGlobals.minNumFlowsPerPacket)
    || (forceExport && readWriteGlobals->shutdownInProgress)
    || sendTemplate /* || (pcapFile != NULL) */;

  if(!emitFlow) {
    gettimeofday(&readWriteGlobals->actTime, NULL);

    if(readWriteGlobals->lastExportTime.tv_sec == 0)
      readWriteGlobals->lastExportTime.tv_sec = readWriteGlobals->actTime.tv_sec,
	readWriteGlobals->lastExportTime.tv_usec = readWriteGlobals->actTime.tv_usec;

    flowExpired = readWriteGlobals->lastExportTime.tv_sec
      && (((time(NULL)-readWriteGlobals->lastExportTime.tv_sec) > readOnlyGlobals.sendTimeout)
	  || (readWriteGlobals->actTime.tv_sec > (readWriteGlobals->lastExportTime.tv_sec+readOnlyGlobals.sendTimeout)));
  }

  if(forceExport || emitFlow || flowExpired) {
    if(readOnlyGlobals.netFlowVersion == 5) {
      initNetFlowV5Header(&readWriteGlobals->theV5Flow);
      readWriteGlobals->theV5Flow.flowHeader.count = htons(readWriteGlobals->numFlows);
      sendNetFlowV5(&readWriteGlobals->theV5Flow, 0);
    } else {
      if(readOnlyGlobals.netFlowVersion == 9) {
	initNetFlowV9Header(&readWriteGlobals->theV9Header);
	readWriteGlobals->theV9Header.count = (deltaFlows > 0) ? htons(4) : htons(1);
      } else {
	initIPFIXHeader(&readWriteGlobals->theIPFIXHeader);
	// readWriteGlobals->theIPFIXHeader.len = 0; /* To be filled later */
      }

      sendNetFlowV9V10(0, (deltaFlows > 0) ? 1 : 0, 0);

      if(readOnlyGlobals.packetsBeforeSendingTemplates == 0)
	readOnlyGlobals.packetsBeforeSendingTemplates = readOnlyGlobals.templatePacketsDelta;
      else
	readOnlyGlobals.packetsBeforeSendingTemplates--;
    }

    readWriteGlobals->numFlows = 0;
    readWriteGlobals->lastExportTime.tv_sec = readWriteGlobals->actTime.tv_sec,
      readWriteGlobals->lastExportTime.tv_usec = readWriteGlobals->actTime.tv_usec;
  }

  if(readWriteGlobals->lastExportTime.tv_sec == 0) {
    readWriteGlobals->lastExportTime.tv_sec = readWriteGlobals->actTime.tv_sec,
      readWriteGlobals->lastExportTime.tv_usec = readWriteGlobals->actTime.tv_usec;
  }

  pthread_rwlock_unlock(&readWriteGlobals->checkExportLock);
}

/* ******************************************* */

static int send_buffer(int s, const void *msg, size_t len,
		       int flags, const struct sockaddr *to, socklen_t tolen) {

  if(is_locked_send())
    return(len); /* Emulate successful send */
  else {
    int rc;

    if(readOnlyGlobals.flowExportDelay == 0) flags |= MSG_DONTWAIT;
    rc = sendto(s, msg, len, flags, to, tolen);

    if(rc == -1) {
      // traceEvent(TRACE_WARNING, "sendto(len=%u) returned errno=%d", len, errno);

      if(errno == EAGAIN) {
	rc = sendto(s, msg, len, flags, to, tolen);
      }
    }

    return(rc);
  }
}

/* ****************************************************** */

#ifdef IP_HDRINCL

#define BUFFER_SIZE 1500

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf,
			  unsigned nbytes, u_int32_t sum) {
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
#ifdef DEBUG_CHECKSUM_VERBOSE
    debug ("sum = %x", sum);
#endif
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

/* ******************************************* */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

static int send_raw_socket(int sock, const void *dataBuffer,
			   int dataBufferLen, struct sockaddr_in *dest) {
  if(is_locked_send())
    return(dataBufferLen); /* Emulate successful send */
  else {
    static int ipHdrId = 0;
    int rc;
    char buffer[BUFFER_SIZE];
    unsigned int buffer_size = BUFFER_SIZE, headerLen;
    struct ip_header *ip_header;
    struct udp_header *udp_header;

    ip_header = (struct ip_header*) buffer;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(buffer_size);
    ip_header->id = htons(ipHdrId++);
    ip_header->ttl = 64;
    ip_header->frag_off = htons(0);
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header,
					sizeof(struct ip_header), 0));
    ip_header->daddr = dest->sin_addr.s_addr;
    ip_header->saddr =  readOnlyGlobals.sockIn.sin_addr.s_addr;

    udp_header = (struct udp_header*)(buffer + sizeof(struct ip_header));
    udp_header->source = readOnlyGlobals.sockIn.sin_port;
    udp_header->dest = dest->sin_port;
    udp_header->len = htons(sizeof(struct udp_header)+dataBufferLen);
    udp_header->check  = 0; /* It must be 0 to compute the checksum */

    headerLen = sizeof(struct ip_header)+sizeof(struct udp_header);
    if(dataBufferLen > (BUFFER_SIZE-headerLen))
      dataBufferLen = BUFFER_SIZE-headerLen-1;
    memcpy(&buffer[headerLen], dataBuffer, dataBufferLen);

    buffer_size = headerLen+dataBufferLen;
    ip_header->tot_len  = htons(buffer_size);

    /*
      http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
      http://www.ietf.org/rfc/rfc0761.txt
      http://www.ietf.org/rfc/rfc0768.txt
    */
    udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udphdr),
					 in_cksum((unsigned char *)dataBuffer, dataBufferLen,
						  in_cksum((unsigned char *)&ip_header->saddr,
							   2*sizeof(ip_header->saddr),
							   IPPROTO_UDP + ntohs(udp_header->len)))));
    rc = send_buffer(sock, buffer, buffer_size, 0,
		     (struct sockaddr*)dest,
		     sizeof(struct sockaddr_in));

    /*
      printf("buff %d [rc=%d][dataBufferLen=%d]\n",
      buffer_size, rc, dataBufferLen);
    */

    return(rc > 0 ? (rc-headerLen) : rc);
  }
}

#endif /* IP_HDRINCL */

/* ******************************************* */

#define MAX_LOCK_CHECK_FREQUENCY   10 /* sec */

int is_locked_send(void) {
  static u_char show_message = 1;
  static time_t last_check = 0;
  static int last_returned_value = 0;
  time_t now = time(NULL);

  /* Avoid checking the lock file too often */
  if((now-last_check) < MAX_LOCK_CHECK_FREQUENCY)
    return(last_returned_value);

  if(readOnlyGlobals.flowLockFile != NULL) {
    struct stat buf;

    last_check = now;
    /* The lock file exists so no flows will be sent */
    if(stat(readOnlyGlobals.flowLockFile, &buf) == 0) {
      if(show_message) {
	traceEvent(TRACE_WARNING,
		   "Lock file is present: no flows will be emitted.");
	show_message = 0;
      }
      return(last_returned_value = 1);
    }
  }

  show_message = 1;
  return(last_returned_value = 0); /* Not locked */
}

/* ****************************************************** */

void reopenSocket(CollectorAddress *collector) {
  int sockopt = 1;

  traceEvent(TRACE_WARNING,
	     "Attempting to reopen the socket. Please wait....");

  close(collector->sockFd), collector->sockFd = -1;

  if(collector->transport == TRANSPORT_TCP)
    collector->sockFd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef HAVE_SCTP
  else if(collector->transport == TRANSPORT_SCTP)
    collector->sockFd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
#endif

  if(collector->sockFd == -1) {
    traceEvent(TRACE_ERROR,
	       "Fatal error while creating socket (%s). Trying again later.",
	       strerror(errno));
    return;
  }

  setsockopt(collector->sockFd, SOL_SOCKET, SO_REUSEADDR,
	     (char *)&sockopt, sizeof(sockopt));

  if(collector->transport == TRANSPORT_TCP) {
    int rc;

    if(collector->isIPv6) {
	rc = connect(collector->sockFd,
		     (struct sockaddr *)&collector->u.v6Address,
		     sizeof(collector->u.v6Address));
      } else {
	rc = connect(collector->sockFd,
		     (struct sockaddr *)&collector->u.v4Address,
		     sizeof(struct sockaddr_in));
      }

    if(rc == -1) {
      char msg[256], buf[64];

      snprintf(msg, sizeof(msg),
	       "Connection failed with remote peer %s [%s]. "
	       "Trying again later.",
	       CollectorAddress2Str(collector, buf, sizeof(buf)),
	       strerror(errno));

      traceEvent(TRACE_ERROR, "%s", msg);
      dumpLogEvent(collector_connection_error, severity_error, msg);
    } else {
      /* Peer reconnected */
      char buf[64], msg[256];

      snprintf(msg, sizeof(msg),
	       "Succesfully reconnected with remote collector %s",
	       CollectorAddress2Str(collector, buf, sizeof(buf)));

      dumpLogEvent(collector_connected, severity_info, msg);

      /*
	NOTE
	When a peer is reconnected the template should be resent
	only to it. However in order to keep the code simple, the
	template is resent to everyone.
      */
      /* Force the probe to resend the template */
      readOnlyGlobals.packetsBeforeSendingTemplates = 0;
      sendNetFlowV9V10(0, 1, 1);
    }
  }

  collector->flowSequence = 0;
}

/* ****************************************************** */

static int sendFlowData(CollectorAddress *collector, char *buffer,
			int bufferLength, int sequenceIncrement) {
  int rc;
  u_int32_t flow_sequence;
  struct timeval now;

  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "Sending %d bytes packet", bufferLength);

  errno = 0;
  gettimeofday(&now, NULL);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "sendFlowData: len=%d\n", bufferLength);
#endif

  /*
    We need to fill the sequence number according to the collector
    sequence.
  */

#if 0
  traceEvent(TRACE_INFO, "**** flowSequence=%d [%d]",
	     collector->flowSequence, readWriteGlobals->theIPFIXHeader.len);
#endif

  flow_sequence = htonl(collector->flowSequence);
  if(readOnlyGlobals.netFlowVersion == 5) {
    struct flow_ver5_hdr *h = (struct flow_ver5_hdr*)buffer;
    h->flow_sequence = flow_sequence; /* version+count+sysUptime+unix_secs */
  } else if(readOnlyGlobals.netFlowVersion == 9) {
    V9FlowHeader *h = (V9FlowHeader*)buffer;
    h->flow_sequence = flow_sequence; /* version+count+sysUptime+unix_secs */
  } else if(readOnlyGlobals.netFlowVersion == 10) {
    IPFIXFlowHeader *h = (IPFIXFlowHeader*)buffer;
    h->flow_sequence = flow_sequence; /* version+count+sysUptime+unix_secs */
  }

  if(readWriteGlobals->flowFd) {
    if(readOnlyGlobals.dumpFormat == binary_format) {
      /*
	 We need locks as both exportBucket() and idleThreadTask()
	 can manipulate the dump files simultanously
      */
      pthread_rwlock_wrlock(&readWriteGlobals->dumpFileLock);

      if(!readOnlyGlobals.simulateStorage) {
	/*
	  Check again as in the meantime the flowFd might have been manipulated as
	  we did not own the lock yet
	*/
	if(readWriteGlobals->flowFd) {
	  int rc;
      
	  fprintf(readWriteGlobals->flowFd, "%04d", bufferLength);
	  rc = fwrite(buffer, 1, bufferLength, readWriteGlobals->flowFd);

	  if(rc != bufferLength)
	    traceEvent(TRACE_WARNING, "fwrite error: wrote %d, expected %d", rc, bufferLength);
	}
      }

      pthread_rwlock_unlock(&readWriteGlobals->dumpFileLock);
    }
  }

  if((readOnlyGlobals.numCollectors == 0) || readOnlyGlobals.none_specified)
    return(bufferLength); /* Fake good send */

  /*
    This delay is used to slow down export rate as some
    collectors might not be able to catch up with nProbe
  */
  if(readOnlyGlobals.flowExportDelay > 0) {
#ifndef WIN32
    struct timespec timeout;
#endif
    u_short canPause = 0;

    /*
      if -B packetFlowGroup is set, we'll set
      canPause if we've sent packetFlowGroup packets
      then we'll pause for readOnlyGlobals.flowExportDelay
    */
    if(readOnlyGlobals.packetFlowGroup > 0) {
      readWriteGlobals->packetSentCount++;

      if((readWriteGlobals->packetSentCount >= readOnlyGlobals.packetFlowGroup)
	 && (collector->lastExportTime.tv_sec > 0)) {
	if(readOnlyGlobals.traceMode == 2)
	  traceEvent(TRACE_INFO, "Pausing %d ms because we've sent %d packet(s)",
		     readOnlyGlobals.flowExportDelay, readWriteGlobals->packetSentCount);
	canPause = 1;
	readWriteGlobals->packetSentCount = 1;
      }
    }

    if(canPause) {
      u_int32_t msDiff = msTimeDiff(&now, &collector->lastExportTime);

#if defined(DEBUG)
      traceEvent(TRACE_WARNING, "====>>>>>>> Last flow was sent %d ms ago", msDiff);
#endif

      if(msDiff < readOnlyGlobals.flowExportDelay) {
	msDiff = readOnlyGlobals.flowExportDelay - msDiff;

#ifndef WIN32
	timeout.tv_sec = 0;
	timeout.tv_nsec = 1000000*msDiff;

	while((nanosleep(&timeout, &timeout) == -1) && (errno == EINTR))
	  ; /* Do nothing */
#else
	waitForNextEvent(msDiff);
#endif
      }
    }
  }

  if(collector->transport == TRANSPORT_TCP) {
    fd_set writemask;
    struct timeval wait_time;

    FD_ZERO(&writemask);
    FD_SET(collector->sockFd, &writemask);
    memset(&wait_time, 0, sizeof(wait_time));

    wait_time.tv_sec = 1; /* Do not complain if < 1 sec */

    rc = -1;

    if(select(collector->sockFd+1, NULL, &writemask, NULL, &wait_time) > 0) {
      if(FD_ISSET(collector->sockFd, &writemask)) {
	errno = 0;
	rc = send(collector->sockFd, buffer, bufferLength, MSG_DONTWAIT /* Non blocking */);
	/* traceEvent(TRACE_WARNING, "======> send() returned %d [errno=%d]", rc, errno); */
      }
    } else {
      /* traceEvent(TRACE_WARNING, "======> select() returned %d [errno=%d]", rc, errno); */
      errno = -1; /* timeout */
    }
  } else {
    if(!collector->isIPv6) {
#ifdef IP_HDRINCL
      if(collector->transport == TRANSPORT_UDP_RAW)
	rc = send_raw_socket(collector->sockFd, buffer, bufferLength,
			     &collector->u.v4Address);
      else
#endif
	rc = send_buffer(collector->sockFd, buffer, bufferLength,
			 0, (struct sockaddr *)&collector->u.v4Address,
			 sizeof(collector->u.v4Address));
    } else
      rc = send_buffer(collector->sockFd, buffer, bufferLength,
		       0, (struct sockaddr *)&collector->u.v6Address,
		       sizeof(collector->u.v6Address));
  }

  /*
    Note that on NetFlow v9 the sequence number is
    incremented per NetFlow packet sent and not per
    flow sent as for previous versions or in IPFIX.
  */
  if(readOnlyGlobals.netFlowVersion == 10)
    collector->flowSequence += readWriteGlobals->totFlowsSinceLastExport;
  else
  collector->flowSequence += sequenceIncrement;

  readWriteGlobals->totFlowsSinceLastExport = 0;

  if(readOnlyGlobals.flowExportDelay > 0)
    memcpy(&collector->lastExportTime, &now, sizeof(struct timeval));

  if((rc == -1)
     && ((errno == EPIPE /* Broken pipe */)
	 || (errno == -1 /* Timeout */))) {
    char msg[256], buf[64];

    snprintf(msg, sizeof(msg), "Collector %s on socket %d %s [errno=%d/%s]",
	     CollectorAddress2Str(collector, buf, sizeof(buf)),
	     collector->sockFd,
	     (errno == EPIPE) ? "disconnected" : "timed out: disconnecting it",
	     errno, strerror(errno));
    traceEvent(TRACE_WARNING, "%s", msg);

    dumpLogEvent((errno == EPIPE) ? collector_disconnected : collector_too_slow, severity_warning, msg);
    reopenSocket(collector);
  }

  if(rc == bufferLength) {
    /* Everything is ok */
    readWriteGlobals->flowExportStats.totExportedBytes += rc, readWriteGlobals->flowExportStats.totExportedPkts++;
  }

  return(rc);
}

/* ****************************************************** */

void sendNetFlow(void *buffer, u_int32_t bufferLength,
		 u_char lastFlow, int sequenceIncrement,
		 u_char broadcastToAllCollectors) {
  u_int32_t rc = 0;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "==>> sendNetFlow(%d) [numCollectors=%d]",
	     bufferLength, readOnlyGlobals.numCollectors);
#endif

  if(((readOnlyGlobals.numCollectors == 0) || readOnlyGlobals.none_specified)
     && (readOnlyGlobals.dumpFormat != binary_format)
     && (readOnlyGlobals.dumpFormat != binary_core_flow_format))
    return;

  errno = 0;

  if(readOnlyGlobals.reflectorMode || broadcastToAllCollectors) {
    /* Send all the flows to all collectors */
    int i;

    for(i = 0; i<readOnlyGlobals.numCollectors; i++) {
      rc = sendFlowData(&readOnlyGlobals.netFlowDest[i],
			buffer, bufferLength,
			sequenceIncrement);

      if(rc != bufferLength) {
	static u_char msgSent = 0;

	if(!msgSent) {
	  char msg[256];

	  snprintf(msg, sizeof(msg), "Error while exporting flows (%s)", strerror(errno));
	  traceEvent(TRACE_WARNING, "%s", msg);
	  dumpLogEvent(flow_export_error, severity_error, msg);
	  msgSent = 1;
	}
      } else {
#ifdef DEBUG
	char addrbuf[INET6_ADDRSTRLEN];

	if(readOnlyGlobals.netFlowDest[i].isIP == 0)
	  traceEvent(TRACE_INFO, "Sent flow packet to %s",
		     inet_ntoa(readOnlyGlobals.netFlowDest[i].u.v4Address.sin_addr));
	else
	  traceEvent(TRACE_INFO, "Sent flow packet to [%s]",
		     inet_ntop(AF_INET6, (void *)&(readOnlyGlobals.netFlowDest[i].u.IPAddress.ip),
			       addrbuf, sizeof (addrbuf)));
#endif /* DEBUG */
      }
    }
  } else {
    static u_short collectorId = 0;

    /* Send flows to all collectors in round robin */
    rc = sendFlowData(&readOnlyGlobals.netFlowDest[collectorId], buffer,
		      bufferLength, sequenceIncrement);

    /* Switch to next collector */
    if(readOnlyGlobals.numCollectors > 0)
      collectorId = (collectorId + 1) % readOnlyGlobals.numCollectors;
  }

  if((rc != bufferLength)
     && (errno != 0)
     && (!readWriteGlobals->shutdownInProgress)) {
    static u_char msgSent = 0;

    if(!msgSent) {
      char msg[256];

      snprintf(msg, sizeof(msg), "Error while exporting flows (%s) [%u/%u]", strerror(errno), rc, bufferLength);
      traceEvent(TRACE_WARNING, "%s", msg);
      dumpLogEvent(flow_export_error, severity_error, msg);
      msgSent = 1;
    }
  }
}

/* ****************************************************** */

void sendNetFlowV5(NetFlow5Record *theV5Flow, u_char lastFlow) {
  int len;

  if(theV5Flow->flowHeader.count == 0) return;

  if(readOnlyGlobals.traceMode == 2)
    traceEvent(TRACE_INFO, "Sending %d flows (NetFlow v5 format)",
	       ntohs(theV5Flow->flowHeader.count));

  len = (ntohs(theV5Flow->flowHeader.count)*sizeof(struct flow_ver5_rec)
	 +sizeof(struct flow_ver5_hdr));

  sendNetFlow((char *)theV5Flow, len, lastFlow,
	      ntohs(theV5Flow->flowHeader.count), 0);
}

/* ****************************************************** */

void initNetFlowV5Header(NetFlow5Record *theV5Flow) {
  memset(&theV5Flow->flowHeader, 0, sizeof(theV5Flow->flowHeader));

  theV5Flow->flowHeader.version        = htons(5);
  theV5Flow->flowHeader.sysUptime      = htonl(msTimeDiff(&readWriteGlobals->actTime,
							  &readOnlyGlobals.initialSniffTime));
  theV5Flow->flowHeader.unix_secs      = htonl(readWriteGlobals->actTime.tv_sec);
  theV5Flow->flowHeader.unix_nsecs     = htonl(readWriteGlobals->actTime.tv_usec/1000);
  /* NOTE: theV5Flow->flowHeader.flow_sequence will be filled by sendFlowData */
  theV5Flow->flowHeader.engine_type    = (u_int8_t)readOnlyGlobals.engineType;
  theV5Flow->flowHeader.engine_id      = (u_int8_t)readOnlyGlobals.engineId;

  if(readOnlyGlobals.pktSampleRate > 1)
    theV5Flow->flowHeader.sampleRate = htons(0x4000 /* Random sampling mode configured */
					     | readOnlyGlobals.pktSampleRate);
  else
    theV5Flow->flowHeader.sampleRate = 0;
}

/* ****************************************************** */

void initNetFlowV9Header(V9FlowHeader *v9Header) {
  memset(v9Header, 0, sizeof(V9FlowHeader));
  v9Header->version        = htons(readOnlyGlobals.netFlowVersion);
  v9Header->sysUptime      = htonl(msTimeDiff(&readWriteGlobals->actTime, &readOnlyGlobals.initialSniffTime));
  v9Header->unix_secs      = htonl((u_long)time(NULL));
  v9Header->sourceId       = htonl((readOnlyGlobals.engineType << 8) + readOnlyGlobals.engineId);
}

/* ****************************************************** */

void initIPFIXHeader(IPFIXFlowHeader *v10Header) {
  memset(v10Header, 0, sizeof(IPFIXFlowHeader));
  v10Header->version             = htons(readOnlyGlobals.netFlowVersion);
  v10Header->sysUptime           = htonl(readWriteGlobals->actTime.tv_sec);
  v10Header->observationDomainId = htonl((readOnlyGlobals.engineType << 8) + readOnlyGlobals.engineId);
}

/* ****************************************************** */

static int padding(int len) {
  int module = len % 4;

  if(module == 0)
    return(0);
  else
    return(4 - module);
}

/* ****************************************************** */

static int sendFlowset(u_int16_t flowset_id, char *flowBuffer, u_int flowBufferLen, int *bufLen) {
  int len, pad;
  V9FlowSet flowSet;

  len = readOnlyGlobals.templateBuffers[flowset_id].bufferLen;

  if(len == 0) return(0); /* No flows to send */

  flowSet.templateId = htons(readOnlyGlobals.idTemplate + flowset_id);
  len += 4;
  pad = padding(len); len += pad;
  flowSet.flowsetLen = htons(len);
  memcpy(&flowBuffer[(*bufLen)], &flowSet, sizeof(flowSet));
  (*bufLen) += sizeof(flowSet);

  if(((*bufLen)+readOnlyGlobals.templateBuffers[flowset_id].bufferLen) >= flowBufferLen) {
    static u_char warning_sent = 0;

    if(!warning_sent) {
      traceEvent(TRACE_WARNING,
		 "Internal error: too many NetFlow flows per packet (see -m) [%u/%u]",
		 ((*bufLen)+readOnlyGlobals.templateBuffers[flowset_id].bufferLen),
		 flowBufferLen);
      warning_sent = 1;
    }

    readOnlyGlobals.templateBuffers[flowset_id].bufferLen = flowBufferLen-(*bufLen)-1;
  }

  memcpy(&flowBuffer[(*bufLen)], readOnlyGlobals.templateBuffers[flowset_id].buffer, readOnlyGlobals.templateBuffers[flowset_id].bufferLen);
  (*bufLen) += readOnlyGlobals.templateBuffers[flowset_id].bufferLen;
  (*bufLen) += pad;

  return(1);
}

/* ****************************************************** */

void sendNetFlowV9V10(u_char lastFlow,
		      u_char sendTemplate,
		      u_char sendOnlyTheTemplate) {
  char flowBuffer[JUMBO_MTU] = { 0 };
  int bufLen = 0, /* len, */ num_extra_elems = 0, i;

  /* traceEvent(TRACE_WARNING, "****** Sending templates... %d [%d]", sendTemplate, sendOnlyTheTemplate); */

  /*
    NOTE:
    In order to keep things simple, whenever there are multiple
    collectors in round robin and the template needs to be sent out
    it is sent alone (i.e. without incuding flows) to all the collectors.

    If there is just one collector, the template also contains flows
    up to the MTU size.
  */
  if(sendTemplate) {
    V9TemplateHeader templateHeader;
    V9TemplateDef templateDef;
    V9OptionTemplate optionTemplateDef;
    char tmpBuffer[256];
    u_int flowBufBegin, flowBufMax, i, maxTemplatePktLen = 1200, beginIdx = 0, endIdx = 0, numTemplatesSent = 0;
    int numElements, optionTemplateId = readOnlyGlobals.idTemplate + readOnlyGlobals.numActiveTemplates;
    V9FlowSet optionsFlowSet;

    while(numTemplatesSent < readOnlyGlobals.numActiveTemplates) {
      u_int16_t len;
      int pad;

      bufLen = 0, num_extra_elems = 0;

      /* NOTE: flow_sequence will be filled by sendFlowData */
      if(readOnlyGlobals.netFlowVersion == 9) {
	memcpy(&flowBuffer[bufLen], &readWriteGlobals->theV9Header, sizeof(readWriteGlobals->theV9Header));
	bufLen += sizeof(readWriteGlobals->theV9Header);
      } else {
	/* IPFIX */
	memcpy(&flowBuffer[bufLen], &readWriteGlobals->theIPFIXHeader, sizeof(readWriteGlobals->theIPFIXHeader));
	bufLen += sizeof(readWriteGlobals->theIPFIXHeader);
      }

      /* Header */
      num_extra_elems++;
      templateHeader.templateFlowset = (readOnlyGlobals.netFlowVersion == 9) ? htons(0) : htons(2); /* CHECK: is 2 is valid all the time ? */
      len = sizeof(V9TemplateHeader);

      for(i=beginIdx; i<readOnlyGlobals.numActiveTemplates; i++) {
	u_int to_add;

	to_add = sizeof(V9TemplateDef) + readOnlyGlobals.templateBuffers[i].templateBufBegin;

	if((len + to_add) > maxTemplatePktLen)
	  break;

	len += to_add;
	endIdx = i, numTemplatesSent++;
      }

      pad = padding(len); len += pad;
      templateHeader.flowsetLen = htons(len);
      memcpy(&flowBuffer[bufLen], &templateHeader, sizeof(V9TemplateHeader)); bufLen += sizeof(V9TemplateHeader);

      /* Dump templates */
      for(i=beginIdx; i <= endIdx; i++) {
	templateDef.fieldCount = htons(readOnlyGlobals.templateBuffers[i].numTemplateFieldElements);
	templateDef.templateId = htons(readOnlyGlobals.idTemplate+i);
	memcpy(&flowBuffer[bufLen], &templateDef, sizeof(V9TemplateDef));
	bufLen += sizeof(V9TemplateDef);
	memcpy(&flowBuffer[bufLen], readOnlyGlobals.templateBuffers[i].templateBuffer,
	       readOnlyGlobals.templateBuffers[i].templateBufBegin);
	bufLen += readOnlyGlobals.templateBuffers[i].templateBufBegin;
      }

      bufLen += pad; /* Add padding */

      /*
	Here is the relevant paragraph from rfc 5101 "3.4.2.1.  Scope".

	The scope is an Information Element specified in the IPFIX
	Information Model [RFC5102].  An IPFIX-compliant implementation of
	the Collecting Process SHOULD support this minimum set of Information
	Elements as scope: LineCardId, TemplateId, exporterIPv4Address,
	exporterIPv6Address, and ingressInterface.  Note that other
	Information Elements, such as meteringProcessId, exportingProcessId,
	observationDomainId, etc. are also valid scopes.  The IPFIX protocol
	doesn't prevent the use of any Information Elements for scope.
	However, some Information Element types don't make sense if specified
	as scope; for example, the counter Information Elements.

	Finally, note that the Scope Field Count MUST NOT be zero.

	The main things to note.
	1) supporting scope is a SHOULD not a MUST so not implementing it may be OK
	2) Counters (and I would argue totals) don't make sense as scope
	3) if you send an options template there MUST be at least one scope field

	Interim solution: we forget scope with IPFIX leaving it to a future nProbe release
      */

      if(numTemplatesSent == readOnlyGlobals.numActiveTemplates) {
	/* We send the scope only when we're done with templates */

	if(readOnlyGlobals.netFlowVersion == 9) {
	  u_int16_t vals[2] = { htons(1) /* Line Card */, htons(4) /* length = 2 bytes */};
	  u_int32_t system_ip = 0x0;

	  /* Options Template */
	  num_extra_elems++;
	  optionTemplateDef.templateFlowset = (readOnlyGlobals.netFlowVersion == 9) ? htons(1) : htons(3);
	  len = sizeof(V9OptionTemplate)+readOnlyGlobals.optionTemplateBufBegin+4;
	  pad = padding(len); len += pad;
	  optionTemplateDef.flowsetLen     = htons(len);
	  optionTemplateDef.templateId     = htons(optionTemplateId);
	  if(readOnlyGlobals.netFlowVersion == 9) {
	    optionTemplateDef.optionScopeLen = htons(4 /* SystemId=2 + SystemLen=2 */);
	    optionTemplateDef.optionLen      = htons(4 /* each field is 4 bytes */
						     * (readOnlyGlobals.numOptionTemplateFieldElements));
	  } else {
	    optionTemplateDef.optionScopeLen = htons(2 /* SystemId + SystemLen */);
	    optionTemplateDef.optionLen      = htons(readOnlyGlobals.numOptionTemplateFieldElements);
	  }

	  memcpy(&flowBuffer[bufLen], &optionTemplateDef, sizeof(V9OptionTemplate));
	  bufLen += sizeof(V9OptionTemplate);

	  /* Options */
	  memcpy(&flowBuffer[bufLen], vals, sizeof(vals));
	  bufLen += sizeof(vals);

	  memcpy(&flowBuffer[bufLen], readOnlyGlobals.optionTemplateBuffer,
		 readOnlyGlobals.optionTemplateBufBegin);
	  bufLen += readOnlyGlobals.optionTemplateBufBegin;
	  bufLen += pad;

	  /* Options DataRecord */
	  num_extra_elems++;
	  flowBufBegin = 0, flowBufMax = sizeof(tmpBuffer);
	  flowPrintf(readOnlyGlobals.v9OptionTemplateElementList, NULL,
		     1 /* IPv4 */, tmpBuffer, &flowBufBegin, &flowBufMax,
		     &numElements, 0, NULL, 0, 0, 1, 0 /* No JSON */);

	  len = 4 /* sizeof(systemId) */ + flowBufBegin+sizeof(optionsFlowSet);
	  pad = padding(len); len += pad;
	  optionsFlowSet.templateId = htons(optionTemplateId);
	  optionsFlowSet.flowsetLen = htons(len);

	  memcpy(&flowBuffer[bufLen], &optionsFlowSet, sizeof(optionsFlowSet));
	  bufLen += sizeof(optionsFlowSet);

	  /* System IP */
	  memcpy(&flowBuffer[bufLen], &system_ip, flowBufBegin);
	  bufLen += sizeof(system_ip);

	  memcpy(&flowBuffer[bufLen], tmpBuffer, flowBufBegin);
	  bufLen += flowBufBegin;
	  bufLen += pad;
	} /* Scope */
      }

      /* Fill in the flow length */
      switch(readOnlyGlobals.netFlowVersion) {
      case 9:
	len = htons(num_extra_elems);
	memcpy(&flowBuffer[2], &len, 2);
	break;

      case 10:
	len = htons(bufLen);
	memcpy(&flowBuffer[2], &len, 2);
      	break;
      }

#ifdef DEBUG
      traceEvent(TRACE_ERROR, "--->>> Sending %u bytes template packet", bufLen);
#endif

      sendNetFlow(&flowBuffer, bufLen, 0, 1, 1);
      beginIdx = endIdx+1;
    } /* while */
  }

  if(!sendOnlyTheTemplate) {
    u_int num, beginIdx, numTemplateFlowsSent = 0;

    while(numTemplateFlowsSent < readOnlyGlobals.numActiveTemplates) {
      bufLen = 0, num_extra_elems = 0, num = 0, beginIdx = 0;

      /* NOTE: flow_sequence will be filled by sendFlowData */
      if(readOnlyGlobals.netFlowVersion == 9) {
	memcpy(&flowBuffer[bufLen], &readWriteGlobals->theV9Header,
	       sizeof(readWriteGlobals->theV9Header));
	bufLen += sizeof(readWriteGlobals->theV9Header);
      } else {
	/* IPFIX */
	memcpy(&flowBuffer[bufLen], &readWriteGlobals->theIPFIXHeader,
	       sizeof(readWriteGlobals->theIPFIXHeader));
	bufLen += sizeof(readWriteGlobals->theIPFIXHeader);
      }

      /* Send all buffered data */
      for(i=beginIdx; i<readOnlyGlobals.numActiveTemplates; i++) {
	int n;

	n = sendFlowset(i, flowBuffer, sizeof(flowBuffer), &bufLen);
	num += n;

#ifdef DEBUG
	if(n > 0)
	  traceEvent(TRACE_ERROR, "--->>> Sending flowset %u/%u [id=%d][len=%u][bufLen=%u][num=%u]",
		     i, readOnlyGlobals.numActiveTemplates,
		     readOnlyGlobals.idTemplate + i, n, bufLen, num);
#endif

	numTemplateFlowsSent++;

	if(bufLen > readOnlyGlobals.maxNetFlowPacketPayloadLen /* bytes */)
	  break;
      }

      /* Fill in the flow length */
      if(readOnlyGlobals.netFlowVersion == 9) {
	u_int16_t len = htons(num+num_extra_elems);

	memcpy(&flowBuffer[2], &len, 2);
      } else if(readOnlyGlobals.netFlowVersion == 10) {
	u_int16_t len = htons(bufLen);

	memcpy(&flowBuffer[2], &len, 2);
      }

      sendNetFlow(flowBuffer, bufLen, 0, 1, 0);

#ifdef DEBUG
      traceEvent(TRACE_ERROR, "--->>> Sending %u bytes flow packet", bufLen);
#endif

      beginIdx = numTemplateFlowsSent+1;
    } /* while */
  }

  for(i=0; i<readOnlyGlobals.numActiveTemplates; i++)
    readOnlyGlobals.templateBuffers[i].bufferLen = 0;
}

/* ****************************************************** */

static void id2user(FlowHashBucket *bkt, char *keyname) {
  if(!bkt->core.user.user_searched) {
    char *user, key[64];

    snprintf(key, sizeof(key), "username.%s", keyname);
    user = find_lru_cache_str(&readWriteGlobals->flowUsersCache, key);

    if(user != NULL) {
      if(user[0] != '\0') {
	bkt->core.user.username = strdup(user);
      } else {
	/* The cache said that we have no result yet (string is "") */
      }

      bkt->core.user.user_searched = 1;
      return;
    }

    user = getHashCacheDataStrKey("", bkt->core.tuple.flow_hash % MAX_NUM_REDIS_CONNECTIONS,
				  keyname, "username");

    if(user != NULL) {
      bkt->core.user.username = user;
      add_to_lru_cache_str_timeout(&readWriteGlobals->flowUsersCache, key, user, 60 /* (sec) Positive expire time */);
    } else {
      add_to_lru_cache_str_timeout(&readWriteGlobals->flowUsersCache, key, "", 5 /* (sec) Negative expire time */);
    }

    bkt->core.user.user_searched = 1;
  }
}

/* ****************************************************** */

void setServerName(FlowHashBucket *bkt, char *name) {
  if((name != NULL) && (bkt->core.server.name == NULL)) {
    if(bkt->core.server.name) free(bkt->core.server.name);
    bkt->core.server.name = strdup(name), bkt->core.server.server_searched = 1;
  }
}

/* ****************************************************** */

void mapServerName(FlowHashBucket *bkt) {
  if(!bkt->core.server.server_searched) {
    char *server_ip, buf[128];

    server_ip = _intoa((bkt->core.tuple.key.k.ipKey.sport > bkt->core.tuple.key.k.ipKey.dport) ?
		       bkt->core.tuple.key.k.ipKey.dst : bkt->core.tuple.key.k.ipKey.src,
		       buf, sizeof(buf));

    bkt->core.server.name = getCacheDataStrKey("dns.cache.", 0, server_ip);
    bkt->core.server.server_searched = 1;
  }
}

/* ****************************************************** */

void teid2user(FlowHashBucket *bkt, u_int32_t teid) {
  if(!bkt->core.user.user_searched) {
    char *user, key[64];

    snprintf(key, sizeof(key), "teid.%u", teid);
    user = find_lru_cache_str(&readWriteGlobals->flowUsersCache, key);

    if(user != NULL) {
      if(user[0] != '\0') {
	bkt->core.user.username = strdup(user);
	bkt->core.user.user_searched = 1;
      } else {
	/* The cache said that we have no result yet (string is "") */
      }

      return;
    }

    user = getCacheDataNumKey("teid.", 0, teid);

    if(user != NULL) {
      bkt->core.user.username = user;
      add_to_lru_cache_str_timeout(&readWriteGlobals->flowUsersCache, key, user, 60 /* (sec) Positive expire time */);
    } else
      add_to_lru_cache_str_timeout(&readWriteGlobals->flowUsersCache, key, "", 5 /* (sec) Negative expire time */);

    bkt->core.user.user_searched = 1;
  }
}

/* ****************************************************** */

static void ip2user(FlowHashBucket *bkt, u_int32_t ipv4, char *keybuf, u_int keybuf_len) {
  char ipbuf[24];

  snprintf(keybuf, keybuf_len, "%s", _intoaV4(ipv4, ipbuf, sizeof(ipbuf)));
  id2user(bkt, keybuf);
}

/* *********************************************** */

static void accoutTrafficPerIMSI(FlowHashBucket *bkt) {
  char/* buf[128], */ key[64], *semicolumn;
  u_int32_t client_ip, id;
  u_int32_t bytes_up, bytes_down;

  if((!readOnlyGlobals.aggregateTrafficPerIMSI)
     || (bkt->core.user.username == NULL))
    return;

  semicolumn = strrchr(bkt->core.user.username, ';');
  if(!semicolumn) {
    traceEvent(TRACE_WARNING, "Invalid IMSI format (%s)", bkt->core.user.username);
    return;
  } else
    client_ip = atol(&semicolumn[1]);

  /*
    IMSI/NSAPI/LAC/CCI/CSAC/IPv4
    123460000026315;5;0;0;0;123456789
  */
  snprintf(key, sizeof(key), "gtp.%s", bkt->core.user.username);
  if(strlen(key) > 14) {
    semicolumn = strchr(&key[14], ';');
    semicolumn = strchr(&semicolumn[1], ';');
    semicolumn[0] = '\0';
  }

  //traceEvent(TRACE_NORMAL, "==> %s", bkt->core.user.username ? bkt->core.user.username : "???");

  if(bkt->core.tuple.key.k.ipKey.src.ipType.ipv4 == client_ip)
    bytes_up = bkt->core.tuple.flowCounters.bytesSent, bytes_down = bkt->core.tuple.flowCounters.bytesRcvd;
  else
    bytes_up = bkt->core.tuple.flowCounters.bytesRcvd, bytes_down = bkt->core.tuple.flowCounters.bytesSent;

  id = bytes_up % MAX_NUM_REDIS_CONNECTIONS;
  incrHashCacheKeyValueNumber(key, id, "bytes.up", bytes_up);
  incrHashCacheKeyValueNumber(key, id, "bytes.down", bytes_down);

  if(bkt->ext && (bkt->core.tuple.key.k.ipKey.proto == IPPROTO_TCP)) {
    u_int32_t retr_up, retr_down, retr;

    if(bkt->core.tuple.key.k.ipKey.src.ipType.ipv4 == client_ip)
      retr_up  = bkt->ext->protoCounters.tcp.bytesSentRetransmitted, retr_down = bkt->ext->protoCounters.tcp.bytesRcvdRetransmitted;
    else
      retr_up  = bkt->ext->protoCounters.tcp.bytesRcvdRetransmitted, retr_down = bkt->ext->protoCounters.tcp.bytesSentRetransmitted;

    incrHashCacheKeyValueNumber(key, id, "bytes.tcp_noretr_up", bytes_up-retr_up);
    incrHashCacheKeyValueNumber(key, id, "bytes.tcp_noretr_down", bytes_down-retr_down);
    incrHashCacheKeyValueNumber(key, id, "pkts.tcp",  bkt->core.tuple.flowCounters.pktSent+bkt->core.tuple.flowCounters.pktRcvd);

    if((retr = bkt->ext->protoCounters.tcp.pktRcvdRetransmitted + bkt->ext->protoCounters.tcp.pktSentRetransmitted) > 0)
      incrHashCacheKeyValueNumber(key, id, "pkts.retr_tcp", retr);    
  }
}

/* *********************************************** */

void mapTrafficToUser(FlowHashBucket *bkt) {
  if(bkt->core.user.user_searched) return;

  /* 1 - Search tunnels (if any) */
  if(bkt->ext != NULL) {
    if(bkt->ext->src2dst_tunnel_id != 0) {
      teid2user(bkt, bkt->ext->src2dst_tunnel_id);
      if(bkt->core.user.user_searched /* Found */) {
	accoutTrafficPerIMSI(bkt);
	return;
      }
    }

    if(bkt->ext->dst2src_tunnel_id != 0) {
      teid2user(bkt, bkt->ext->dst2src_tunnel_id);
      if(bkt->core.user.user_searched /* Found */) {
	accoutTrafficPerIMSI(bkt);
	return;
      }
    }
  }

  if(readOnlyGlobals.enableRadiusPlugin
     || readOnlyGlobals.enableDiameterPlugin) {
    /* 2 - Search IPs */
    if(bkt->core.tuple.key.k.ipKey.src.ipVersion == 4) {
      /* We search only IPv4 */
      char buf[32];

      /* Try with the client first */
      if(bkt->core.tuple.key.k.ipKey.sport < bkt->core.tuple.key.k.ipKey.dport) {
	ip2user(bkt, bkt->core.tuple.key.k.ipKey.src.ipType.ipv4, buf, sizeof(buf));
	if(bkt->core.user.user_searched /* Found */) return;
	ip2user(bkt, bkt->core.tuple.key.k.ipKey.dst.ipType.ipv4, buf, sizeof(buf));
      } else {
	ip2user(bkt, bkt->core.tuple.key.k.ipKey.dst.ipType.ipv4, buf, sizeof(buf));
	if(bkt->core.user.user_searched /* Found */) return;
	ip2user(bkt, bkt->core.tuple.key.k.ipKey.src.ipType.ipv4, buf, sizeof(buf));
      }
    }
  }
}

/* **************************************************** */

int set_tcp_client_address(char *host_and_port, struct sockaddr_in *servaddr) {
  char buf[256], *host, *port;
  struct hostent *server;

  snprintf(buf, sizeof(buf), "%s", host_and_port);
  host = strtok(buf, ":");
  if(!host) return(-1);

  port = strtok(NULL, ":");
  if(!port) return(-2);

  if(!(server = gethostbyname(host)))
    return(-3);

  memset(servaddr, 0, sizeof(struct sockaddr_in));
  servaddr->sin_family = AF_INET;
  servaddr->sin_addr.s_addr = (*(struct in_addr *)server->h_addr_list[0]).s_addr;
  servaddr->sin_port = htons(atoi(port));

  return(0);
}

/* **************************************************** */

void close_socket(int sock) {
  if(sock != -1) {
#ifndef WIN32
    shutdown(sock, SHUT_RDWR);
#endif
    close(sock);
  }
}

/* **************************************************** */

int connect_to_server(struct sockaddr *servaddr) {
  int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
  int set = 1;

  if(tcp_socket == -1) {
    printf("Unable to create a socket [%s/%u]\n", strerror(errno), errno);
    return(-1);
  }

#ifndef linux
#ifndef WIN32
  setsockopt(tcp_socket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
#endif
#endif
  setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&set, sizeof(int));

  if(connect(tcp_socket, servaddr, sizeof(struct sockaddr)) != 0) {
    close_socket(tcp_socket);
    return(-1);
  }

  return(tcp_socket);
}

/* **************************************************** */

int send_tcp(int sock, char *msg, u_int msg_len) {
  int flags = 0;

#ifdef linux
  flags = MSG_NOSIGNAL;
#endif

  return(send(sock, msg, msg_len, flags));
}

/* **************************************************** */

