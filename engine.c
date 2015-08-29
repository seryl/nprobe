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

// #define ACCURATE_HASH 1

/* ****************************************************** */

void freenDPI(FlowHashBucket *myBucket) {
  if(myBucket->core.l7.proto.ndpi.flow) {
    free(myBucket->core.l7.proto.ndpi.flow);
    myBucket->core.l7.proto.ndpi.flow = NULL;
  }

  if(myBucket->core.l7.proto.ndpi.src) {
    free(myBucket->core.l7.proto.ndpi.src);
    myBucket->core.l7.proto.ndpi.src = NULL;
  }

  if(myBucket->core.l7.proto.ndpi.dst) {
    free(myBucket->core.l7.proto.ndpi.dst);
    myBucket->core.l7.proto.ndpi.dst = NULL;
  }
}

/* ****************************************************** */

void allocateFlowHash(int thread_id) {
  u_int mallocSize = sizeof(FlowHashBucket*)*readOnlyGlobals.flowHashSize;

  readWriteGlobals->theFlowHash[thread_id] = (FlowHashBucket**)calloc(1, mallocSize);
  if(readWriteGlobals->theFlowHash[thread_id] == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory");
    exit(-1);
  }

  readWriteGlobals->expireFlowListHead[thread_id] = NULL, readWriteGlobals->expireFlowListTail[thread_id] = NULL;
  readWriteGlobals->idleFlowListHead[thread_id] = NULL, readWriteGlobals->idleFlowListTail[thread_id] = NULL;
}

/* ****************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte;

    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************** */

char* _intoa(IpAddress addr, char* buf, u_short bufLen) {
  if((addr.ipVersion == 4) || (addr.ipVersion == 0 /* Misconfigured */))
    return(_intoaV4(addr.ipType.ipv4, buf, bufLen));
  else {
    char *ret;

#if 0
    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, &buf[1], bufLen-2);
#else
    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, buf, bufLen);
#endif

    if(ret == NULL) {
      traceEvent(TRACE_WARNING, "Internal error (buffer too short)");
      buf[0] = '\0';
    }
#if 0
    else {
      int len = strlen(ret);

      buf[0] = '[';
      buf[len+1] = ']';
      buf[len+2] = '\0';
    }
#endif

    return(buf);
  }
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ****************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* ******************************************************** */

/*
  We need to create a key that is more reliable than the hash value
  that can easily lead to false positives
*/
u_int64_t getLRUCacheKey(FlowHashBucket *bkt) {
  u_int64_t key =
    (bkt->core.tuple.flow_hash /* << 32 */)
    + (bkt->core.tuple.key.k.ipKey.proto << 24)
    + (bkt->core.tuple.key.vlanId << 16)
    + (bkt->core.tuple.key.k.ipKey.sport * bkt->core.tuple.key.k.ipKey.dport);

  return(key);
}

/* ******************************************************** */

void setnDPIProto(FlowHashBucket *bkt, u_int16_t proto_id) {
  if(proto_id != NDPI_PROTOCOL_UNKNOWN) {
    bkt->core.l7.proto.ndpi.ndpi_proto = proto_id,
      bkt->core.l7.proto_type = NDPI_PROTO_TYPE,
      bkt->core.l7.proto.ndpi.detection_completed = 1;

    if(!readOnlyGlobals.enableL7BridgePlugin)
      freenDPI(bkt);
  }
}

/* ******************************************************** */

#define MAX_PKTS   7

void setPayload(FlowHashBucket *bkt,
		const struct pcap_pkthdr *h, u_char *p,
		u_int16_t ip_offset, u_char *payload,
		int payloadLen, FlowDirection direction) {
  if(bkt->core.l7.proto.ndpi.detection_completed
     || (!readOnlyGlobals.enable_l7_protocol_discovery)
     || (bkt->core.l7.proto_type != NO_PROTO_TYPE)
     || (bkt->core.l7.proto.ndpi.ndpi_proto != NDPI_PROTOCOL_UNKNOWN))
    return;

  /* Initial bytes only please */
  if((bkt->core.tuple.flowCounters.pktSent < MAX_PKTS)
     && (bkt->core.tuple.flowCounters.pktRcvd < MAX_PKTS)) {
    u_int16_t ndpi_proto;

    if(!bkt->core.l7.proto.ndpi.searched_port_based_protocol) {
      ndpi_proto = ndpi_find_port_based_protocol(readOnlyGlobals.l7.l7handler,
						 bkt->core.tuple.key.k.ipKey.proto,
						 bkt->core.tuple.key.k.ipKey.src.ipType.ipv4,
						 bkt->core.tuple.key.k.ipKey.sport,
						 bkt->core.tuple.key.k.ipKey.dst.ipType.ipv4,
						 bkt->core.tuple.key.k.ipKey.dport);
      setnDPIProto(bkt, ndpi_proto);
      bkt->core.l7.proto.ndpi.searched_port_based_protocol = 1;
    }

    if((bkt->core.l7.proto.ndpi.ndpi_proto == NDPI_PROTOCOL_UNKNOWN)
       && bkt->core.l7.proto.ndpi.flow) {
      u_int64_t when = ((u_int64_t) h->ts.tv_sec) * 1000 /* detection_tick_resolution */
	+ h->ts.tv_usec / 1000 /* (1000000 / detection_tick_resolution) */;

      /* traceEvent(TRACE_NORMAL, "[caplen=%u/len=%u][ip_offset=%u][payloadLen=%u][diff=%d]",
	 h->caplen, h->len, ip_offset, payloadLen, h->caplen-ip_offset);
      */
      ndpi_proto = ndpi_detection_process_packet(readOnlyGlobals.l7.l7handler,
						 bkt->core.l7.proto.ndpi.flow,
						 (u_int8_t *)&p[ip_offset],
						 h->caplen-ip_offset, when,
						 bkt->core.l7.proto.ndpi.src,
						 bkt->core.l7.proto.ndpi.dst);

      setnDPIProto(bkt, ndpi_proto);
    }
  } else {
    bkt->core.l7.proto.ndpi.detection_completed = 1, bkt->core.l7.proto_type = NDPI_PROTO_TYPE;
    freenDPI(bkt);
  }
}

/* ************************************************* */

static void updateApplLatency(u_short proto, FlowHashBucket *bkt,
			      FlowDirection direction, struct timeval *stamp) {
  if((!readOnlyGlobals.enableLatencyStats)
     || (bkt->ext == NULL)
     || (bkt->ext->extensions == NULL)
     )
    return;

  if(!applLatencyComputed(bkt->ext)) {
    /*
      src ---------> dst -+
      | Application
      | Latency
      <--------      -+

      NOTE:
      1. Application latency is calculated as the time passed since the first
      packet sent the first packet on the opposite direction is received.
      2. Application latency is calculated only on the first packet

    */

    if(direction == src2dst_direction) {
      /* src->dst */
      if(bkt->ext->extensions->src2dstApplLatency.tv_sec == 0)
	bkt->ext->extensions->src2dstApplLatency.tv_sec = stamp->tv_sec, bkt->ext->extensions->src2dstApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->ext->extensions->dst2srcApplLatency.tv_sec != 0) {
	bkt->ext->extensions->dst2srcApplLatency.tv_sec  = bkt->ext->extensions->src2dstApplLatency.tv_sec-bkt->ext->extensions->dst2srcApplLatency.tv_sec;

	if((bkt->ext->extensions->src2dstApplLatency.tv_usec-bkt->ext->extensions->dst2srcApplLatency.tv_usec) < 0) {
	  bkt->ext->extensions->dst2srcApplLatency.tv_usec = 1000000 + bkt->ext->extensions->src2dstApplLatency.tv_usec - bkt->ext->extensions->dst2srcApplLatency.tv_usec;
	  if(bkt->ext->extensions->dst2srcApplLatency.tv_usec > 1000000) bkt->ext->extensions->dst2srcApplLatency.tv_usec = 1000000;
	  bkt->ext->extensions->dst2srcApplLatency.tv_sec--;
	} else
	  bkt->ext->extensions->dst2srcApplLatency.tv_usec = bkt->ext->extensions->src2dstApplLatency.tv_usec-bkt->ext->extensions->dst2srcApplLatency.tv_usec;

	bkt->ext->extensions->src2dstApplLatency.tv_sec = 0, bkt->ext->extensions->src2dstApplLatency.tv_usec = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags));
      }
    } else {
      /* dst -> src */
      if(bkt->ext->extensions->dst2srcApplLatency.tv_sec == 0)
	bkt->ext->extensions->dst2srcApplLatency.tv_sec = stamp->tv_sec, bkt->ext->extensions->dst2srcApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->ext->extensions->src2dstApplLatency.tv_sec != 0) {
	bkt->ext->extensions->src2dstApplLatency.tv_sec  = bkt->ext->extensions->dst2srcApplLatency.tv_sec-bkt->ext->extensions->src2dstApplLatency.tv_sec;

	if((bkt->ext->extensions->dst2srcApplLatency.tv_usec-bkt->ext->extensions->src2dstApplLatency.tv_usec) < 0) {
	  bkt->ext->extensions->src2dstApplLatency.tv_usec = 1000000 + bkt->ext->extensions->dst2srcApplLatency.tv_usec - bkt->ext->extensions->src2dstApplLatency.tv_usec;
	  if(bkt->ext->extensions->src2dstApplLatency.tv_usec > 1000000) bkt->ext->extensions->src2dstApplLatency.tv_usec = 1000000;
	  bkt->ext->extensions->src2dstApplLatency.tv_sec--;
	} else
	  bkt->ext->extensions->src2dstApplLatency.tv_usec = bkt->ext->extensions->dst2srcApplLatency.tv_usec-bkt->ext->extensions->src2dstApplLatency.tv_usec;

	bkt->ext->extensions->dst2srcApplLatency.tv_sec = 0, bkt->ext->extensions->dst2srcApplLatency.tv_usec = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags));
      }
    }

#if 0
    if(applLatencyComputed(bkt)) {
      char buf[64], buf1[64];

      if(bkt->ext->extensions->src2dstApplLatency.tv_sec || bkt->ext->extensions->src2dstApplLatency.tv_usec)
	printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->ext->extensions->src2dstApplLatency.tv_sec*1000
						   +(float)bkt->ext->extensions->src2dstApplLatency.tv_usec/1000),
	       _intoa(bkt->src, buf, sizeof(buf)), _intoa(bkt->dst, buf1, sizeof(buf1)));
      else
	printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->ext->extensions->dst2srcApplLatency.tv_sec*1000
						   +(float)bkt->ext->extensions->dst2srcApplLatency.tv_usec/1000),
	       _intoa(bkt->dst, buf, sizeof(buf)), _intoa(bkt->src, buf1, sizeof(buf1)));
    }
#endif
  }
}

/* ****************************************************** */

static void updatePktLenStats(FlowHashBucket *bkt, FlowDirection direction,
			      struct timeval *when,
			      u_int pkt_len, u_int8_t ttl_val, u_int numPkts) {
  if(pkt_len > bkt->ext->flowCounters.pktSize.longest)
    bkt->ext->flowCounters.pktSize.longest = pkt_len;

  if((bkt->ext->flowCounters.pktSize.shortest == 0)
     || (pkt_len < bkt->ext->flowCounters.pktSize.shortest))
    bkt->ext->flowCounters.pktSize.shortest = pkt_len;

  if(bkt->ext->extensions && readOnlyGlobals.enablePacketStats) {
    EtherStats *eth = (direction == src2dst_direction) ? &bkt->ext->extensions->etherstats.src2dst : &bkt->ext->extensions->etherstats.dst2src;
    TTLStats   *ttl = (direction == src2dst_direction) ? &bkt->ext->extensions->ttlstats.src2dst : &bkt->ext->extensions->ttlstats.dst2src;
    struct timeval delta;

    /*
       The value of numPkts must be 1, but in case of fragmented packets it can be more than one. In this
       case stats are not too precise as more packets are collapsed into one however we believe it is
       precise enough for our calculations belo
    */
    if(pkt_len <= 128)       eth->num_pkts_up_to_128_bytes += numPkts;
    else if(pkt_len <= 256)  eth->num_pkts_128_to_256_bytes += numPkts;
    else if(pkt_len <= 512)  eth->num_pkts_256_to_512_bytes += numPkts;
    else if(pkt_len <= 1024) eth->num_pkts_512_to_1024_bytes += numPkts;
    else if(pkt_len <= 1514) eth->num_pkts_1024_to_1514_bytes += numPkts;
    else eth->num_pkts_over_1514_bytes += numPkts;

    if(ttl_val == 1)         ttl->num_pkts_eq_1 += numPkts;
    else if(ttl_val <= 5)    ttl->num_pkts_2_5 += numPkts;
    else if(ttl_val <= 32)   ttl->num_pkts_5_32 += numPkts;
    else if(ttl_val <= 64)   ttl->num_pkts_32_64 += numPkts;
    else if(ttl_val <= 96)   ttl->num_pkts_64_96 += numPkts;
    else if(ttl_val <= 128)  ttl->num_pkts_96_128 += numPkts;
    else if(ttl_val <= 160)  ttl->num_pkts_128_160 += numPkts;
    else if(ttl_val <= 192)  ttl->num_pkts_160_192 += numPkts;
    else if(ttl_val <= 224)  ttl->num_pkts_192_224 += numPkts;
    else ttl->num_pkts_224_255 += numPkts;

    if(direction == src2dst_direction) {
      if(bkt->core.tuple.flowTimers.lastSeenSent.tv_sec == 0) {
	// diff = 0;
    } else {
	timeval_diff(&bkt->core.tuple.flowTimers.lastSeenSent, when, &delta, 0);
	// diff = toMs(&delta);
      }
    } else {
      if(bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec == 0) {
	// diff = 0;
      } else {
	timeval_diff(&bkt->core.tuple.flowTimers.lastSeenRcvd, when, &delta, 0);
	// diff = toMs(&delta);
      }
    }
  }
}

/* ****************************************************** */

static void updateTTL(FlowHashBucket *bkt, FlowDirection direction, u_int8_t ttl) {
  if(direction == src2dst_direction) {
    if(ttl > 0) {
      if(bkt->ext->src2dstMinTTL == 0)
	bkt->ext->src2dstMinTTL = ttl;
      else
	bkt->ext->src2dstMinTTL = min(bkt->ext->src2dstMinTTL, ttl);
    }

    bkt->ext->src2dstMaxTTL = max(bkt->ext->src2dstMaxTTL, ttl);
  } else {
    if(ttl > 0) {
      if(bkt->ext->dst2srcMinTTL == 0)
	bkt->ext->dst2srcMinTTL = ttl;
      else
	bkt->ext->dst2srcMinTTL = min(bkt->ext->dst2srcMinTTL, ttl);
    }

    bkt->ext->dst2srcMaxTTL = max(bkt->ext->dst2srcMaxTTL, ttl);
  }
}

/* ****************************************************** */

static void updateTos(FlowHashBucket *bkt, FlowDirection direction, u_int8_t tos) {
  if(direction == src2dst_direction)
    bkt->ext->src2dstTos |= tos;
  else
    bkt->ext->dst2srcTos |= tos;
}

/* ****************************************************** */

void timeval_diff(struct timeval *begin, struct timeval *end,
		  struct timeval *result, u_short divide_by_two) {
  if(end->tv_sec >= begin->tv_sec) {
    result->tv_sec = end->tv_sec-begin->tv_sec;

    if((end->tv_usec - begin->tv_usec) < 0) {
      result->tv_usec = 1000000 + end->tv_usec - begin->tv_usec;
      if(result->tv_usec > 1000000) begin->tv_usec = 1000000;
      result->tv_sec--;
    } else
      result->tv_usec = end->tv_usec-begin->tv_usec;

    if(divide_by_two)
      result->tv_sec /= 2, result->tv_usec /= 2;
  } else
    result->tv_sec = 0, result->tv_usec = 0;
}

/* ****************************************************** */

static char* print_flags(u_int8_t flags, char *buf, u_int buf_len) {
  snprintf(buf, buf_len, "%s%s%s%s%s",
	   (flags & TH_SYN) ? " SYN" : "",
	   (flags & TH_ACK) ? " ACK" : "",
	   (flags & TH_FIN) ? " FIN" : "",
	   (flags & TH_RST) ? " RST" : "",
	   (flags & TH_PUSH) ? " PUSH" : "");
  if(buf[0] == ' ')
    return(&buf[1]);
  else
    return(buf);
}

/* ****************************************************** */

static u_int32_t getNextTcpSeq(u_int8_t tcpFlags,
			       u_int32_t tcpSeqNum,
			       u_int32_t payloadLen) {

  return(tcpSeqNum + ((tcpFlags & TH_SYN) ? 1 : 0) + payloadLen);
}

/* ****************************************************** */

static u_int8_t updateTcpSeq(struct timeval *when,
			     FlowHashBucket *bkt, FlowDirection direction,
			     u_int8_t tcpFlags, u_int32_t tcpSeqNum,
			     u_int32_t tcpAckNum, u_int32_t payloadLen,
			     u_int16_t tcpWin,
			     const struct pcap_pkthdr *h, u_char *p, u_int32_t len) {
   u_int32_t nextSeqNum;
   u_int8_t retransmitted_pkt = 0;
   u_int8_t update_last_seqnum = 1;

   if(!readOnlyGlobals.enableTcpSeqStats) return(0);
   if(bkt->ext->extensions == NULL) return(0);

   // if(unlikely(readOnlyGlobals.enable_debug)) traceEvent(TRACE_ERROR, "updateTcpSeq(seqNum=%u, ackNum=%u)", tcpSeqNum, tcpAckNum);

   /* Not always nProbe gets the TCP sequence number */
   if(tcpSeqNum == 0) return(0);

   nextSeqNum = getNextTcpSeq(tcpFlags, tcpSeqNum, payloadLen);

   if(bkt->ext->lastPktDirection != direction) {
     double msLatency, lastLatency;

     /*
       In case we're in the middle of a connection, the network delay
       is the miminum (yet > 0) that we have observed so far. This is
       because some communications might be triggered based on some events
       and thus we need to take as latency the minimum of observed event
       latency
     */
     if(direction == src2dst_direction) {
       if((bkt->ext->extensions->tcpseq.src2dst.next == tcpSeqNum)
	  && (bkt->ext->extensions->tcpseq.dst2src.next == tcpAckNum)
	  && (bkt->ext->extensions->synTime.tv_sec == 0)
	  && ((bkt->ext->extensions->clientNwLatency.tv_sec == 0) && (bkt->ext->extensions->clientNwLatency.tv_usec == 0))) {
	 /* This is what we waited for */

	 msLatency = toMs(when) - toMs(&bkt->core.tuple.flowTimers.lastSeenRcvd);
	 lastLatency = toMs(&bkt->ext->extensions->clientNwLatency);

	 if((msLatency < lastLatency) || (lastLatency == 0)) {
	   timeval_diff(&bkt->core.tuple.flowTimers.lastSeenRcvd, when, &bkt->ext->extensions->clientNwLatency, 1);

	   if(0)
	     traceEvent(TRACE_NORMAL, "Recomputed client latency [Client: %.2f ms]",
			(float)(bkt->ext->extensions->clientNwLatency.tv_sec*1000+(float)bkt->ext->extensions->clientNwLatency.tv_usec/1000));
	 }
       }
     } else {
       if((bkt->ext->extensions->tcpseq.dst2src.next == tcpSeqNum)
	  && (bkt->ext->extensions->tcpseq.src2dst.next == tcpAckNum)
	  && ((bkt->ext->extensions->serverNwLatency.tv_sec == 0) && (bkt->ext->extensions->serverNwLatency.tv_usec == 0))) {
	 /* This is what we waited for */
	 msLatency = toMs(when) - toMs(&bkt->core.tuple.flowTimers.lastSeenSent);
	 lastLatency = toMs(&bkt->ext->extensions->serverNwLatency);

	 if((msLatency < lastLatency) || (lastLatency == 0)) {
	   timeval_diff(&bkt->core.tuple.flowTimers.lastSeenSent, when, &bkt->ext->extensions->serverNwLatency, 1);

	   if(0)
	     traceEvent(TRACE_NORMAL, "Recomputed server latency [Server: %.2f ms]",
			(float)(bkt->ext->extensions->serverNwLatency.tv_sec*1000+(float)bkt->ext->extensions->serverNwLatency.tv_usec/1000));

	 }
       }
     }
   }

 #if 0
   if(unlikely(readOnlyGlobals.enable_debug))
     traceEvent(TRACE_ERROR, "[%s] [payload_len=%u][%s][received=%u][expected=%u][next=%u][ack=%u][ooo=%u][retransmitted=%u][latency=%.2f ms]",
		(direction == src2dst_direction) ? "src->dst" : "dst->src",
		payloadLen, print_flags(tcpFlags, buf, sizeof(buf)), tcpSeqNum,
		(direction == src2dst_direction) ? bkt->ext->extensions->tcpseq.src2dst.next : bkt->ext->extensions->tcpseq.dst2src.next,
		nextSeqNum, tcpAckNum,
		(direction == src2dst_direction) ? bkt->ext->protoCounters.tcp.sentOOOrder :
		bkt->ext->protoCounters.tcp.rcvdOOOrder,
		(direction == src2dst_direction) ? bkt->ext->protoCounters.tcp.pktSentRetransmitted :
		bkt->ext->protoCounters.tcp.pktRcvdRetransmitted,
		(direction == src2dst_direction) ? toMs(&bkt->ext->extensions->clientNwLatency) : toMs(&bkt->ext->extensions->serverNwLatency));
 #endif

   if(direction == src2dst_direction) {
     /* src -> dst */

     if(bkt->ext->extensions->tcpseq.src2dst.next > 0) {
       if(bkt->ext->extensions->tcpseq.src2dst.next != tcpSeqNum) {
	 if(bkt->ext->extensions->tcpseq.src2dst.last == tcpSeqNum) {
	   bkt->ext->protoCounters.tcp.pktSentRetransmitted++, retransmitted_pkt = 1;
	   bkt->ext->protoCounters.tcp.bytesSentRetransmitted += len;
	   if(unlikely(readOnlyGlobals.enable_debug))
	     traceEvent(TRACE_WARNING, "Found retransmitted packet src->dst [seq: %u][last: %u][next: %u][win: %u]",
			tcpSeqNum, bkt->ext->extensions->tcpseq.src2dst.last,
			bkt->ext->extensions->tcpseq.src2dst.next, tcpWin);
	 } else if(bkt->ext->extensions->tcpseq.src2dst.last > (tcpSeqNum-1)) {
	   bkt->ext->protoCounters.tcp.sentOOOrder++;
	   update_last_seqnum = 0;
	   if(unlikely(readOnlyGlobals.enable_debug)) {
	     traceEvent(TRACE_WARNING, "Found OoOrder packet src->dst [seq: %u][expected: %u]",
			tcpSeqNum, bkt->ext->extensions->tcpseq.src2dst.next);
	     dump_bad_packet(h, p);
	   }
	 }
       }
     }

     bkt->ext->extensions->tcpseq.src2dst.next = nextSeqNum;
     if(update_last_seqnum) bkt->ext->extensions->tcpseq.src2dst.last = tcpSeqNum;
   } else {
     /* dst -> src */

     if(bkt->ext->extensions->tcpseq.dst2src.next > 0) {
       if(bkt->ext->extensions->tcpseq.dst2src.next != tcpSeqNum) {
	 if(bkt->ext->extensions->tcpseq.dst2src.last == tcpSeqNum) {
	   bkt->ext->protoCounters.tcp.pktRcvdRetransmitted++, retransmitted_pkt = 1;
	   bkt->ext->protoCounters.tcp.bytesRcvdRetransmitted += len;

	   // 01/Sep/2012 21:30:05 [engine.c:496] WARNING: Found retransmitted packet dst->src [seq: 1114407503][last: 1114410423][next: 1114413343][win: 63352]

	   if(unlikely(readOnlyGlobals.enable_debug))
	     traceEvent(TRACE_WARNING, "Found retransmitted packet dst->src [seq: %u][last: %u][next: %u][win: %u]",
			tcpSeqNum, bkt->ext->extensions->tcpseq.dst2src.last,
			bkt->ext->extensions->tcpseq.dst2src.next, tcpWin);
	 } else if(bkt->ext->extensions->tcpseq.dst2src.last > (tcpSeqNum-1)) {
	   bkt->ext->protoCounters.tcp.rcvdOOOrder++;
	   update_last_seqnum = 0;
	   if(unlikely(readOnlyGlobals.enable_debug)) {
	     traceEvent(TRACE_WARNING, "Found OoOrder packet dst->src [seq: %u][expected: %u]",
			tcpSeqNum, bkt->ext->extensions->tcpseq.dst2src.next);
	     dump_bad_packet(h, p);
	   }
	 }
       }
     }

     bkt->ext->extensions->tcpseq.dst2src.next = nextSeqNum;
     if(update_last_seqnum) bkt->ext->extensions->tcpseq.dst2src.last = tcpSeqNum;
   }

   return(retransmitted_pkt);
 }

 /* ****************************************************** */

 /*
   Client           nProbe         Server
   ->    SYN                       synTime
   <-    SYN|ACK                   synAckTime
   ->    ACK                       ackTime

   serverNwLatency = (synAckTime - synTime) / 2
   clientNwLatency = (ackTime - synAckTime) / 2
 */

static void updateTcpFlags(FlowHashBucket *bkt, FlowDirection direction,
			   struct timeval *stamp, u_int8_t flags,
			   u_int16_t tcpMaxSegmentSize, u_int8_t tcpWinScale) {
#if 0
   char buf[32];

   traceEvent(TRACE_NORMAL, "updateTcpFlags() [%s][direction: %s]",
	      print_flags(flags, buf, sizeof(buf)),
	      direction == src2dst_direction ? "src->dst" : "dst->src");
 #endif

   if(unlikely(bkt->ext->beginInitiator == unknown_direction)) {
     if(flags == TH_SYN)
       bkt->ext->beginInitiator = direction;
     else if(flags == (TH_SYN|TH_ACK))
       bkt->ext->beginInitiator = (direction == src2dst_direction) ? dst2src_direction : src2dst_direction;
   }

   /* This is a termination */
   if(((flags & TH_FIN) == TH_FIN) || ((flags & TH_RST) == TH_RST)) {
     /* Check if this is the first FIN/RST */
     if(((bkt->ext->protoCounters.tcp.src2dstTcpFlags & (TH_FIN|TH_RST)) == 0)
	&& ((bkt->ext->protoCounters.tcp.dst2srcTcpFlags & (TH_FIN|TH_RST)) == 0))
       bkt->ext->terminationInitiator = direction;
   }

   if(bkt->ext->extensions == NULL) return;

   if(flags == TH_SYN) {
     bkt->ext->protoCounters.tcp.tcpMaxSegmentSize = tcpMaxSegmentSize,
       bkt->ext->protoCounters.tcp.tcpWinScale = tcpWinScale;
   }

   if(!nwLatencyComputed(bkt->ext)) {
     if((flags == TH_SYN) && (bkt->ext->extensions->synTime.tv_sec == 0 /* No retransmission */)) {
       bkt->ext->extensions->synTime.tv_sec = stamp->tv_sec,
       bkt->ext->extensions->synTime.tv_usec = stamp->tv_usec;
     } else if((flags == (TH_SYN | TH_ACK)) && (bkt->ext->extensions->synAckTime.tv_sec == 0 /* No retransmission */)) {
       if(bkt->ext->extensions->synTime.tv_sec != 0) {
	 bkt->ext->extensions->synAckTime.tv_sec  = stamp->tv_sec,
	 bkt->ext->extensions->synAckTime.tv_usec = stamp->tv_usec;
	 timeval_diff(&bkt->ext->extensions->synTime, stamp, &bkt->ext->extensions->serverNwLatency, 1);
       }
     } else if(flags == TH_ACK) {
       if(bkt->ext->extensions->synTime.tv_sec == 0) {
	 /* We missed the SYN flag */
	 NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED,   &(bkt->ext->flags));
	 NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->ext->flags)); /* We cannot calculate it as we have
									   missed the 3-way handshake */
	 return;
       }

       if(((direction == src2dst_direction)    && (bkt->ext->protoCounters.tcp.src2dstTcpFlags != TH_SYN))
	  || ((direction == dst2src_direction) && (bkt->ext->protoCounters.tcp.dst2srcTcpFlags != TH_SYN)))
	 return; /* Wrong flags */

       if(bkt->ext->extensions->synAckTime.tv_sec > 0) {
	 timeval_diff(&bkt->ext->extensions->synAckTime, stamp, &bkt->ext->extensions->clientNwLatency, 1);
	 NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED, &(bkt->ext->flags));
	 updateApplLatency(IPPROTO_TCP, bkt, direction, stamp);

 #if 0
	 if(unlikely(readOnlyGlobals.enable_debug))
	   traceEvent(TRACE_NORMAL, "[Client: %.2f ms][Server: %.2f ms]\n",
		      (float)(bkt->ext->extensions->clientNwLatency.tv_sec*1000+(float)bkt->ext->extensions->clientNwLatency.tv_usec/1000),
		      (float)(bkt->ext->extensions->serverNwLatency.tv_sec*1000+(float)bkt->ext->extensions->serverNwLatency.tv_usec/1000));
 #endif
       }
     }
   } else {
     /* Nw latency computed */
     if(!applLatencyComputed(bkt->ext)) {
       /*
	 src ---------> dst -+
	 | Application
	 | Latency
	 <--------      -+

	 NOTE:
	 1. Application latency is calculated as the time passed since the first
	 packet sent after the 3-way handshake until the first packet on
	 the opposite direction is received.
	 2. Application latency is calculated only on the first packet
       */

       updateApplLatency(IPPROTO_TCP, bkt, direction, stamp);
     }
   }
 }

 /* ****************************************************** */

 /*
   1 - equal
   0 - different
 */
 int cmpIpAddress(IpAddress *src, IpAddress *dst) {
   if(src->ipVersion != dst->ipVersion) return(0);

   if(src->ipVersion == 4) {
     return(src->ipType.ipv4 == dst->ipType.ipv4 ? 1 : 0);
   } else {
     return(!memcmp(&src->ipType.ipv6, &dst->ipType.ipv6, sizeof(struct in6_addr)));
   }
 }

 /* ****************************************************** */

 u_int32_t get_flow_serial() {
   if(unlikely(readOnlyGlobals.useLocks)) {
     u_int32_t serial;

 #ifdef HAVE_BUILTIN_ATOMIC
     serial = __sync_add_and_fetch(&readWriteGlobals->flow_serial, 1);
 #else
     pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
     serial = readWriteGlobals->flow_serial;
     readWriteGlobals->flow_serial++;
     pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
 #endif

     return(serial);
   } else
     return(readWriteGlobals->flow_serial++);
 }

 /* ****************************************************** */

 static FlowHashBucket* allocFlowBucket(u_int8_t proto, u_short thread_id,
					u_short mutex_idx, u_short idx) {
   FlowHashBucket *bkt;
   ticks when;
   static u_int8_t once = 0;

   if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();

   bkt = (FlowHashBucket*)calloc(1, sizeof(FlowHashBucket));

   if(bkt == NULL)
     goto bkt_failure;

   if(unlikely(readOnlyGlobals.tracePerformance)) {
     ticks diff = getticks() - when;

     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
     readOnlyGlobals.bucketMallocTicks += diff, readOnlyGlobals.num_malloced_buckets++;
     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
   }

   if(readOnlyGlobals.enable_l7_protocol_discovery) {
     // printf("--->>> %u\n", readOnlyGlobals.l7.proto.ndpi.flow_struct_size+2*readOnlyGlobals.l7.proto.ndpi.proto_size);

     if((bkt->core.l7.proto.ndpi.flow = calloc(1, readOnlyGlobals.l7.flow_struct_size)) == NULL)
       goto bkt_failure;

     bkt->core.l7.proto.ndpi.src = malloc(readOnlyGlobals.l7.proto_size);
     bkt->core.l7.proto.ndpi.dst = malloc(readOnlyGlobals.l7.proto_size);

     if((bkt->core.l7.proto.ndpi.src == NULL) || (bkt->core.l7.proto.ndpi.dst == NULL))
       goto bkt_failure;

     bkt->core.l7.proto.ndpi.ndpi_proto = NDPI_PROTOCOL_UNKNOWN;
   }

   bkt->ext = (FlowHashExtendedBucket*)calloc(1, sizeof(FlowHashExtendedBucket));

   if(bkt->ext == NULL)
     goto bkt_failure;

   if(readOnlyGlobals.enableExtBucket) {
     bkt->ext->extensions = (FlowHashBucketExtensions*)calloc(1, sizeof(FlowHashBucketExtensions));

     if(bkt->ext->extensions == NULL)
       goto bkt_failure;
   }

   if(bkt->ext)
     bkt->ext->thread_id = thread_id;

 #if 0
   if(readWriteGlobals->exportBucketsLen < 16)
     traceEvent(TRACE_NORMAL, "[+] bucketsAllocated=%u",
		readWriteGlobals->bucketsAllocated);
 #endif

   bkt->core.tuple.flow_serial = 0;

   if(proto == 1)       readWriteGlobals->accumulateStats[thread_id].icmpFlows++;
   else if(proto == 6)  readWriteGlobals->accumulateStats[thread_id].tcpFlows++;
   else if(proto == 17) readWriteGlobals->accumulateStats[thread_id].udpFlows++;

   bkt->magic = MAGIC_NUMBER;

   if(unlikely(readOnlyGlobals.tracePerformance)) {
     ticks diff = getticks() - when;

     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
     readOnlyGlobals.bucketAllocationTicks += diff, readOnlyGlobals.num_allocated_buckets++;
     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
   }

   if(unlikely(readOnlyGlobals.useLocks))
     pthread_rwlock_wrlock(&readWriteGlobals->expireListLock);

   if(readWriteGlobals->expireFlowListHead[thread_id] == NULL) {
     /* The only entry of the list */
     readWriteGlobals->expireFlowListHead[thread_id] = readWriteGlobals->expireFlowListTail[thread_id] = bkt;
   } else {
     /* The list is already populated: append at the end */
     readWriteGlobals->expireFlowListTail[thread_id]->core.max_duration.next = bkt;
     bkt->core.max_duration.prev = readWriteGlobals->expireFlowListTail[thread_id];
     readWriteGlobals->expireFlowListTail[thread_id] = bkt;
   }

   /* Append it to the idle flow list */
   if(readWriteGlobals->idleFlowListHead[thread_id] == NULL) {
     /* The only entry of the list */
     readWriteGlobals->idleFlowListHead[thread_id] = readWriteGlobals->idleFlowListTail[thread_id] = bkt;
   } else {
     /* The list is already populated: append */
     readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = bkt;
     bkt->core.no_traffic.prev = readWriteGlobals->idleFlowListTail[thread_id];
     readWriteGlobals->idleFlowListTail[thread_id] = bkt;
   }

   if(unlikely(readOnlyGlobals.useLocks))
     pthread_rwlock_unlock(&readWriteGlobals->expireListLock);

   if(unlikely(readOnlyGlobals.tracePerformance)) {
     ticks diff = getticks() - when;

     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
     readOnlyGlobals.bucketAllocationTicks += diff, readOnlyGlobals.num_allocated_buckets++;
     if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
   }

   incAtomic(&readWriteGlobals->bucketsAllocated, 1);

   /* This is the return point in case of succefull allocation */
   return(bkt);

  bkt_failure:
   if(!once) {
     traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
     once = 1;
   }

   purgeBucket(bkt);
   return(NULL);
 }

 /* ****************************************************** */

 static void updateHost(HostInfo *host, IpAddress *addr, u_int32_t ifHost, u_int16_t ifIdx) {
   host->ifHost = ifHost, host->ifIdx = ifIdx;
 }

 /* ****************************************************** */

 static u_int32_t hostHash(IpAddress *host) {
   if(host->ipVersion == 4)
     return(host->ipType.ipv4);
   else
     return(host->ipType.ipv6.s6_addr32[0]
	    + host->ipType.ipv6.s6_addr32[1]
	    + host->ipType.ipv6.s6_addr32[2]
	    + host->ipType.ipv6.s6_addr32[3]);
 }

 /* ****************************************************** */

 #ifdef ACCURATE_HASH

 static void sortFlowIndex(struct flow_index *to_index) {
   u_int32_t u32;
   u_int32_t u16;

   if(to_index->sport == to_index->dport) {
     /* Sort on host */

     if(to_index->srcHost <= to_index->dstHost)
       return; /* Nothing to do */
     else {
       /* Just swap hosts */
       u32 = to_index->srcHost;
       to_index->srcHost = to_index->dstHost;
       to_index->dstHost = u32;
     }
   } else if(to_index->sport < to_index->dport) {
     return; /* Nothing to do */
   } else /* to_index->sport > to_index->dport */ {
     u32 = to_index->srcHost, u16 = to_index->sport;
     to_index->srcHost = to_index->dstHost, to_index->sport = to_index->dport;
     to_index->dstHost = u32, to_index->dport= u16;
   }
 }

 /* ****************************************************** */

 #if 1

 /* http://burtleburtle.net/bob/hash/evahash.html */

 /* The mixing step */
 #define mix(a,b,c)				\
   {						\
     a=a-b;  a=a-c;  a=a^(c>>13);		\
     b=b-c;  b=b-a;  b=b^(a<<8);			\
     c=c-a;  c=c-b;  c=c^(b>>13);		\
     a=a-b;  a=a-c;  a=a^(c>>12);		\
     b=b-c;  b=b-a;  b=b^(a<<16);		\
     c=c-a;  c=c-b;  c=c^(b>>5);			\
     a=a-b;  a=a-c;  a=a^(c>>3);			\
     b=b-c;  b=b-a;  b=b^(a<<10);		\
     c=c-a;  c=c-b;  c=c^(b>>15);		\
   }

 #define mix64(a,b,c)				\
   {						\
     a=a-b;  a=a-c;  a=a^(c>>43);		\
     b=b-c;  b=b-a;  b=b^(a<<9);			\
     c=c-a;  c=c-b;  c=c^(b>>8);			\
     a=a-b;  a=a-c;  a=a^(c>>38);		\
     b=b-c;  b=b-a;  b=b^(a<<23);		\
     c=c-a;  c=c-b;  c=c^(b>>5);			\
     a=a-b;  a=a-c;  a=a^(c>>35);		\
     b=b-c;  b=b-a;  b=b^(a<<49);		\
     c=c-a;  c=c-b;  c=c^(b>>11);		\
     a=a-b;  a=a-c;  a=a^(c>>12);		\
     b=b-c;  b=b-a;  b=b^(a<<18);		\
     c=c-a;  c=c-b;  c=c^(b>>22);		\
   }

 /* The whole new hash function */
 u_int32_t hashVal(const u_int8_t *k,  /* the key */
		   u_int32_t length,   /* the length of the key in bytes */
		   u_int32_t initval)  /* the previous hash, or an arbitrary value */
 {
   u_int32_t a,b,c;  /* the internal state */
   u_int32_t          len;    /* how many key bytes still need mixing */

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* variable initialization of internal state */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
     {
       a=a+(k[0]+((u_int32_t)k[1]<<8)+((u_int32_t)k[2]<<16) +((u_int32_t)k[3]<<24));
       b=b+(k[4]+((u_int32_t)k[5]<<8)+((u_int32_t)k[6]<<16) +((u_int32_t)k[7]<<24));
       c=c+(k[8]+((u_int32_t)k[9]<<8)+((u_int32_t)k[10]<<16)+((u_int32_t)k[11]<<24));
       mix(a,b,c);
       k = k+12; len = len-13;
     }

   /*------------------------------------- handle the last 11 bytes */
   c = c+length;
   switch(len)              /* all the case statements fall through */
     {
     case 11: c=c+((u_int32_t)k[10]<<24);
     case 10: c=c+((u_int32_t)k[9]<<16);
     case 9 : c=c+((u_int32_t)k[8]<<8);
       /* the first byte of c is reserved for the length */
     case 8 : b=b+((u_int32_t)k[7]<<24);
     case 7 : b=b+((u_int32_t)k[6]<<16);
     case 6 : b=b+((u_int32_t)k[5]<<8);
     case 5 : b=b+k[4];
     case 4 : a=a+((u_int32_t)k[3]<<24);
     case 3 : a=a+((u_int32_t)k[2]<<16);
     case 2 : a=a+((u_int32_t)k[1]<<8);
     case 1 : a=a+k[0];
       /* case 0: nothing left to add */
     }
   mix(a,b,c);

   /*-------------------------------------------- report the result */
   return c;
 }

 #else
 /*
   http://sites.google.com/site/murmurhash/

   The code below is MurmurHash2()
 */

 unsigned int hashVal(const u_int8_t * key, int len, unsigned int seed)
 {
   // 'm' and 'r' are mixing constants generated offline.
   // They're not really 'magic', they just happen to work well.

   const unsigned int m = 0x5bd1e995;
   const int r = 24;

   // Initialize the hash to a 'random' value

   unsigned int h = seed ^ len;

   // Mix 4 bytes at a time into the hash

   const unsigned char * data = (const unsigned char *)key;

   while(len >= 4)
     {
       unsigned int k = *(unsigned int *)data;

       k *= m;
       k ^= k >> r;
       k *= m;

       h *= m;
       h ^= k;

       data += 4;
       len -= 4;
     }

   // Handle the last few bytes of the input array

   switch(len)
     {
     case 3: h ^= data[2] << 16;
     case 2: h ^= data[1] << 8;
     case 1: h ^= data[0];
       h *= m;
     };

   // Do a few final mixes of the hash to ensure the last few
   // bytes are well-incorporated.

   h ^= h >> 13;
   h *= m;
   h ^= h >> 15;

   return h;
 }
 #endif

 #endif

 /* ****************************** */

 static void hash_lock(const char *filename, const int line, u_int32_t thread_id, u_int32_t mutex_idx) {
   if(unlikely(readOnlyGlobals.needHashLock)) {
     pthread_rwlock_t *rwlock = &readWriteGlobals->flowHashRwLock[thread_id][mutex_idx];
     int rc = pthread_rwlock_wrlock(rwlock);

     if(rc != 0) traceEvent(TRACE_WARNING, "hash_lock failed [rc=%d][thread_id=%u][mutex_idx=%u] @ %s:%d",
			    rc, thread_id, mutex_idx, filename, line);
   }
 }

 /* ****************************************************** */

 static void hash_unlock(const char *filename, const int line, u_int32_t thread_id, u_int32_t mutex_idx) {
   if(unlikely(readOnlyGlobals.needHashLock)) {
     pthread_rwlock_t *rwlock = &readWriteGlobals->flowHashRwLock[thread_id][mutex_idx];
     int rc = pthread_rwlock_unlock(rwlock);

     if(rc != 0) traceEvent(TRACE_WARNING, "hash_unlock failed [rc=%d][thread_id=%u][mutex_idx=%u] @ %s:%d",
			    rc, thread_id, mutex_idx, filename, line);
   }
 }

 /* ******************************************************** */

 /* We put the bucket as first on the idle list */
 void tellProbeToExportFlow(u_int32_t thread_id, FlowHashBucket *myBucket) {
   if(readWriteGlobals->idleFlowListHead[thread_id] == myBucket) {
     /* 1st Element of the list: nothing to do we just have to wait */
   } else if(readWriteGlobals->idleFlowListTail[thread_id] == myBucket) {
     /* Last element of the list */

     /* 1 - Remove me from list */
     readWriteGlobals->idleFlowListTail[thread_id] = myBucket->core.no_traffic.prev;
     readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = NULL;

     /* 2 - Place me at the head of the list */
     readWriteGlobals->idleFlowListHead[thread_id]->core.no_traffic.prev = myBucket;
     myBucket->core.no_traffic.prev = NULL, myBucket->core.no_traffic.next = readWriteGlobals->idleFlowListHead[thread_id];
     readWriteGlobals->idleFlowListHead[thread_id] = myBucket;
   } else {
     /* Middle */

     /* 1 - Remove me from list */
     (myBucket->core.no_traffic.prev)->core.no_traffic.next = myBucket->core.no_traffic.next;
     (myBucket->core.no_traffic.next)->core.no_traffic.prev = myBucket->core.no_traffic.prev;

     /* 2 - Place me at the head of the list */
     readWriteGlobals->idleFlowListHead[thread_id]->core.no_traffic.prev = myBucket;
     myBucket->core.no_traffic.prev = NULL, myBucket->core.no_traffic.next = readWriteGlobals->idleFlowListHead[thread_id];
     readWriteGlobals->idleFlowListHead[thread_id] = myBucket;
   }
 }

 /* ******************************************************** */

 static void walkHashList(u_int32_t thread_id, int flushHash, time_t now) {
   FlowHashBucket *myBucket, *myNextBucket;
   u_int num_exported, num_runs;

   num_exported = 0, num_runs = 0;

   /*
     NOTE

     We do not need to call hash_lock() as we are called
     by the worker thread either when it is idle or when it
     has processed a packet. So when we're called nobody else is
     disturbing us
   */

   for(num_runs = 0; num_runs < 2; num_runs++) {
     if(num_runs == 0)
       myBucket = readWriteGlobals->expireFlowListHead[thread_id];
     else {
       if(flushHash) break;
       myBucket = readWriteGlobals->idleFlowListHead[thread_id];
     }

     if(unlikely(readOnlyGlobals.useLocks))
       pthread_rwlock_wrlock(&readWriteGlobals->expireListLock);

     while(myBucket != NULL) {
       myNextBucket = (num_runs == 0) ? myBucket->core.max_duration.next : myBucket->core.no_traffic.next;

       /* Flush buckets marked during the previous cycle */
       if(myBucket->core.purge_at_next_loop || flushHash) {
	 /*
	   We've updated the pointers, hence removed this bucket from the active bucket list,
	   therefore we now invalidate the next pointer
	 */
	 /* 1 - Remove from hash */
	 if(readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] == NULL) {
	   traceEvent(TRACE_WARNING, "Internal error: NULL head for index %u [num_runs: %u][thread_id: %u]",
		      myBucket->core.tuple.flow_idx, num_runs, thread_id);
	 } else if(readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] == myBucket) {
	   /* 1st Element of the list */
	   readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] = myBucket->core.hash.next;
	   if(readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx] != NULL)
	     readWriteGlobals->theFlowHash[thread_id][myBucket->core.tuple.flow_idx]->core.hash.prev = NULL;
	 } else {
	   /* Middle or last */
	   (myBucket->core.hash.prev)->core.hash.next = myBucket->core.hash.next;
	   if(myBucket->core.hash.next != NULL) /* We are not the last element */
	     (myBucket->core.hash.next)->core.hash.prev = myBucket->core.hash.prev;
	 }

	 /* 2 - Max Duration */
	 if(readWriteGlobals->expireFlowListHead[thread_id] == readWriteGlobals->expireFlowListTail[thread_id]) {
	   /* The list has only one element: me */
	   if(readWriteGlobals->expireFlowListHead[thread_id] != myBucket) {
	     traceEvent(TRACE_WARNING, "Internal error: [Head: %p][Tail: %p][myBucket: %p][num_runs: %u][thread_id: %u]",
			readWriteGlobals->expireFlowListHead[thread_id],
			readWriteGlobals->expireFlowListTail[thread_id],
			myBucket, num_runs, thread_id);
	   }
	   readWriteGlobals->expireFlowListHead[thread_id] = readWriteGlobals->expireFlowListTail[thread_id] = NULL;
	 } else if(readWriteGlobals->expireFlowListHead[thread_id] == myBucket) {
	   /* 1st Element of the list and more than one element on the list */
	   readWriteGlobals->expireFlowListHead[thread_id] = myBucket->core.max_duration.next;
	   readWriteGlobals->expireFlowListHead[thread_id]->core.max_duration.prev = NULL;
	 } else if(readWriteGlobals->expireFlowListTail[thread_id] == myBucket) {
	   /* Last element of the list */
	   readWriteGlobals->expireFlowListTail[thread_id] = myBucket->core.max_duration.prev;
	   readWriteGlobals->expireFlowListTail[thread_id]->core.max_duration.next = NULL;
	 } else {
	   /* Middle */
	   (myBucket->core.max_duration.prev)->core.max_duration.next = myBucket->core.max_duration.next;
	   (myBucket->core.max_duration.next)->core.max_duration.prev = myBucket->core.max_duration.prev;
	 }

	 /* 3 - No Traffic */
	 if(readWriteGlobals->idleFlowListHead[thread_id] == readWriteGlobals->idleFlowListTail[thread_id]) {
	   /* The list has only one element: me */
	   if(readWriteGlobals->idleFlowListHead[thread_id] != myBucket) {
	     traceEvent(TRACE_WARNING, "Internal error: [Head: %p][Tail: %p][myBucket: %p][num_runs: %u]",
			readWriteGlobals->idleFlowListHead[thread_id],
			readWriteGlobals->idleFlowListTail[thread_id],
			myBucket, num_runs);
	   }
	   readWriteGlobals->idleFlowListHead[thread_id] = readWriteGlobals->idleFlowListTail[thread_id] = NULL;
	 } else if(readWriteGlobals->idleFlowListHead[thread_id] == myBucket) {
	   /* 1st Element of the list */
	   readWriteGlobals->idleFlowListHead[thread_id] = myBucket->core.no_traffic.next;
	   readWriteGlobals->idleFlowListHead[thread_id]->core.no_traffic.prev = NULL;
	 } else if(readWriteGlobals->idleFlowListTail[thread_id] == myBucket) {
	   /* Last element of the list */
	   readWriteGlobals->idleFlowListTail[thread_id] = myBucket->core.no_traffic.prev;
	   readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = NULL;
	 } else {
	   /* Middle */
	   (myBucket->core.no_traffic.prev)->core.no_traffic.next = myBucket->core.no_traffic.next;
	   (myBucket->core.no_traffic.next)->core.no_traffic.prev = myBucket->core.no_traffic.prev;
	 }

	 if(!(myBucket->ext && myBucket->ext->sampled_flow)) {
	   if(readWriteGlobals->exportBucketsLen < readOnlyGlobals.maxExportQueueLen) {
	     /*
	       The flow is both expired and we have room in the export
	       queue to send it out, hence we can export it
	     */
	     queueBucketToExport(myBucket);
	   } else {
	     /* The export queue is full:

		The flow is expired and in queue since too long. As there's
		no room left in queue, the only thing we can do is to
		drop it
	     */
	     discardBucket(myBucket);
	     readWriteGlobals->probeStats.totFlowDropped++;

	     /*
	       Too much work to be done: let's decrease the export delay
	       if this has been set!
	     */
	     if(readOnlyGlobals.flowExportDelay > 0)
	       readOnlyGlobals.flowExportDelay--;
	   }
	 } else {
	   /* Free bucket */
	   discardBucket(myBucket);
	 }

	 num_exported++;

	 myBucket = myNextBucket;
       } else {
	 u_int8_t bucket_found = 0;

	 if(flushHash || isFlowExpired(myBucket, now)) {
	   /* Remove it from bucket list at the next run */
	   setBucketExpired(myBucket);
	   myBucket->core.purge_at_next_loop = 1, bucket_found = 1;
	 }

	 if(flushHash || bucket_found) {
	   myBucket = myNextBucket;
	   continue;
	 } else
	   break; /* Stop at the first flow thet is not expired */
       }
     } /* while */

     if(unlikely(readOnlyGlobals.useLocks))
       pthread_rwlock_unlock(&readWriteGlobals->expireListLock);
   }

   /* Check idle flows */

   if(num_exported > 0)
     signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);
 }

 /* ****************************************************** */

 FlowHashBucket* getHashBucket(u_int32_t packet_hash, u_short thread_id) {
   u_int32_t idx = packet_hash % readOnlyGlobals.flowHashSize;
   FlowHashBucket *bkt = readWriteGlobals->theFlowHash[thread_id][idx];

   while(bkt != NULL) {
     if((!bkt->core.bucket_expired) && (bkt->core.tuple.flow_hash == packet_hash)) {
       return(bkt);
     } else
       bkt = bkt->core.hash.next;
   }

   return(NULL);
 }

 /* ****************************************************** */

 void checkBucketExpire(FlowHashBucket *bkt, u_short thread_id) {
   /* Let's move this flow at the end of the idle flow list */
   if((readWriteGlobals->idleFlowListTail[thread_id] != bkt)
      /* The list has only one element */
      && (readWriteGlobals->idleFlowListHead[thread_id] != readWriteGlobals->idleFlowListTail[thread_id])
      ) {
     /* We're not the last/first one of the list */

     if(unlikely(readOnlyGlobals.useLocks))
       pthread_rwlock_wrlock(&readWriteGlobals->expireListLock);

     /* Trick to avoid locking everytime checkBucketExpire is called */
     if((readWriteGlobals->idleFlowListTail[thread_id] != bkt)
	&& (readWriteGlobals->idleFlowListHead[thread_id] != readWriteGlobals->idleFlowListTail[thread_id])
	) {
       /* 1 - Remove bkt from the list */
       if(readWriteGlobals->idleFlowListHead[thread_id] == readWriteGlobals->idleFlowListTail[thread_id]) {
	 /* The list has only one element: me */
	 readWriteGlobals->idleFlowListHead[thread_id] = readWriteGlobals->idleFlowListTail[thread_id] = NULL;
       } else if(readWriteGlobals->idleFlowListHead[thread_id] == bkt) {
	 /* 1st Element of the list */
	 readWriteGlobals->idleFlowListHead[thread_id] = bkt->core.no_traffic.next;
	 readWriteGlobals->idleFlowListHead[thread_id]->core.no_traffic.prev = NULL;
       } else if(readWriteGlobals->idleFlowListTail[thread_id] == bkt) {
	 /* Last element of the list */
	 readWriteGlobals->idleFlowListTail[thread_id] = bkt->core.no_traffic.prev;
	 readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = NULL;
       } else {
	 /* Middle */
	 (bkt->core.no_traffic.prev)->core.no_traffic.next = bkt->core.no_traffic.next;

	 if(bkt->core.no_traffic.next)
	   (bkt->core.no_traffic.next)->core.no_traffic.prev = bkt->core.no_traffic.prev;
       }

       /* 2 - Append it at the end */
       readWriteGlobals->idleFlowListTail[thread_id]->core.no_traffic.next = bkt;
       bkt->core.no_traffic.prev = readWriteGlobals->idleFlowListTail[thread_id];
       bkt->core.no_traffic.next = NULL;
       readWriteGlobals->idleFlowListTail[thread_id] = bkt;
     }

     if(unlikely(readOnlyGlobals.useLocks))
       pthread_rwlock_unlock(&readWriteGlobals->expireListLock);
   }
 }

 /* ****************************************************** */

 FlowHashBucket* processGTPFlowPacket(u_short thread_id, u_int32_t gtp_teid,
				      struct pcap_pkthdr *h, u_int gtp_pkt_len) {
#if DEBUG_HASHING
   u_int16_t sport = 0, dport = 0, vlanId = 0;
#endif
   u_int32_t idx = gtp_teid % readOnlyGlobals.flowHashSize;
   u_int32_t mutex_idx = gtp_teid % MAX_HASH_MUTEXES;
   u_int32_t n = 0;
   FlowHashBucket *bkt;

   /* The statement below guarantees that packets are serialized */
   hash_lock(__FILE__, __LINE__, thread_id, mutex_idx);

   bkt = readWriteGlobals->theFlowHash[thread_id][idx];

   while(bkt != NULL) {
     if(bkt->magic != MAGIC_NUMBER) {
       traceEvent(TRACE_ERROR, "Magic error detected (magic=%d)", bkt->magic);
       if(readWriteGlobals->theFlowHash[thread_id][idx] == bkt) {
	 readWriteGlobals->theFlowHash[thread_id][idx] = NULL;
       }

       bkt = NULL;
       break;
     }

     if(bkt->core.tuple.key.is_gtp_flow && (bkt->core.tuple.key.k.gtpKey.teid == gtp_teid)) {
       bkt->core.tuple.flowCounters.bytesSent += gtp_pkt_len, bkt->core.tuple.flowCounters.pktSent += 1;

       if(bkt->core.tuple.flowTimers.firstSeenSent.tv_sec == 0)
	 bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = h->ts.tv_usec;

       bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;

       checkBucketExpire(bkt, thread_id);
       idleThreadTask(thread_id, 1);
       hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
       return(bkt);
     }

     /* Bucket not found yet */
     n++, bkt = bkt->core.hash.next;
   } /* while */

   if(n > readWriteGlobals->maxBucketSearch) {
#ifdef DEBUG_HASHING
     FlowHashBucket *head = readWriteGlobals->theFlowHash[thread_id][idx];
     int i = 0;
#endif

     readWriteGlobals->maxBucketSearch = n;

#ifdef DEBUG_HASHING
     traceEvent(TRACE_NORMAL, "[maxBucketSearch=%d][thread_id=%u][idx=%u][teid=%04X]",
		readWriteGlobals->maxBucketSearch, thread_id, idx, gtp_teid);

     while(head != NULL) {
       char buf[256], buf1[256], src_buf[32], dst_buf[32];

       traceEvent(TRACE_NORMAL, "(%u) [%s] %s:%d -> %s:%d [%s -> %s][vlan %d][subflowId: %u/0x%04x][idx=%u]",
		  i, head->core.tuple.key.is_ip_flow ? proto2name(head->core.tuple.key.k.ipKey.proto) : "NonIP",
		  _intoa(head->core.tuple.key.k.ipKey.src, buf, sizeof(buf)), sport,
		  _intoa(head->core.tuple.key.k.ipKey.dst, buf1, sizeof(buf1)), dport,
		  etheraddr_string(head->ext->srcInfo.macAddress, src_buf),
		  etheraddr_string(head->ext->dstInfo.macAddress, dst_buf),
		  vlanId, head->ext->subflow_id, head->ext->subflow_id, idx);
       head = head->core.hash.next, i++;
     }
#endif
   }

   if(unlikely(readOnlyGlobals.enable_debug))
     traceEvent(TRACE_NORMAL, "Adding new bucket");

   if(bkt == NULL) {
     if(getAtomic(&readWriteGlobals->bucketsAllocated) >= readOnlyGlobals.maxNumActiveFlows) {
       static u_char msgSent = 0;

       if(!msgSent) {
	 traceEvent(TRACE_WARNING, "Too many (%u) active flows [threadId=%u][limit=%u] (see -M)",
		    getAtomic(&readWriteGlobals->bucketsAllocated),
		    thread_id, readOnlyGlobals.maxNumActiveFlows);
	 msgSent = 1;
       }
       readWriteGlobals->probeStats.droppedPktsTooManyFlows++;

       hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
       return(bkt);
     }

     bkt = allocFlowBucket(0, thread_id, mutex_idx, idx);

     if(bkt == NULL) {
       static u_int8_t once = 0;

       if(!once) {
	 traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
	 once = 1;
       }

       hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
       return(bkt);
     }
   }

   bkt->core.tuple.flow_idx = idx, bkt->core.tuple.key.is_gtp_flow = 1, bkt->core.tuple.key.k.gtpKey.teid = gtp_teid;

   bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec,
     bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
   bkt->core.tuple.flowCounters.bytesSent = gtp_pkt_len, bkt->core.tuple.flowCounters.pktSent = 1;

 #if 1
   /* Access cache + redis */
   teid2user(bkt, gtp_teid);
 #else
   /* Access only the local LRU cache */
   snprintf(key, sizeof(key), "teid.%u", gtp_teid);
   user = find_lru_cache_str(&readWriteGlobals->flowUsersCache, key);
   //traceEvent(TRACE_ERROR, "==>>>> %s", key);

   if(user && (user[0] != '\0')) {
     /* cell_lac;cell_ci;sac;end_user_ip */
     char *w, *cell_ci = strtok_r(user, ";", &w);

     if(cell_ci) {
       cell_ci = strtok_r(NULL, ";", &w);

       if(cell_ci) {
	 // FIX -
	 bkt->core.tuple.key.k.gtpKey.cell_id = atoi(cell_ci);
	 // traceEvent(TRACE_ERROR, "==>>>> %s", cell_ci);
       }
     }
   }
 #endif

   addToList(bkt, &readWriteGlobals->theFlowHash[thread_id][idx]);

   idleThreadTask(thread_id, 2);

   if(readOnlyGlobals.traceMode == 2)
     traceEvent(TRACE_INFO, "New Flow: [teid=%04X][%s]", gtp_teid,
		bkt->core.user.username ? bkt->core.user.username : "");
   if(readOnlyGlobals.disableFlowCache)
     setBucketExpired(bkt);

   hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);

   return(bkt);
 }

 /* ****************************************************** */

 FlowHashBucket* processFlowPacket(u_short thread_id,
				   int packet_if_idx /* -1 = unknown */,
				   u_int8_t rx_packet, /* 1=RX, 0=TX */
				   u_int32_t subflow_id, u_int8_t proto, u_short numFragments,
				   u_int16_t ip_offset, u_int8_t sampledPacket,
				   u_short numPkts, u_int8_t tos, u_int8_t ttl,
				   u_short vlanId, u_int32_t tunnel_id, u_int16_t gtp_offset,
				   struct eth_header *ehdr,
				   IpAddress *src, u_short sport,
				   IpAddress *dst, u_short dport,
				   u_int8_t untunneled_proto,
				   IpAddress *untunneled_src, u_short untunneled_sport,
				   IpAddress *untunneled_dst, u_short untunneled_dport,
				   u_int len, u_int16_t tcpWin, u_int8_t tcpFlags,
				   u_int32_t tcpSeqNum, u_int32_t tcpAckNum,
				   u_int16_t tcpMaxSegmentSize, u_int8_t tcpWinScale,
				   u_int8_t icmpType, u_int8_t icmpCode,
				   u_short numMplsLabels,
				   u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
				   u_int32_t if_input, u_int32_t if_output,
				   struct pcap_pkthdr *h, u_char *p,
				   u_int16_t payload_shift, u_int payloadLen,
				   u_int originalPayloadLen,
				   time_t _firstSeen, /* Always set to 0 unless numPkts > 0 */
				   u_int32_t src_as, u_int32_t dst_as,
				   u_int16_t src_mask, u_int16_t dst_mask,
				   u_int32_t flow_sender_ip,
				   u_int32_t packet_hash,
				   u_int8_t engine_type, u_int8_t engine_id,
				   char *osi_src, char *osi_dst,
				   struct generic_netflow_record *record) {
   u_char *payload = NULL;
   u_int32_t n = 0, mutex_idx, realLen = sampledPacket ? (numPkts*len) : len;
   u_int32_t ndpi_proto = NDPI_PROTOCOL_UNKNOWN;
   FlowHashBucket *bkt;
   struct timeval firstSeen;
   u_int32_t idx;
   FlowDirection direction;
   ticks when;
   u_int8_t use_mac_search = 0, flow_found = 0, retransmitted_pkt = 0;
 #ifdef ACCURATE_HASH
   struct flow_index to_index;
 #endif

   if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
   if(unlikely(readOnlyGlobals.ignoreVlan))       vlanId = 0;
   if(unlikely(readOnlyGlobals.ignoreProtocol))   proto = 0;
   if(unlikely(readOnlyGlobals.ignoreIP))         src->ipVersion = 4, src->ipType.ipv4 = 0, dst->ipVersion = 4, dst->ipType.ipv4 = 0;
   if(unlikely(readOnlyGlobals.ignorePorts))      sport = 0, dport = 0;
   if(unlikely(readOnlyGlobals.ignoreTos
	       || readOnlyGlobals.enableMySQLPlugin
	       || readOnlyGlobals.enableHttpPlugin
	       || readOnlyGlobals.enableProcessPlugin
	       || readOnlyGlobals.enableOraclePlugin
	       || readOnlyGlobals.enableWhoisPlugin
	       ))
     tos = 0;

 #ifdef ACCURATE_HASH
   if(src->ipVersion == 4) {
     to_index.srcHost = src->ipType.ipv4, to_index.dstHost = dst->ipType.ipv4;
   } else {
     to_index.srcHost = src->ipType.ipv6.s6_addr32[0] + src->ipType.ipv6.s6_addr32[1]
       + src->ipType.ipv6.s6_addr32[2] + src->ipType.ipv6.s6_addr32[3];
     to_index.dstHost = dst->ipType.ipv6.s6_addr32[0] + dst->ipType.ipv6.s6_addr32[1]
       + dst->ipType.ipv6.s6_addr32[2] + dst->ipType.ipv6.s6_addr32[3];
   }
   to_index.vlanId = vlanId, to_index.sport = sport, to_index.dport = dport, to_index.tos = tos,
     to_index.proto = proto, to_index.subflow_id = subflow_id;
 #endif

   if(unlikely(readOnlyGlobals.enableDnsPlugin)) {
     if((proto == IPPROTO_UDP)
	&& ((sport == 53) || (dport == 53))
	&& (payloadLen > 2)) {
       u_int16_t *transaction_id = (u_int16_t*)&p[payload_shift];

       subflow_id = ntohs(*transaction_id);
     }
   }

   if(unlikely(readOnlyGlobals.enableDhcpPlugin)) {
     if((proto == IPPROTO_UDP)
	&& ((sport == 67) || (sport == 68))
	&& (payloadLen > 2)) {
       u_int32_t *transaction_id = (u_int32_t*)&p[payload_shift+4];

       subflow_id = ntohl(*transaction_id);
     }
   }

   if(unlikely(readOnlyGlobals.enableRadiusPlugin)) {
     if((proto == IPPROTO_UDP)
	&& ((sport == 1812)    || (dport == 1812) /* Start/Stop */
	    || (sport == 1813) || (dport == 1813) /* Accounting */
	    || (sport == 1645) || (dport == 1645) /* Start/Stop */
	    || (sport == 1646) || (dport == 1646) /* Accounting */
	    )
	&& (payloadLen >= 20)) {
       subflow_id = p[payload_shift+1] /* Packet Identifier */;
     }
   }

   if(unlikely(readOnlyGlobals.enableSipPlugin)) {
     if((proto == IPPROTO_UDP) && ((sport == 5060) || (dport == 5060)) && (payloadLen > 9)) {
       char *call_id = strstr((const char*)&p[payload_shift], "Call-ID: ");

       if(call_id != NULL) {
	 u_int32_t hash = 0, c;

	 call_id = &call_id[9];
	 while((c = *call_id++)) {
	   hash = c + (hash << 6) + (hash << 16) - hash;

	   if((c == '\r') || (c == '\n'))
	     break;
	 }

	 //traceEvent(TRACE_INFO, "Computing SIP HASH Call-ID=%s Hash=%u ", &row[9], hash);

	 subflow_id = hash;
       }
     }
   }

   h->caplen = min(h->caplen, readOnlyGlobals.snaplen);

   if(gtp_offset > 0) {
     if((p[gtp_offset] & 0xE0 /* GTPv0 */) == 0) {
       struct gtpv0_header *gtp = (struct gtpv0_header*)&p[gtp_offset];

       if(readOnlyGlobals.enableGtpPlugin)
	 subflow_id = ntohs(gtp->sequence_number);

       if(gtp->message_type == 0xFF /* T-PDU */)
	 gtp_offset = 0 /* unknown msg, we ignore GTP */, packet_hash = 0;
       else
	 packet_hash = (subflow_id << 1) + subflow_id + src->ipType.ipv4 + dst->ipType.ipv4;
     } else if(p[gtp_offset] & 0x20 /* GTPv1 */) {
       struct gtpv1_header *gtp = (struct gtpv1_header*)&p[gtp_offset];

       if(readOnlyGlobals.enableGtpPlugin)
	 subflow_id = ntohs(gtp->sequence_number);

       if(gtp->message_type == 0xFF /* T-PDU */)
	 gtp_offset = 0 /* unknown msg, we ignore GTP */, packet_hash = 0;
       else
	 packet_hash = (subflow_id << 1) + subflow_id + src->ipType.ipv4 + dst->ipType.ipv4;
     } else if(p[gtp_offset] & 0x40 /* GTPv2 */) {
       struct gtpv2_header *gtp = (struct gtpv2_header*)&p[gtp_offset];

       if(readOnlyGlobals.enableGtpPlugin)
	 subflow_id = (gtp->sequence_number[0] << 16)
	   + (gtp->sequence_number[1] << 8)
	   + gtp->sequence_number[2];

       if(unlikely(readOnlyGlobals.enable_debug))
	 traceEvent(TRACE_NORMAL, "[GTPv2] subflow_id=%u", subflow_id);

       if(gtp->message_type == 0xFF /* T-PDU */)
	 gtp_offset = 0 /* unknown msg, we ignore GTP */, packet_hash = 0;
       else
	 packet_hash = (subflow_id << 1) + subflow_id + src->ipType.ipv4 + dst->ipType.ipv4;
     }
   }

   if(unlikely(packet_hash == 0)) {
 #ifdef ACCURATE_HASH
     sortFlowIndex(&to_index); /* We need a symmetric hash value */
     packet_hash = hashVal((const u_int8_t*)&to_index, sizeof(to_index), readOnlyGlobals.numProcessThreads /* seed */);
 #else
     {
       u_int32_t srcHost, dstHost;

       if((src->ipVersion == 0) || (src->ipVersion == 4)) {
	 if((src->ipType.ipv4 == 0) && (dst->ipType.ipv4 == 0) && (ehdr != NULL)) {
	   /* This is a fake IP thus we need to work at ethernet level */
	   srcHost = ehdr->ether_shost[0] + ehdr->ether_shost[1] + ehdr->ether_shost[2]
	     + ehdr->ether_shost[3] + ehdr->ether_shost[4] + ehdr->ether_shost[5];
	   dstHost = ehdr->ether_dhost[0] + ehdr->ether_dhost[1] + ehdr->ether_dhost[2]
	     + ehdr->ether_dhost[3] + ehdr->ether_dhost[4] + ehdr->ether_dhost[5];
	   use_mac_search = 1;
	 } else
	   srcHost = src->ipType.ipv4, dstHost = dst->ipType.ipv4;
       } else {
	 srcHost = src->ipType.ipv6.s6_addr32[0]+src->ipType.ipv6.s6_addr32[1]
	   +src->ipType.ipv6.s6_addr32[2]+src->ipType.ipv6.s6_addr32[3];
	 dstHost = dst->ipType.ipv6.s6_addr32[0]+dst->ipType.ipv6.s6_addr32[1]
	   +dst->ipType.ipv6.s6_addr32[2]+dst->ipType.ipv6.s6_addr32[3];
       }

       packet_hash = vlanId+proto+srcHost+dstHost+3*(sport+dport)+tos+untunneled_proto
	 + subflow_id /* Nice to differentiate across similar flows */;
     }
 #endif
   }

   idx = packet_hash % readOnlyGlobals.flowHashSize;

   if(_firstSeen == 0)
     firstSeen.tv_sec = h->ts.tv_sec, firstSeen.tv_usec = h->ts.tv_usec;
   else
     firstSeen.tv_sec = _firstSeen, firstSeen.tv_usec = 0;

   if(likely(readOnlyGlobals.pcapFile == NULL)) /* Live capture */
     readWriteGlobals->actTime.tv_sec = h->ts.tv_sec, readWriteGlobals->actTime.tv_usec = h->ts.tv_usec;

   if(payload_shift > 0)
     payload = &p[payload_shift];
   else
     payloadLen = 0; /* Sanity check */

   mutex_idx = idx % MAX_HASH_MUTEXES;

   // traceEvent(TRACE_INFO, "mutex_idx=%d", mutex_idx);
   // traceEvent(TRACE_NORMAL, "packet_hash=%u/thread_id=%d/idx=%d", packet_hash, thread_id, idx);

   /* The statement below guarantees that packets are serialized */
   hash_lock(__FILE__, __LINE__, thread_id, mutex_idx);

   bkt = readWriteGlobals->theFlowHash[thread_id][idx];

   while(bkt != NULL) {
     if(bkt->magic != MAGIC_NUMBER) {
       traceEvent(TRACE_ERROR, "Magic error detected (magic=%d)", bkt->magic);
       if(readWriteGlobals->theFlowHash[thread_id][idx] == bkt) {
	 readWriteGlobals->theFlowHash[thread_id][idx] = NULL;
       }

       bkt = NULL;
       break;
     }

     if(use_mac_search) {
       if((bkt->core.tuple.flow_hash == packet_hash)
	  && (bkt->core.tuple.key.vlanId == vlanId)
	  && (memcmp(bkt->core.tuple.key.k.macKey.src, ehdr->ether_shost, 6) == 0)
	  && (memcmp(bkt->core.tuple.key.k.macKey.dst, ehdr->ether_dhost, 6) == 0))
	 flow_found = 1;
     } else {
       if(((bkt->core.tuple.flow_hash == packet_hash)
	   && (bkt->core.tuple.key.k.ipKey.proto == proto)
	   && (bkt->core.tuple.key.vlanId == vlanId)
	   && (bkt->ext->subflow_id == subflow_id)
	   && (((bkt->core.tuple.key.k.ipKey.sport == sport)
		&& (bkt->core.tuple.key.k.ipKey.dport == dport)
		/* Don't check TOS if we've not sent any packet (it can happen with resetBucketStats()) */
		&& ((bkt->core.tuple.flowCounters.pktSent == 0) || (bkt->ext->src2dstTos == tos))
		&& cmpIpAddress(&bkt->core.tuple.key.k.ipKey.src, src)
		&& cmpIpAddress(&bkt->core.tuple.key.k.ipKey.dst, dst)
		)
	       ||
	       ((bkt->core.tuple.key.k.ipKey.sport == dport)
		&& (bkt->core.tuple.key.k.ipKey.dport == sport)
		/* Don't check TOS if we've not seen any backward packet */
		&& ((bkt->core.tuple.flowCounters.pktRcvd == 0) || (bkt->ext->dst2srcTos == tos))
		&& cmpIpAddress(&bkt->core.tuple.key.k.ipKey.src, dst)
		&& cmpIpAddress(&bkt->core.tuple.key.k.ipKey.dst, src)
		)))
	  || ((gtp_offset > 0)
	      && (bkt->ext->subflow_id == subflow_id)
	      && (((src->ipType.ipv4 == bkt->core.tuple.key.k.ipKey.src.ipType.ipv4) && (dst->ipType.ipv4 == bkt->core.tuple.key.k.ipKey.dst.ipType.ipv4))
		  || ((src->ipType.ipv4 == bkt->core.tuple.key.k.ipKey.dst.ipType.ipv4) && (dst->ipType.ipv4 == bkt->core.tuple.key.k.ipKey.src.ipType.ipv4))))
	  )
	 flow_found = 1;
     }

     /*
       Extra check to make sure that also the encapsulation matched with the flow
     */
     if(flow_found) {
       if(untunneled_proto != 0) {
	 if((bkt->ext->extensions == NULL) || (bkt->ext->extensions->untunneled.proto != untunneled_proto))
	   flow_found = 0;
       } else {
	 /* untunneled_proto == 0 */

	 if((bkt->ext->extensions != NULL) && (bkt->ext->extensions->untunneled.proto != untunneled_proto))
	   flow_found = 0;
       }
     }

     if(flow_found) {
       if(!bkt->core.bucket_expired) {
	 if((bkt->core.tuple.key.k.ipKey.sport == sport)
	    && cmpIpAddress(&bkt->core.tuple.key.k.ipKey.src, src)) {
	   // traceEvent(TRACE_ERROR, "[%p][sport=%u]", bkt, sport);
	   direction = src2dst_direction; /* , bkt->core.rx_direction.src2dst = rx_packet; [done at creation] */
	 } else {
	   direction = dst2src_direction, bkt->core.rx_direction.dst2src = rx_packet;

	   /* The opposite tunnel has been set already */
	   bkt->ext->dst2src_tunnel_id = tunnel_id;
	 }

	 if(likely(!bkt->ext->sampled_flow)) {
	   /* This flow has not been sampled */

	   if(proto == IPPROTO_TCP) {
	     /* We must do this here before we update the flow timers */
	     retransmitted_pkt = updateTcpSeq(&h->ts, bkt, direction, tcpFlags, tcpSeqNum, tcpAckNum,
					      originalPayloadLen, tcpWin, h, p, len);
	  }

	  if(direction == src2dst_direction) {
	    /* src -> dst */
	    bkt->core.tuple.flowCounters.bytesSent += realLen, bkt->core.tuple.flowCounters.pktSent += numPkts;

	    /* NOTE: do not move the statement below after the time update below */
	    updatePktLenStats(bkt, direction, &h->ts, h->len, ttl, numPkts);

	    if(bkt->core.tuple.flowTimers.firstSeenSent.tv_sec == 0)
	      bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = h->ts.tv_usec;

	    bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
	    if(numFragments > 0) bkt->ext->flowCounters.sentFragPkts += numFragments;

	    if(tos != 0) updateTos(bkt, 0, tos);
	    updateTTL(bkt, 0, ttl);
	    if(readOnlyGlobals.enable_l7_protocol_discovery)
	      setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);
	  } else {
	    /* dst -> src */
	    bkt->core.tuple.flowCounters.bytesRcvd += realLen, bkt->core.tuple.flowCounters.pktRcvd += numPkts;

	    /* NOTE: do not move the statement below after the time update below */
	    updatePktLenStats(bkt, direction, &h->ts, h->len, ttl, numPkts);

	    if(((bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec == 0) && (bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec == 0))
	       || (to_msec(&firstSeen) < to_msec(&bkt->core.tuple.flowTimers.firstSeenRcvd)))
	      bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = firstSeen.tv_usec;

	    bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = h->ts.tv_sec, bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = h->ts.tv_usec;
	    if(numFragments > 0) bkt->ext->flowCounters.rcvdFragPkts += numFragments;

	    if(tos != 0) updateTos(bkt, 1, tos);
	    updateTTL(bkt, 1, ttl);
	    if(readOnlyGlobals.enable_l7_protocol_discovery)
	      setPayload(bkt, h, p, ip_offset, payload, payloadLen, 1);
	  }

	  // traceEvent(TRACE_NORMAL, "-> %u/%u [%u]\n", realLen, realLen+14, bkt->core.tuple.flowCounters.bytesRcvd+bkt->core.tuple.flowCounters.bytesSent);

	  if(unlikely(readOnlyGlobals.num_active_plugins > 0)) {

	    if(payloadLen > 0) payload[payloadLen] = '\0';
	    pluginCallback(PACKET_CALLBACK, packet_if_idx,
			   bkt, direction,
			   ip_offset, proto, (numFragments > 0) ? 1 : 0,
			   numPkts, tos, retransmitted_pkt,
			   vlanId, ehdr, src, sport,
			   dst, dport, len,
			   tcpFlags, tcpSeqNum, icmpType, numMplsLabels,
			   mplsLabels, h, p, payload, payloadLen);
	  }
	}

	switch(proto) {
	case IPPROTO_TCP:
	  if(bkt->ext) {
	    updateTcpFlags(bkt, direction, &h->ts, tcpFlags, tcpMaxSegmentSize, tcpWinScale);
	    /* NOTE: updateTcpSeq() has been already called above */

	    /* Do not move this line before updateTcpFlags(...) */
	    if(direction == src2dst_direction)
	      bkt->ext->protoCounters.tcp.src2dstTcpFlags |= tcpFlags, bkt->ext->protoCounters.tcp.src2dstLastWin = tcpWin;
	    else
	      bkt->ext->protoCounters.tcp.dst2srcTcpFlags |= tcpFlags, bkt->ext->protoCounters.tcp.dst2srcLastWin = tcpWin;
	  }
	  break;

	case IPPROTO_UDP:
	  updateApplLatency(proto, bkt, direction, &h->ts);
	  break;
	}

	if(((direction == src2dst_direction) && (bkt->core.tuple.flowCounters.bytesSent > BYTES_WRAP_THRESHOLD))
	   || ((direction == dst2src_direction) && (bkt->core.tuple.flowCounters.bytesRcvd > BYTES_WRAP_THRESHOLD))) {
	  /*
	    The counter has a pretty high value: we better mark this flow as expired
	    in order to avoid wrapping the counter.
	  */
	  setBucketExpired(bkt);
	}

	checkBucketExpire(bkt, thread_id);
	bkt->ext->lastPktDirection = direction;

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  ticks diff = getticks() - when;
	  if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.processingWoFlowCreationTicks += diff, readOnlyGlobals.num_pkts_without_flow_creation++;
	  if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}

	idleThreadTask(thread_id, 3);
	hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
	return(bkt);
      } else {
	/*
	  This flow is the same as the one we need but it expired so
	  we better cache some info from it in order to use for the
	  current flow we will have to create
	*/
	ndpi_proto = bkt->core.l7.proto.ndpi.ndpi_proto;
	flow_found = 0; /* We need to search another bucket */
      }
    }

    /* Bucket not found yet */
    n++, bkt = bkt->core.hash.next;
  } /* while */

  if(n > readWriteGlobals->maxBucketSearch) {
    readWriteGlobals->maxBucketSearch = n;

    {
#ifdef DEBUG_HASHING
      FlowHashBucket *head = readWriteGlobals->theFlowHash[thread_id][idx];
      int i = 1;
#endif

      readWriteGlobals->maxBucketSearch = n;

#ifdef DEBUG_HASHING
      traceEvent(TRACE_NORMAL, "[maxBucketSearch=%d][thread_id=%u][idx=%u]",
		 readWriteGlobals->maxBucketSearch, thread_id, idx);

      while(head != NULL) {
	char buf[256], buf1[256], src_buf[32], dst_buf[32];

	traceEvent(TRACE_NORMAL, "(%u) [%s] %s:%d -> %s:%d [%s -> %s][vlan %d][tos %u/%u/%u][subflowId: %u/0x%04x][idx=%u][expired=%u][hash=%u]",
		   i, head->core.tuple.key.is_ip_flow ? proto2name(head->core.tuple.key.k.ipKey.proto) : "NonIP",
		   _intoa(head->core.tuple.key.k.ipKey.src, buf, sizeof(buf)), head->core.tuple.key.k.ipKey.sport,
		   _intoa(head->core.tuple.key.k.ipKey.dst, buf1, sizeof(buf1)), head->core.tuple.key.k.ipKey.dport,
		   etheraddr_string(head->ext->srcInfo.macAddress, src_buf),
		   etheraddr_string(head->ext->dstInfo.macAddress, dst_buf), vlanId,
		   head->ext->src2dstTos, head->ext->dst2srcTos, tos,
		   head->ext->subflow_id, head->ext->subflow_id, idx,
		   head->core.bucket_expired,
		   head->core.tuple.flow_hash);
	head = head->core.hash.next, i++;
      }
#endif
    }

    if(unlikely(readOnlyGlobals.enable_debug))
    {
      char buf[256], buf1[256];

      traceEvent(TRACE_NORMAL, "[maxBucketSearch=%d][thread_id=%u][idx=%u][packet_hash=%u][vlan=%d][%s][%s:%d -> %s:%d][tos=%u]",
		 readWriteGlobals->maxBucketSearch, thread_id, idx, packet_hash,
		 vlanId, proto2name(proto),
		 _intoa(*src, buf, sizeof(buf)), sport,
		 _intoa(*dst, buf1, sizeof(buf1)), dport,
		 tos);
    }
  }

#ifdef DEBUG
  if(unlikely(readOnlyGlobals.enable_debug))
    traceEvent(TRACE_NORMAL, "Adding new bucket");
#endif

  if(bkt == NULL) {
    if(getAtomic(&readWriteGlobals->bucketsAllocated) >= readOnlyGlobals.maxNumActiveFlows) {
      static u_char msgSent = 0;

      if(!msgSent) {
	traceEvent(TRACE_WARNING, "Too many (%u) active flows [threadId=%u][limit=%u] (see -M)",
		   getAtomic(&readWriteGlobals->bucketsAllocated),
		   thread_id, readOnlyGlobals.maxNumActiveFlows);
	msgSent = 1;
      }
      readWriteGlobals->probeStats.droppedPktsTooManyFlows++;

      hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
      return(bkt);
    }

    bkt = allocFlowBucket(proto, thread_id, mutex_idx, idx);

    if(bkt == NULL) {
      static u_int8_t once = 0;

      if(!once) {
	traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
	once = 1;
      }

      hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);
      return(bkt);
    }
  }

  bkt->magic = MAGIC_NUMBER;

  if(readOnlyGlobals.disableFlowCache)
    setBucketExpired(bkt);

  direction = src2dst_direction, bkt->core.tuple.flow_idx = idx, bkt->core.tuple.flow_hash = packet_hash;

  /* The settings below are done once per direction (we choosed src -> dst) */
  if(record && (rx_packet == 1 /* src -> dst */)) {
    if(record->cisco.nbar2_application_id > 0)
      bkt->core.l7.proto.collected_application_id = record->cisco.nbar2_application_id, bkt->core.l7.proto_type = NBAR2_PROTO_TYPE;

    if(record->ixia.l7_application_id > 0)
      bkt->core.l7.proto.collected_application_id = record->ixia.l7_application_id, bkt->core.l7.proto_type = IXIA_PROTO_TYPE;

    if(record->ixia.src_ip_country[0] != '\0')
      bkt->ext->srcInfo.collected_country_code = strdup(record->ixia.src_ip_country);

    if(record->ixia.src_ip_city[0] != '\0')
      bkt->ext->srcInfo.collected_city = strdup(record->ixia.src_ip_city);

    if(record->ixia.dst_ip_country[0] != '\0')
      bkt->ext->dstInfo.collected_country_code = strdup(record->ixia.dst_ip_country);

    if(record->ixia.dst_ip_city[0] != '\0')
      bkt->ext->dstInfo.collected_city = strdup(record->ixia.dst_ip_city);
  }

  bkt->ext->lastPktDirection = direction, bkt->core.engine_type = engine_type, bkt->core.engine_id = engine_id;
  bkt->core.tuple.key.is_gtp_flow = 0;

  if(use_mac_search) {
    bkt->core.tuple.key.is_ip_flow = 0; /* Mac Flow */
    memcpy(bkt->core.tuple.key.k.macKey.src, ehdr->ether_shost, 6), memcpy(bkt->core.tuple.key.k.macKey.dst, ehdr->ether_dhost, 6);
  } else {
    bkt->core.tuple.key.is_ip_flow = 1; /* IP Flow */
    memcpy(&bkt->core.tuple.key.k.ipKey.src, src, sizeof(HostInfo)), memcpy(&bkt->core.tuple.key.k.ipKey.dst, dst, sizeof(HostInfo));
    updateHost(&bkt->ext->srcInfo, src, flow_sender_ip, if_input);
    updateHost(&bkt->ext->dstInfo, dst, 0 /* unknown */, NO_INTERFACE_INDEX);
  }

  if(osi_src && osi_dst && bkt->ext && readOnlyGlobals.enableExtBucket) {
    bkt->ext->extensions->osi.ssap = strdup(osi_src);
    bkt->ext->extensions->osi.dsap = strdup(osi_dst);
  }

  if(readOnlyGlobals.flowSampleRate > 1) {
    pthread_rwlock_wrlock(&readWriteGlobals->rwGlobalsRwLock);

    if(readWriteGlobals->flowsToGo <= 1) {
      readWriteGlobals->flowsToGo = readOnlyGlobals.flowSampleRate;
    } else {
      readWriteGlobals->flowsToGo--;
      bkt->ext->sampled_flow = 1;
    }

    pthread_rwlock_unlock(&readWriteGlobals->rwGlobalsRwLock);
  }

  bkt->ext->subflow_id = subflow_id, bkt->core.rx_direction.src2dst = rx_packet,
    bkt->core.tuple.key.k.ipKey.proto = proto, bkt->core.tuple.key.vlanId = vlanId, bkt->ext->src2dst_tunnel_id = tunnel_id,
    bkt->core.tuple.key.k.ipKey.sport = sport, bkt->core.tuple.key.k.ipKey.dport = dport,
    bkt->ext->srcInfo.asn = src_as, bkt->ext->dstInfo.asn = dst_as,
    bkt->ext->srcInfo.mask = src_mask, bkt->ext->dstInfo.mask = dst_mask;

  if(readOnlyGlobals.enable_l7_protocol_discovery
     && (bkt->core.l7.proto_type == NO_PROTO_TYPE)) {
    if(gtp_offset > 0)
      ndpi_proto = NDPI_PROTOCOL_GTP;
    else if(ndpi_proto == NDPI_PROTOCOL_UNKNOWN)
      ndpi_proto = find_lru_cache_num(&readWriteGlobals->l7Cache, bkt->core.tuple.flow_hash);

    setnDPIProto(bkt, ndpi_proto);
  }

  /* Tunnels */
  if(readOnlyGlobals.tunnel_mode) {
    if(bkt->ext->extensions && untunneled_src && untunneled_dst) {
      memcpy(&bkt->ext->extensions->untunneled.src, untunneled_src, sizeof(IpAddress));
      memcpy(&bkt->ext->extensions->untunneled.dst, untunneled_dst, sizeof(IpAddress));
      bkt->ext->extensions->untunneled.proto = untunneled_proto;
      bkt->ext->extensions->untunneled.sport = untunneled_sport, bkt->ext->extensions->untunneled.dport = untunneled_dport;
    }
  }

  if(unlikely(readOnlyGlobals.handle_l2 && (ehdr != NULL))) {
    memcpy(bkt->ext->srcInfo.macAddress, (char *)ESRC(ehdr), 6);
    memcpy(bkt->ext->dstInfo.macAddress, (char *)EDST(ehdr), 6);
  }

  bkt->ext->if_input = if_input, bkt->ext->if_output = if_output,
    bkt->core.tuple.flowTimers.firstSeenSent.tv_sec = firstSeen.tv_sec, bkt->core.tuple.flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec,
    bkt->core.tuple.flowTimers.firstSeenSent.tv_usec = firstSeen.tv_usec, bkt->core.tuple.flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
  bkt->core.tuple.flowTimers.firstSeenRcvd.tv_sec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_sec = 0,
    bkt->core.tuple.flowTimers.firstSeenRcvd.tv_usec = bkt->core.tuple.flowTimers.lastSeenRcvd.tv_usec = 0;
  bkt->core.tuple.flowCounters.bytesSent += realLen, bkt->core.tuple.flowCounters.pktSent += numPkts;

  // traceEvent(TRACE_NORMAL, "-> %u/%u [%u]\n", realLen, realLen+14, bkt->core.tuple.flowCounters.bytesRcvd+bkt->core.tuple.flowCounters.bytesSent);
  if(numFragments > 0) bkt->ext->flowCounters.sentFragPkts += numFragments;

  updatePktLenStats(bkt, direction, &h->ts, h->len, ttl, numPkts);
  updateTTL(bkt, 0, ttl);
  if(tos != 0) updateTos(bkt, 0, tos);
  if(proto == IPPROTO_TCP) {
    updateTcpFlags(bkt, src2dst_direction, &h->ts, tcpFlags, tcpMaxSegmentSize, tcpWinScale);
    updateTcpSeq(&h->ts, bkt, src2dst_direction, tcpFlags, tcpSeqNum, tcpAckNum, originalPayloadLen, tcpWin, h, p, len);
  } else if(proto == IPPROTO_UDP)
    updateApplLatency(proto, bkt, src2dst_direction, &h->ts);
  else if((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6)) {
    u_int16_t val = (256 * icmpType) + icmpCode;

    /* We "& 0x7F" as with IPv6 the codes will exceed the bitmask */
    if(direction == src2dst_direction) {
      bkt->ext->protoCounters.icmp.src2dstIcmpType = val;
      NPROBE_FD_SET(icmpType & 0x7F, &bkt->ext->protoCounters.icmp.src2dstIcmpFlags);
    } else {
      bkt->ext->protoCounters.icmp.dst2srcIcmpType = val;
      NPROBE_FD_SET(icmpType & 0x7F, &bkt->ext->protoCounters.icmp.dst2srcIcmpFlags);
    }
  }

  if(readOnlyGlobals.enable_l7_protocol_discovery)
    setPayload(bkt, h, p, ip_offset, payload, payloadLen, 0);

  bkt->ext->protoCounters.tcp.src2dstTcpFlags |= tcpFlags;

#if 0
  if(bkt->ext->extensions && (numMplsLabels > 0)) {
    bkt->ext->extensions->mplsInfo = malloc(sizeof(struct mpls_labels));

    if(bkt->ext->extensions->mplsInfo) {
      bkt->ext->extensions->mplsInfo->numMplsLabels = numMplsLabels;
      memcpy(bkt->ext->extensions->mplsInfo->mplsLabels, mplsLabels,
	     MAX_NUM_MPLS_LABELS*MPLS_LABEL_LEN);
    } else
      traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
  }
#endif

  if(unlikely((bkt->core.tuple.key.is_ip_flow == 1)
	      && (readOnlyGlobals.num_active_plugins > 0)))
    pluginCallback(CREATE_FLOW_CALLBACK, packet_if_idx,
		   bkt, src2dst_direction /* direction */,
		   ip_offset, proto, (numFragments > 0) ? 1 : 0,
		   numPkts,  tos, 0,
		   vlanId, ehdr,
		   src,  sport,
		   dst,  dport, len,
		   tcpFlags, tcpSeqNum,
		   icmpType, numMplsLabels,
		   mplsLabels, h, p, payload, payloadLen);

  addToList(bkt, &readWriteGlobals->theFlowHash[thread_id][idx]);

#ifdef DEBUG_EXPORT
  traceEvent(TRACE_INFO, "Bucket added");
#endif

  if(readOnlyGlobals.disableFlowCache)
    setBucketExpired(bkt);

  if(readOnlyGlobals.traceMode == 2) {
    char buf[256], buf1[256], src_buf[32], dst_buf[32];

    traceEvent(TRACE_NORMAL, "New Flow: [%s] %s:%d -> %s:%d [%s -> %s][vlan %d][tos %d][ifIdx: %u -> %u][subflowId: %u/0x%04x]"
	       "[idx=%u]"
	       // "[packet_hash=%u]"
	       ,
	       bkt->core.tuple.key.is_ip_flow ? proto2name(proto) : "NonIP",
	       _intoa(*src, buf, sizeof(buf)), sport,
	       _intoa(*dst, buf1, sizeof(buf1)), dport,
	       etheraddr_string(bkt->ext->srcInfo.macAddress, src_buf),
	       etheraddr_string(bkt->ext->dstInfo.macAddress, dst_buf),
	       vlanId, tos, bkt->ext->if_input, bkt->ext->if_output,
	       bkt->ext->subflow_id, bkt->ext->subflow_id
	       , idx //, packet_hash
	       );
  }

  hash_unlock(__FILE__, __LINE__, thread_id, mutex_idx);

  if(unlikely(readOnlyGlobals.tracePerformance)) {
    ticks diff = getticks() - when;
    if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
    readOnlyGlobals.processingWithFlowCreationTicks += diff, readOnlyGlobals.num_pkts_with_flow_creation++;
    if(unlikely(readOnlyGlobals.useLocks)) pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
  }

  return(bkt);
}

/* ****************************************************** */

#define	NPROBE_ICMP_V6_ECHO_REQUEST   128		/* V6 echo request */
#define	NPROBE_ICMP_V6_ECHO_REPLY     129		/* V6 echo reply */
#define	NPROBE_ICMP_V6_ROUTER_SOL     133		/* V6 router solicitation */
#define	NPROBE_ICMP_V6_ROUTER_ADV     134		/* V6 router advertisement */
#define	NPROBE_ICMP_V6_NEIGHBOR_SOL   135		/* V6 neighbor solicitation */
#define	NPROBE_ICMP_V6_NEIGHBOR_ADV   136		/* V6 neighbor advertisement */
#define	NPROBE_ICMP_V6_MDPV2          143		/* V6 Multicast Listener Report Message v2 */


void printICMPflags(u_int8_t proto, u_int32_t flags, char *icmpBuf, int icmpBufLen) {

  if(proto == IPPROTO_ICMPV6) {
    snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ECHO_REQUEST & 0x7F, &flags)     ? "[ECHO REQUEST]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ECHO_REPLY & 0x7F, &flags)     ? "[ECHO REPLY]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ROUTER_SOL & 0x7F, &flags)     ? "[ROUTER SOLIC]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_ROUTER_ADV & 0x7F, &flags)     ? "[ROUTER ADV]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_NEIGHBOR_SOL & 0x7F, &flags)     ? "[NEIGHBOR SOLIC]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_NEIGHBOR_ADV & 0x7F, &flags)     ? "[NEIGHBOR ADV]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_V6_MDPV2 & 0x7F, &flags)     ? "[MDP V2]" : ""
	     );
  } else {
    snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ECHOREPLY, &flags)     ? "[ECHO REPLY]" : "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_UNREACH, &flags)       ? "[UNREACH]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_SOURCEQUENCH, &flags)  ? "[SOURCE_QUENCH]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_REDIRECT, &flags)      ? "[REDIRECT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ECHO, &flags)          ? "[ECHO]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERADVERT, &flags)  ? "[ROUTERADVERT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERSOLICIT, &flags) ? "[ROUTERSOLICIT]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TIMXCEED, &flags)      ? "[TIMXCEED]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_PARAMPROB, &flags)     ? "[PARAMPROB]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMP, &flags)        ? "[TIMESTAMP]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMPREPLY, &flags)   ? "[TIMESTAMP REPLY]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_IREQ, &flags)          ? "[INFO REQ]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_IREQREPLY, &flags)     ? "[INFO REPLY]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREQ , &flags)      ? "[MASK REQ]": "",
	     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREPLY, &flags)     ? "[MASK REPLY]": "");
  }
}

/* ****************************************************** */

void printFlow(FlowHashBucket *theFlow, FlowDirection direction) {
  char _buf[256] = { 0 }, _buf1[256] = { 0 }, latBuf[48] = { 0 };
  char *buf, *buf1, *proto_name;
  char vlanStr[16] = { 0 }, tunnelStr[64] = { 0 }, fragmented[32] =  { 0 };
  char icmpBuf[128] = { 0 }, applLatBuf[48] = { 0 }, jitterStr[64] = { 0 };
  char subflowStr[32] = { 0 }, l7proto[32] = { 0 };
  float time_diff;

  if(theFlow->ext) {
    if(((direction == src2dst_direction) && (theFlow->ext->flowCounters.sentFragPkts > 0))
       || ((direction == dst2src_direction) && (theFlow->ext->flowCounters.rcvdFragPkts > 0))) {
      snprintf(fragmented, sizeof(fragmented), "[%u FRAGMENT(S)]",
	       (direction == src2dst_direction) ? theFlow->ext->flowCounters.sentFragPkts
	       : theFlow->ext->flowCounters.rcvdFragPkts);
    }

    if(nwLatencyComputed(theFlow->ext)
       && ((theFlow->ext->extensions->clientNwLatency.tv_sec > 0) || (theFlow->ext->extensions->clientNwLatency.tv_usec > 0))) {
      snprintf(latBuf, sizeof(latBuf), "[CNL: %.3f ms]",
	       (float)(theFlow->ext->extensions->clientNwLatency.tv_sec*1000+(float)theFlow->ext->extensions->clientNwLatency.tv_usec/1000));
    }

    if(nwLatencyComputed(theFlow->ext)
       && ((theFlow->ext->extensions->serverNwLatency.tv_sec > 0) || (theFlow->ext->extensions->serverNwLatency.tv_usec > 0))) {
      int len = strlen(latBuf);

      snprintf(&latBuf[len], sizeof(latBuf)-len, "[SNL: %.3f ms]",
	       (float)(theFlow->ext->extensions->serverNwLatency.tv_sec*1000+(float)theFlow->ext->extensions->serverNwLatency.tv_usec/1000));
    }

    if(applLatencyComputed(theFlow->ext)) {
      if((direction == src2dst_direction)
         && (theFlow->ext->extensions->src2dstApplLatency.tv_sec || theFlow->ext->extensions->src2dstApplLatency.tv_usec))
        snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.3f ms]",
	         timeval2ms(&theFlow->ext->extensions->src2dstApplLatency));
      else if((direction == dst2src_direction)
	      && (theFlow->ext->extensions->dst2srcApplLatency.tv_sec || theFlow->ext->extensions->dst2srcApplLatency.tv_usec))
        snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.3f ms]",
	         timeval2ms(&theFlow->ext->extensions->dst2srcApplLatency));
    }

    if((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_ICMP) || (theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_ICMPV6)) {
      if(direction == src2dst_direction)
        printICMPflags(theFlow->core.tuple.key.k.ipKey.proto, theFlow->ext->protoCounters.icmp.src2dstIcmpFlags, icmpBuf, sizeof(icmpBuf));
      else
        printICMPflags(theFlow->core.tuple.key.k.ipKey.proto, theFlow->ext->protoCounters.icmp.dst2srcIcmpFlags, icmpBuf, sizeof(icmpBuf));
    }

    if(theFlow->ext->src2dst_tunnel_id == 0)
      tunnelStr[0] = '\0';
    else
      snprintf(tunnelStr, sizeof(tunnelStr), "[TunnelId 0x%08X/0x%08X]",
	       theFlow->ext->src2dst_tunnel_id, theFlow->ext->dst2src_tunnel_id);

    if(theFlow->ext->subflow_id == 0)
      subflowStr[0] = '\0';
    else
      snprintf(subflowStr, sizeof(subflowStr), "[SubflowId %u]",
	       theFlow->ext->subflow_id);
  }

  if((theFlow->core.tuple.key.vlanId == 0) || (theFlow->core.tuple.key.vlanId == NO_VLAN))
    vlanStr[0] = '\0';
  else
    snprintf(vlanStr, sizeof(vlanStr), "[VLAN %u]", theFlow->core.tuple.key.vlanId);

  if(readOnlyGlobals.enable_l7_protocol_discovery)
    snprintf(l7proto, sizeof(l7proto), "[%s/%d]",
	     getProtoName(theFlow->core.l7.proto.ndpi.ndpi_proto),
	     theFlow->core.l7.proto.ndpi.ndpi_proto);

  if(theFlow->core.tuple.key.is_ip_flow) {
    buf  = _intoa(theFlow->core.tuple.key.k.ipKey.src, _buf, sizeof(_buf));
    buf1 = _intoa(theFlow->core.tuple.key.k.ipKey.dst, _buf1, sizeof(_buf1));
  } else {
    buf  = etheraddr_string(theFlow->core.tuple.key.k.macKey.src, _buf);
    buf1 = etheraddr_string(theFlow->core.tuple.key.k.macKey.dst, _buf1);
  }

  proto_name = theFlow->core.tuple.key.is_ip_flow ? proto2name(theFlow->core.tuple.key.k.ipKey.proto) : "NonIP";

  if(direction == src2dst_direction) {
    char *initiator = "Unknown";

    if((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) && (theFlow->ext != NULL)) {
      if(theFlow->ext->beginInitiator == src2dst_direction)
	initiator = buf;
      else if(theFlow->ext->beginInitiator == dst2src_direction)
	initiator = buf1;
    }

    time_diff = (readOnlyGlobals.flowCollection.collectorInPort > 0) ? 0 :
      (float)msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenSent,
			&theFlow->core.tuple.flowTimers.firstSeenSent)/1000;

    if(theFlow->core.tuple.key.is_gtp_flow) {
      traceEvent(TRACE_INFO, "Emitting Flow: [->][gtp_teid=%04X][%u pkt/%u bytes]",
		 theFlow->core.tuple.key.k.gtpKey.teid,
		 (int)theFlow->core.tuple.flowCounters.pktSent, (int)theFlow->core.tuple.flowCounters.bytesSent);
    } else {
      if(!readOnlyGlobals.bidirectionalFlows)
	traceEvent(TRACE_INFO, "Emitting Flow: [->][%s] %s:%d -> %s:%d %s[%u pkt/%u bytes][ifIdx %d->%d][%.1f sec]%s%s%s%s%s%s%s%s[init %s]",
		   proto_name, buf, theFlow->core.tuple.key.k.ipKey.sport,
		   buf1, theFlow->core.tuple.key.k.ipKey.dport,
		   subflowStr,
		   (int)theFlow->core.tuple.flowCounters.pktSent, (int)theFlow->core.tuple.flowCounters.bytesSent,
		   theFlow->ext ? theFlow->ext->if_input : 0,
		   theFlow->ext ? theFlow->ext->if_output : 0, time_diff,
		   latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto, initiator);
      else
	traceEvent(TRACE_INFO, "Emitting Flow: [<->][%s] %s:%d -> %s:%d %s[%u/%u pkt][%u/%u bytes][ifIdx %d<->%d][%.1f sec]%s%s%s%s%s%s%s%s[init %s]",
		   proto_name, buf, theFlow->core.tuple.key.k.ipKey.sport,
		   buf1, theFlow->core.tuple.key.k.ipKey.dport,
		   subflowStr,
		   (int)theFlow->core.tuple.flowCounters.pktSent, (int)theFlow->core.tuple.flowCounters.pktRcvd,
		   (int)theFlow->core.tuple.flowCounters.bytesSent, (int)theFlow->core.tuple.flowCounters.bytesRcvd,
		   theFlow->ext ? theFlow->ext->if_input : 0,
		   theFlow->ext ? theFlow->ext->if_output : 0, time_diff,
		   latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto, initiator);
    }
  } else {
    time_diff = (readOnlyGlobals.flowCollection.collectorInPort > 0) ? 0 : (float)msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenRcvd,
									      &theFlow->core.tuple.flowTimers.firstSeenRcvd)/1000;

    traceEvent(TRACE_INFO, "Emitting Flow: [<-][%s] %s:%d -> %s:%d %s[%u pkt/%u bytes][ifIdx %d->%d][%.1f sec]%s%s%s%s%s%s%s%s",
	       proto_name, buf1, theFlow->core.tuple.key.k.ipKey.dport,
	       buf, theFlow->core.tuple.key.k.ipKey.sport, subflowStr,
	       (int)theFlow->core.tuple.flowCounters.pktRcvd, (int)theFlow->core.tuple.flowCounters.bytesRcvd,
	       theFlow->ext ? theFlow->ext->if_output : 0,
	       theFlow->ext ? theFlow->ext->if_input : 0, time_diff,
	       latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr, l7proto);
  }
}

/* ****************************************************** */

u_int8_t endTcpFlow(unsigned short flags) {
  if(((flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK))
     || ((flags & TH_RST) == TH_RST))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

int isFlowExpired(FlowHashBucket *myBucket, time_t theTime) {
  if(!myBucket->core.bucket_expired) {
    if((theTime < myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)
       || (theTime < myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec))
      return(0); /* Too early */
  }

  if(myBucket->core.bucket_expired /* Forced expire */
     || ((theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec) >= readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((myBucket->core.tuple.do_not_expire_for_max_duration == 0)
	 && ((theTime-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec) >= readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
	 )
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (((theTime-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec) >= readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
	     || ((myBucket->core.tuple.do_not_expire_for_max_duration == 0)
		 && ((theTime-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec) >= readOnlyGlobals.lifetimeTimeout))
	     ))  /* flow expired: flow active but too old   */
     || ((myBucket->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) && (theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec > 10 /* sec */)
	 && (myBucket->ext && endTcpFlow(myBucket->ext->protoCounters.tcp.src2dstTcpFlags))
	 && (myBucket->ext && endTcpFlow(myBucket->ext->protoCounters.tcp.dst2srcTcpFlags)))
     /* Checks for avoiding that bad time on received flows
	(e.g. via logs) can create problems with export */
     || (theTime < myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (theTime < myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec))
     /* This should not happen but let's take into account */
     || (theTime < myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec)
     || (theTime < myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec)
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

int isFlowExpiredSinceTooLong(FlowHashBucket *myBucket, time_t theTime) {
  if(myBucket->core.bucket_expired /* Forced expire */
     || ((theTime-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec)  >= 2*readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
     || ((myBucket->core.tuple.flowCounters.pktRcvd > 0)
	 && (((theTime-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec) >= 2*readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
	     || ((theTime-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)))  /* flow expired: flow active but too old   */
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

void printBucket(FlowHashBucket *myBucket) {
  int a = time(NULL)-myBucket->core.tuple.flowTimers.firstSeenSent.tv_sec;
  int b = time(NULL)-myBucket->core.tuple.flowTimers.lastSeenSent.tv_sec;
  int c = myBucket->core.tuple.flowCounters.bytesRcvd ? time(NULL)-myBucket->core.tuple.flowTimers.firstSeenRcvd.tv_sec : 0;
  int d = myBucket->core.tuple.flowCounters.bytesRcvd ? time(NULL)-myBucket->core.tuple.flowTimers.lastSeenRcvd.tv_sec : 0;

#ifdef DEBUG
  if((a > 30) || (b>30) || (c>30) || (d>30))
#endif
    {
      char str[128], str1[128];

      printf("[%4s] %s:%d [%u pkts] <-> %s:%d [%u pkts] [FsSent=%d][LsSent=%d][FsRcvd=%d][LsRcvd=%d]\n",
	     proto2name(myBucket->core.tuple.key.k.ipKey.proto),
	     _intoa(myBucket->core.tuple.key.k.ipKey.src, str, sizeof(str)),
	     myBucket->core.tuple.key.k.ipKey.sport, myBucket->core.tuple.flowCounters.pktSent,
	     _intoa(myBucket->core.tuple.key.k.ipKey.dst, str1, sizeof(str1)),
	     myBucket->core.tuple.key.k.ipKey.dport, myBucket->core.tuple.flowCounters.pktRcvd,
	     a, b, c, d);
    }
}

/* ******************************************************** */

/* NOTE: this function should not be called by a separate thread */
void walkHash(u_int32_t thread_id, int flushHash) {
  if(readWriteGlobals->expireFlowListHead[thread_id] != NULL) {
    if(flushHash) traceEvent(TRACE_NORMAL, "About to flush hash (threadId %d)", thread_id);
    walkHashList(thread_id, flushHash, readWriteGlobals->now);
    if(flushHash) traceEvent(TRACE_NORMAL, "Completed hash walk (thread %d)", thread_id);
  }
}

/* ****************************************************** */

#ifdef HAVE_SQLITE
void sqlite_exec_sql(char* sql) {
  int rc;
  char *zErrMsg = 0;

  if(readWriteGlobals->sqlite3Handler == NULL) {
    traceEvent(TRACE_ERROR, "NULL sqlite3 handler [%s]", sql);
    return;
  }

  rc = sqlite3_exec(readWriteGlobals->sqlite3Handler, sql, NULL, 0, &zErrMsg);
  if(rc != SQLITE_OK) {
    traceEvent(TRACE_ERROR, "SQL error: %s [%s]", sql, zErrMsg);
    sqlite3_free(zErrMsg);
  }
}
#endif

/* ****************************************************** */

void close_dump_file() {
  /*
     We need locks as both exportBucket() and idleThreadTask()
     can manipulate the dump files simultanously
   */
  pthread_rwlock_wrlock(&readWriteGlobals->dumpFileLock);

  switch(readOnlyGlobals.dumpFormat) {
  case sqlite_format:
#ifdef HAVE_SQLITE
    if(readWriteGlobals->sqlite3Handler != NULL) {
      sqlite_exec_sql("commit;");
      sqlite3_close(readWriteGlobals->sqlite3Handler);
      readWriteGlobals->sqlite3Handler = NULL;
      traceEvent(TRACE_NORMAL, "Insert %u rows into the saved database",
		 readWriteGlobals->sql_row_idx);
    }
#endif
    break;

  case binary_format:
  case text_format:
  case binary_core_flow_format:
    if(readWriteGlobals->flowFd != NULL) {
      fclose(readWriteGlobals->flowFd);
      readWriteGlobals->flowFd = NULL;
    }
    break;
  }

  if(readWriteGlobals->dumpFilePath[0] != '\0') {
    char newPath[512]; /* same size as dumpFilePath */
    int len = strlen(readWriteGlobals->dumpFilePath)-strlen(TEMP_PREFIX);

    strncpy(newPath, readWriteGlobals->dumpFilePath, len); newPath[len] = '\0';
    rename(readWriteGlobals->dumpFilePath, newPath);
    traceEvent(TRACE_NORMAL, "Flow file '%s' is now available", newPath);
    execute_command(readOnlyGlobals.execCmdDump, newPath);
  }

  pthread_rwlock_unlock(&readWriteGlobals->dumpFileLock);
}

/* ****************************************************** */

#ifdef HAVE_GEOIP
void geoLocate(IpAddress *addr, HostInfo *bkt) {
  if((readOnlyGlobals.geo_ip_city_db == NULL) || (bkt->geo != NULL))
    return;

  pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);
  if(addr->ipVersion == 4)
    bkt->geo = GeoIP_record_by_ipnum(readOnlyGlobals.geo_ip_city_db, addr->ipType.ipv4);
#ifdef HAVE_GEOIP_IPv6
  else if((addr->ipVersion == 6) && readOnlyGlobals.geo_ip_city_db_v6)
    bkt->geo = GeoIP_record_by_ipnum_v6(readOnlyGlobals.geo_ip_city_db_v6, addr->ipType.ipv6);
#endif

  pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
}
#endif

/* ****************************************************** */

void checkExportFileClose() {
  if(readWriteGlobals->flowFd
     && (readWriteGlobals->now > readOnlyGlobals.flowFd_close_time)) {
    close_dump_file();
  }
}

/* ************************************ */

void dumpFlowToCache(FlowHashBucket *myBucket) {
  u_int16_t id = readWriteGlobals->now % MAX_NUM_REDIS_CONNECTIONS;

  // traceEvent(TRACE_ERROR, "==>>> %s(%d)", __FUNCTION__, readOnlyGlobals.imsi_aggregation_enabled);

  if(readOnlyGlobals.imsi_aggregation_enabled) {
    //if(myBucket->core.user.username) traceEvent(TRACE_ERROR, "==>>> %s", myBucket->core.user.username);
    if(myBucket->core.user.username
       && (myBucket->core.user.username[16] == ';' /* IMSI "284031100221392;1000;12373;0" */)) {
      char imsi[16], key[64];
      const u_int aggregation_time = 300 /* 5 min */;
      struct timeval *begin_time = getFlowBeginTime(myBucket, src2dst_direction);

      strncpy(imsi, &myBucket->core.user.username[1], 15);
      imsi[15] = '\0';
      snprintf(key, sizeof(key)-1, "%u.%s.%s",
	       (unsigned int)(begin_time->tv_sec - (begin_time->tv_sec % aggregation_time)),
	       imsi, getProtoName(myBucket->core.l7.proto.ndpi.ndpi_proto));

      incrCacheHashKeyValueNumber(key, id, "flows", 1);
      incrCacheHashKeyValueNumber(key, id, "packets", myBucket->core.tuple.flowCounters.pktRcvd + myBucket->core.tuple.flowCounters.pktSent);
      incrCacheHashKeyValueNumber(key, id, "bytes", myBucket->core.tuple.flowCounters.bytesRcvd + myBucket->core.tuple.flowCounters.bytesSent);
      incrCacheHashKeyValueNumber(key, id, "duration", getFlowDurationSec(myBucket));
      //traceEvent(TRACE_ERROR, "==>>> %s", key);
    }
  }

  if(readOnlyGlobals.ucloud_enabled) {
    char src_buf[256], dst_buf[256], *src, *dst;

    src = _intoa(myBucket->core.tuple.key.k.ipKey.src, src_buf, sizeof(src_buf)),
      dst = _intoa(myBucket->core.tuple.key.k.ipKey.dst, dst_buf, sizeof(dst_buf));

    incrCacheHashKeyValueNumber(src, id, "bytes.sent", myBucket->core.tuple.flowCounters.bytesSent);
    incrCacheHashKeyValueNumber(src, id, "bytes.rcvd", myBucket->core.tuple.flowCounters.bytesRcvd);
    incrCacheHashKeyValueNumber(dst, id, "bytes.sent", myBucket->core.tuple.flowCounters.bytesRcvd);
    incrCacheHashKeyValueNumber(dst, id, "bytes.rcvd", myBucket->core.tuple.flowCounters.bytesSent);

    /*
      Compute the top X hosts

      http://highscalability.com/blog/2011/7/6/11-common-web-use-cases-solved-in-redis.html
      http://antirez.com/post/take-advantage-of-redis-adding-it-to-your-stack.html

      Get the top 5 senders
      redis 127.0.0.1:6379> zrange bytes.topSenders -5 -1 WITHSCORES

    */
    zIncrCacheHashKeyValueNumber("bytes.topSenders",   id, src, myBucket->core.tuple.flowCounters.bytesSent);
    zIncrCacheHashKeyValueNumber("bytes.topReceivers", id, dst, myBucket->core.tuple.flowCounters.bytesRcvd);

    if(myBucket->core.l7.proto.ndpi.ndpi_proto != NDPI_PROTOCOL_UNKNOWN) {
      char *pname = getProtoName(myBucket->core.l7.proto.ndpi.ndpi_proto);
      char sbuf[256], dbuf[256];

      snprintf(sbuf, sizeof(sbuf), "%s.sent", pname), snprintf(dbuf, sizeof(dbuf), "%s.rcvd", pname);
      incrCacheHashKeyValueNumber(src, id, sbuf, myBucket->core.tuple.flowCounters.bytesSent);
      incrCacheHashKeyValueNumber(src, id, dbuf, myBucket->core.tuple.flowCounters.bytesRcvd);
      incrCacheHashKeyValueNumber(dst, id, sbuf, myBucket->core.tuple.flowCounters.bytesRcvd);
      incrCacheHashKeyValueNumber(dst, id, dbuf, myBucket->core.tuple.flowCounters.bytesSent);
    }

    expireCacheKey("", id, src, 43200 /* 12h */), expireCacheKey("", id, dst, 43200 /* 12h */);
  }
}

/* ****************************************************** */

static void check_dump_file_open(void) {
  if(unlikely(readOnlyGlobals.dirPath != NULL)) {
    time_t theTime;

    if(readOnlyGlobals.reforgeTimestamps)
      theTime = readWriteGlobals->now = time(NULL);
    else
      theTime = readWriteGlobals->now;

    /*
       We need locks as both exportBucket() and idleThreadTask()
       can manipulate the dump files simultanously
    */
    checkExportFileClose();

    /* Lock after the checkExportFileClose() otherwise we starve */
    pthread_rwlock_wrlock(&readWriteGlobals->dumpFileLock);

    if(readWriteGlobals->flowFd == NULL) {
      struct tm *tm;
      char file_id[64], creation_time[256], dir_path[256];

#ifdef HAVE_SQLITE
      if(readWriteGlobals->sqlite3Handler == NULL) {
#endif
      tm = localtime(&theTime);

      if(!readOnlyGlobals.nestDumpDirs) {
	creation_time[0] = '\0', snprintf(dir_path, sizeof(dir_path), "%s", readOnlyGlobals.dirPath);
	snprintf(file_id, sizeof(file_id), "%04u%02u%02u_%02u%02u%02u",
		 tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);
      } else {
	strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H", tm);
	snprintf(dir_path, sizeof(dir_path), "%s%c%s",
		 readOnlyGlobals.dirPath, CONST_DIR_SEP, creation_time);
	snprintf(file_id, sizeof(file_id), "%02u",
		 tm->tm_min - (tm->tm_min % ((readOnlyGlobals.file_dump_timeout+59)/60)));
      }

      mkdir_p(dir_path);

      snprintf(readWriteGlobals->dumpFilePath,
	       sizeof(readWriteGlobals->dumpFilePath),
	       "%s%c%s%s%s.%s%s",
	       readOnlyGlobals.dirPath, '/', creation_time,
	       (creation_time[0] == '\0') ? "" : "/",
	       file_id,
#ifdef HAVE_SQLITE
	       (readOnlyGlobals.dumpFormat == sqlite_format) ? "sqlite" : "flows",
#else
	       "flows",
#endif
	       TEMP_PREFIX);

#ifdef WIN32
      revertSlash(readWriteGlobals->dumpFilePath, 0);
#endif

#ifdef HAVE_SQLITE
      if(readOnlyGlobals.dumpFormat == sqlite_format) {
	traceEvent(TRACE_NORMAL, "About to open database %s", readWriteGlobals->dumpFilePath);

	if(sqlite3_open(readWriteGlobals->dumpFilePath, &readWriteGlobals->sqlite3Handler) != 0) {
	  traceEvent(TRACE_WARNING, "Unable to create database %s' [%s]",
		     readWriteGlobals->dumpFilePath, sqlite3_errmsg(readWriteGlobals->sqlite3Handler));
	  sqlite3_close(readWriteGlobals->sqlite3Handler);
	  readWriteGlobals->sqlite3Handler = NULL;
	} else {
	  int i;
	  char sql_buffer[2048] = { '\0' };

	  traceEvent(TRACE_NORMAL, "Saving flows into temporary database '%s'",
		     readWriteGlobals->dumpFilePath);
	  snprintf(sql_buffer, sizeof(sql_buffer), "begin; create table flows (");

	  /* Dump header */
	  for(i=0; i<TEMPLATE_LIST_LEN; i++) {
	    if(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i] != NULL) {
	      if(i > 0) snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ", ");
	      snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer),
		       "%s %s",
		       readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->netflowElementName,
		       (readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->templateElementLen <= 4) ? "number" : "string");
	    } else
	      break;
	  }

	  snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ")");
	  sqlite_exec_sql(sql_buffer);
	}
      }
#endif

      if((readOnlyGlobals.dumpFormat == text_format)
	 || (readOnlyGlobals.dumpFormat == binary_format)
	 || (readOnlyGlobals.dumpFormat == binary_core_flow_format)
	 ) {
	if((readWriteGlobals->flowFd = fopen(readWriteGlobals->dumpFilePath, "w+b")) == NULL) {
	  traceEvent(TRACE_WARNING, "Unable to create file '%s' [errno=%d]",
		     readWriteGlobals->dumpFilePath, errno);
	} else {
	  theTime -= (theTime % readOnlyGlobals.file_dump_timeout);
	  readOnlyGlobals.flowFd_close_time = theTime + readOnlyGlobals.file_dump_timeout;

	  traceEvent(TRACE_NORMAL, "Saving flows into temporary file '%s'",
		     readWriteGlobals->dumpFilePath);

	  /* Dump header */
	  if(readOnlyGlobals.dumpFormat == text_format) {
	    if(!readOnlyGlobals.simulateStorage) {
	      int i;

	      for(i=0; i<TEMPLATE_LIST_LEN; i++) {
		if(readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i] != NULL) {
		  if(i > 0)
		    fprintf(readWriteGlobals->flowFd, "%s", readOnlyGlobals.csv_separator);
		  fprintf(readWriteGlobals->flowFd, "%s",
			  readOnlyGlobals.userTemplateBuffer.v9TemplateElementList[i]->netflowElementName);
		} else
		  break;
	      }

	      fprintf(readWriteGlobals->flowFd, "\n");
	    }
	  }
	}
      }

      readWriteGlobals->sql_row_idx = 0;
#ifdef HAVE_SQLITE
      }
#endif
    }


    pthread_rwlock_unlock(&readWriteGlobals->dumpFileLock);
  }
}

/* ****************************************************** */

/*
  NOTE

  A flow might call exportBucket() several times for instance if it
  expires before the expected time.

  So before allocating memory into exportBucket() make sure that
  you're not allocating it several times
*/
void exportBucket(FlowHashBucket *myBucket, u_char free_memory) {
  if(unlikely(readOnlyGlobals.demo_mode && readOnlyGlobals.demo_expired))
    return;

  if(readOnlyGlobals.enable_l7_protocol_discovery
     && readOnlyGlobals.l7.enable_l7_protocol_guess
     && (myBucket->core.l7.proto.ndpi.ndpi_proto == NDPI_PROTOCOL_UNKNOWN)
     // && myBucket->core.l7.proto.ndpi.flow
     ) {
    u_int16_t ndpi_proto;

    ndpi_proto = ndpi_guess_undetected_protocol(readOnlyGlobals.l7.l7handler,
						myBucket->core.tuple.key.k.ipKey.proto,
						myBucket->core.tuple.key.k.ipKey.src.ipType.ipv4,
						myBucket->core.tuple.key.k.ipKey.sport,
						myBucket->core.tuple.key.k.ipKey.dst.ipType.ipv4,
						myBucket->core.tuple.key.k.ipKey.dport);
    setnDPIProto(myBucket, ndpi_proto);
  }

  switch(readOnlyGlobals.l7.discard_unknown_flows) {
  case 1: /* Export only known flows */
    if(myBucket->core.l7.proto.ndpi.ndpi_proto == NDPI_PROTOCOL_UNKNOWN)
      return;
    break;
  case 2: /* Export only unknown flows */
    if(myBucket->core.l7.proto.ndpi.ndpi_proto != NDPI_PROTOCOL_UNKNOWN)
      return;
    break;
  }

  /* Pre-export activities */
  if((!readOnlyGlobals.none_specified) && readOnlyGlobals.computeInterfaceIndexes && myBucket->ext) {
    if(myBucket->ext->if_input == NO_INTERFACE_INDEX)  myBucket->ext->if_input = ifIdx(myBucket, 1);
    if(myBucket->ext->if_output == NO_INTERFACE_INDEX) myBucket->ext->if_output = ifIdx(myBucket, 0);
  }

  if((readOnlyGlobals.numLocalNetworks > 0) && myBucket->core.tuple.key.is_ip_flow) {
    IpAddress *host;
    struct in_addr addr;

    host = &myBucket->core.tuple.key.k.ipKey.src;

    if(host->ipVersion == 4) {
      addr.s_addr = host->ipType.ipv4;
      host->localHost = isLocalAddress(&addr);

      host = &myBucket->core.tuple.key.k.ipKey.dst;
      addr.s_addr = host->ipType.ipv4;
      host->localHost = isLocalAddress(&addr);
    }
  }


#ifdef HAVE_REDIS
  if(readOnlyGlobals.redis.read_context != NULL) {
    if(readOnlyGlobals.mapUserTraffic) mapTrafficToUser(myBucket);
    dumpFlowToCache(myBucket);
  }
#endif

  /*
     It might happen that a plugin exports a bucket while we're exporting
     and thus we need to lock
  */
  pthread_rwlock_wrlock(&readWriteGlobals->exportRwLock);

#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_city_db != NULL) {
    /* We need to geo-locate this flow */
    geoLocate(&myBucket->core.tuple.key.k.ipKey.src, &myBucket->ext->srcInfo);
    geoLocate(&myBucket->core.tuple.key.k.ipKey.dst, &myBucket->ext->dstInfo);
  }
#endif

  check_dump_file_open();

  if((myBucket->core.tuple.key.k.ipKey.proto != TCP_PROTOCOL)
     || (myBucket->core.tuple.flowCounters.bytesSent >= readOnlyGlobals.minFlowSize)) {
    exportBucketToNetflow(myBucket, src2dst_direction);
  }

  /* *********************** */

  if((readOnlyGlobals.netFlowVersion == 5)
     || ((readOnlyGlobals.netFlowVersion != 5) && (!readOnlyGlobals.bidirectionalFlows))) {
    if(myBucket->core.tuple.flowCounters.bytesRcvd > 0) {
      /*
	v9 flows do not need to be exported twice, once per direction
	as they are bi-directional. However if the flow format does not
	contain bi-directional info (e.g. IN_BYTES, OUT_BYTES) the two
	flow directions need to be sent anyway. Hence we decide to send
	both flow directions
      */

      if((myBucket->core.tuple.key.k.ipKey.proto != TCP_PROTOCOL)
	 || (myBucket->core.tuple.flowCounters.bytesRcvd >= readOnlyGlobals.minFlowSize)) {
	exportBucketToNetflow(myBucket, dst2src_direction);
      }
    }
  }

  if(free_memory) {
    if(unlikely((myBucket->core.tuple.key.is_ip_flow == 1)
		&& (readOnlyGlobals.num_active_plugins > 0)))
      pluginCallback(DELETE_FLOW_CALLBACK,
		     -1 /* packet_if_idx, -1 = unknown */,
		     myBucket, 0,
		     0, 0, 0,
		     0, 0, 0,
		     0, NULL,
		     NULL, 0,
		     NULL, 0,
		     0,
		     0, 0, 0, 0, NULL,
		     NULL, NULL, NULL, 0);
  }

  pthread_rwlock_unlock(&readWriteGlobals->exportRwLock);

  myBucket->core.tuple.flow_serial = 0; /* Reset it for future flows */
}

/* ****************************************************** */

void discardBucket(FlowHashBucket *myBucket) {
  readWriteGlobals->probeStats.totFlowBytesDropped +=
    myBucket->core.tuple.flowCounters.bytesSent + myBucket->core.tuple.flowCounters.bytesRcvd;
  readWriteGlobals->probeStats.totFlowPktsDropped +=
    myBucket->core.tuple.flowCounters.pktSent + myBucket->core.tuple.flowCounters.pktRcvd;

  if(unlikely((myBucket->core.tuple.key.is_ip_flow == 1)
	      && (readOnlyGlobals.num_active_plugins > 0)))
    pluginCallback(DELETE_FLOW_CALLBACK,
		   -1 /* packet_if_idx, -1 = unknown */,
		   myBucket, 0,
		   0, 0, 0,
		   0, 0, 0,
		   0, NULL,
		   NULL, 0,
		   NULL, 0,
		   0,
		   0, 0, 0, 0, NULL,
		   NULL, NULL, NULL, 0);

  purgeBucket(myBucket);
}

/* ****************************************************** */

void queueBucketToExport(FlowHashBucket *myBucket) {
  if(readWriteGlobals->exportBucketsLen > MAX_EXPORT_QUEUE_LEN) {
    static char show_message = 0;

    if(!show_message) {
      if(readOnlyGlobals.flowExportDelay > 0) {
	traceEvent(TRACE_WARNING,
		   "Too many (%u) queued buckets for export: bucket discarded.",
		   readWriteGlobals->exportBucketsLen);
	traceEvent(TRACE_WARNING, "Please check -e value and decrease it.");
	show_message = 1;
      }
    }

    discardBucket(myBucket);
  } else {
    pthread_rwlock_wrlock(&readWriteGlobals->exportMutex);
    addToList(myBucket, &readWriteGlobals->exportQueue);
    readWriteGlobals->exportBucketsLen++;
#ifdef DEBUG
    traceEvent(TRACE_NORMAL, "[+] [exportBucketsLen=%d][myBucket=%p]",
	       readWriteGlobals->exportBucketsLen, myBucket);
#endif
    pthread_rwlock_unlock(&readWriteGlobals->exportMutex);
  }
}

/* ****************************************************** */

void* dequeueBucketToExport(void* notUsed) {
#if 0
  u_int num_exported = 0;
#endif

#ifdef linux
  if(readOnlyGlobals.exportThreadAffinity >= 0)
    bindthread2core(pthread_self(), readOnlyGlobals.exportThreadAffinity);
#endif

  traceEvent(TRACE_INFO, "Starting bucket dequeue thread");

  readOnlyGlobals.dequeueBucketToExport_up = 1;

  while(readWriteGlobals->shutdownInProgress < 2) {
#if 0
    if(unlikely(readOnlyGlobals.enable_debug))
      traceEvent(TRACE_NORMAL, "dequeueBucketToExport()");
#endif

    if(readWriteGlobals->exportQueue == NULL) {
      if(readWriteGlobals->shutdownInProgress < 2) {
	/* traceEvent(TRACE_INFO, "About to call waitCondvar()"); */
	waitCondvar(&readWriteGlobals->exportQueueCondvar);
	/* traceEvent(TRACE_INFO, "waitCondvar() called"); */
#if 0
	num_exported = 0;
#endif
      } else
	break;
    }

    if(readWriteGlobals->exportQueue != NULL) {
      FlowHashBucket *myBucket;

#if 0
      if(num_exported >= 100) {
	usleep(2000);
	num_exported = 0;
      }
#endif

      /* Remove bucket from list */
      pthread_rwlock_wrlock(&readWriteGlobals->exportMutex);
      if(readWriteGlobals->exportQueue != NULL) {
	myBucket = getListHead(&readWriteGlobals->exportQueue);
	if(myBucket != NULL) {
	  if(readWriteGlobals->exportBucketsLen == 0)
	    traceEvent(TRACE_WARNING, "Internal error (exportBucketsLen == 0)");
	  else
	    readWriteGlobals->exportBucketsLen--;
	}
      } else
	myBucket = NULL;

      pthread_rwlock_unlock(&readWriteGlobals->exportMutex);

      if(myBucket != NULL) {
	/* Export bucket */
	ticks when, when1, diff;

	// traceEvent(TRACE_NORMAL, "[-] [exportBucketsLen=%d][myBucket=%p][bucketsAllocated=%u]", readWriteGlobals->exportBucketsLen, myBucket, readWriteGlobals->bucketsAllocated);

	if(unlikely(readOnlyGlobals.tracePerformance)) when = getticks();
	exportBucket(myBucket, 1);

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  when1 = getticks();
	  diff = when1 - when;
	  pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.bucketExportTicks += diff, readOnlyGlobals.num_exported_buckets++;
	  pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}

	purgeBucket(myBucket);

	if(unlikely(readOnlyGlobals.tracePerformance)) {
	  diff = getticks() - when1;
	  pthread_rwlock_wrlock(&readOnlyGlobals.ticksLock);
	  readOnlyGlobals.bucketPurgeTicks += diff,  readOnlyGlobals.num_purged_buckets++;
	  pthread_rwlock_unlock(&readOnlyGlobals.ticksLock);
	}
      }
    }
  }

  readOnlyGlobals.dequeueBucketToExport_up = 0;

  traceEvent(TRACE_INFO, "Export thread terminated [exportQueue=%x]",
	     readWriteGlobals->exportQueue);
  signalCondvar(&readWriteGlobals->termCondvar, 0);
  return(NULL);
}

/* ****************************************************** */

void purgeBucket(FlowHashBucket *myBucket) {
  PluginInformation *next_info, *info;

  info = myBucket->ext ? myBucket->ext->plugin : NULL;

  myBucket->magic = 0;

  /* These pointers should have been already freed by plugins */
  while(info != NULL) {
    if(info->pluginData) free(info->pluginData);
    next_info = info->next;
    free(info);
    info = next_info;
  }

  freenDPI(myBucket);

  if(myBucket->core.user.username != NULL) {
    free(myBucket->core.user.username);
    myBucket->core.user.username = NULL;
  }

  if(myBucket->core.server.name != NULL) {
    free(myBucket->core.server.name);
    myBucket->core.server.name = NULL;
  }

  /*
    Do not move this statement below as we will free
    myBucket->ext invalidating its value
  */
  decAtomic(&readWriteGlobals->bucketsAllocated, 1);

  if(myBucket->ext) {
    /*
      On Windows all mutexes that have been created must be destroyed otherwise
      they leak handles and thus the system runs out of memory/handles
    */

#ifdef HAVE_GEOIP
    if(myBucket->ext->srcInfo.geo) GeoIPRecord_delete(myBucket->ext->srcInfo.geo);
    if(myBucket->ext->dstInfo.geo) GeoIPRecord_delete(myBucket->ext->dstInfo.geo);
#endif

    if(myBucket->ext->srcInfo.collected_country_code) {
      free(myBucket->ext->srcInfo.collected_country_code);
      myBucket->ext->srcInfo.collected_country_code = NULL;
    }

    if(myBucket->ext->dstInfo.collected_country_code) {
      free(myBucket->ext->dstInfo.collected_country_code);
      myBucket->ext->dstInfo.collected_country_code = NULL;
    }

    if(myBucket->ext->srcInfo.collected_city) {
      free(myBucket->ext->srcInfo.collected_city);
      myBucket->ext->srcInfo.collected_city = NULL;
    }

    if(myBucket->ext->dstInfo.collected_city) {
      free(myBucket->ext->dstInfo.collected_city);
      myBucket->ext->dstInfo.collected_city = NULL;
    }

    if(myBucket->ext->srcInfo.aspath != NULL) {
      free(myBucket->ext->srcInfo.aspath);
      myBucket->ext->srcInfo.aspath = NULL;
    }

    if(myBucket->ext->dstInfo.aspath != NULL) {
      free(myBucket->ext->dstInfo.aspath);
      myBucket->ext->dstInfo.aspath = NULL;
    }

    if(myBucket->ext && myBucket->ext->extensions) {
      if(myBucket->ext->extensions->osi.ssap != NULL) {
	free(myBucket->ext->extensions->osi.ssap);
	myBucket->ext->extensions->osi.ssap = NULL;
      }

      if(myBucket->ext->extensions->osi.dsap != NULL) {
	free(myBucket->ext->extensions->osi.dsap);
	myBucket->ext->extensions->osi.dsap = NULL;
      }
    }

    if(myBucket->ext->extensions) {
#if 0
      if(myBucket->ext->extensions->mplsInfo) free(myBucket->ext->extensions->mplsInfo);
#endif
      free(myBucket->ext->extensions);
      myBucket->ext->extensions = NULL;
    }

    free(myBucket->ext);
  }

#if 0
  traceEvent(TRACE_NORMAL, "[-] bucketsAllocated=%u",
	     readWriteGlobals->bucketsAllocated[myBucket->ext ? myBucket->ext->thread_id : 0]);
#endif

  free(myBucket);
}

/* ****************************************************** */

void idleThreadTask(u_int8_t thread_id, u_int8_t context_type) {
  //traceEvent(TRACE_NORMAL, "idleThreadTask(%d) [context_type: %u]", thread_id, context_type);

  if(readOnlyGlobals.dontExportFlowsDuringProcessing) return;

  /* We need to update in case no more packets are coming */
  if(readOnlyGlobals.pcapFile == NULL)
    readWriteGlobals->now = time(NULL);

  if(unlikely(!readOnlyGlobals.disableFlowCache)) {
    if(likely((readWriteGlobals->idleTaskNextUpdate[thread_id] > 0)
	      && (readWriteGlobals->shutdownInProgress || (readWriteGlobals->now < readWriteGlobals->idleTaskNextUpdate[thread_id]))))
      return;
  }

  // traceEvent(TRACE_NORMAL, "idleThreadTask(%d) begin [context_type: %u]", thread_id, context_type);

  /* We're not reading from a pcap file dump */
  if(readOnlyGlobals.pcapFile == NULL)
    readWriteGlobals->now = time(NULL);

  checkExportFileClose(); /* Close dump files if open since too long */
  walkHashList(thread_id, 0, readWriteGlobals->now);
  readWriteGlobals->idleTaskNextUpdate[thread_id] = readWriteGlobals->now + 1 /* IDLE_TASK_UPDATE_FREQUENCY */;

  /* We call the idle task only for the first thread */
  if(thread_id == 0) {
    pluginIdleThreadTask();
    checkNetFlowExport(0); /* Flush queued flows */
  }
}

/* ******************************************** */

struct timeval* getFlowBeginTime(FlowHashBucket *theFlow, FlowDirection direction) {
  struct timeval *t;

  if(readOnlyGlobals.bidirectionalFlows) {
    if((theFlow->core.tuple.flowTimers.firstSeenRcvd.tv_sec == 0)
       || (toMs(&theFlow->core.tuple.flowTimers.firstSeenSent) < toMs(&theFlow->core.tuple.flowTimers.firstSeenRcvd)))
      t = &theFlow->core.tuple.flowTimers.firstSeenSent;
    else
      t = &theFlow->core.tuple.flowTimers.firstSeenRcvd;
  } else {
    t = (direction == src2dst_direction) ? &theFlow->core.tuple.flowTimers.firstSeenSent : &theFlow->core.tuple.flowTimers.firstSeenRcvd;
  }

  // if(t->tv_sec == 0) traceEvent(TRACE_ERROR, "==> t->tv_sec=%u", t->tv_sec);

  return(t);
}

/* ******************************************** */

struct timeval* getFlowEndTime(FlowHashBucket *theFlow, FlowDirection direction) {
  struct timeval *t;

  if(readOnlyGlobals.bidirectionalFlows) {
    if((theFlow->core.tuple.flowTimers.lastSeenRcvd.tv_sec == 0)
       || (toMs(&theFlow->core.tuple.flowTimers.lastSeenSent) > toMs(&theFlow->core.tuple.flowTimers.lastSeenRcvd)))
      t = &theFlow->core.tuple.flowTimers.lastSeenSent;
    else
      t = &theFlow->core.tuple.flowTimers.lastSeenRcvd;
  } else {
    t = (direction == src2dst_direction) ? &theFlow->core.tuple.flowTimers.lastSeenSent : &theFlow->core.tuple.flowTimers.lastSeenRcvd;
  }

  // if(t->tv_sec == 0) traceEvent(TRACE_ERROR, "==> t->tv_sec=%u", t->tv_sec);

  return(t);
}

/* ******************************************** */

u_int32_t getFlowDurationSec(FlowHashBucket *theFlow) {
  u_int32_t first = getFlowBeginTime(theFlow, src2dst_direction)->tv_sec;
  u_int32_t last  = max(theFlow->core.tuple.flowTimers.lastSeenSent.tv_sec, theFlow->core.tuple.flowTimers.lastSeenRcvd.tv_sec);

  return(last-first+1);
}

