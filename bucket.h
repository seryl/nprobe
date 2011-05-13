/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2002-2010 Luca Deri <deri@ntop.org> 
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

#ifndef _BUCKET_H_
#define _BUCKET_H_

/* ********************************** */

#define ENABLE_MAGIC

/* ********************************** */

/*
 * fallbacks for essential typedefs
 */
#ifdef WIN32
#ifndef __GNUC__
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
#endif
typedef u_char  u_int8_t;
typedef u_short u_int16_t;
typedef uint   u_int32_t;
#endif /* WIN32 */

/* ********************************** */

#define NPROBE_FD_SET(n, p)   (*(p) |= (1 << (n)))
#define NPROBE_FD_CLR(n, p)   (*(p) &= ~(1 << (n)))
#define NPROBE_FD_ISSET(n, p) (*(p) & (1 << (n)))
#define NPROBE_FD_ZERO(p)     (*(p) = 0)


#define MAX_PAYLOAD_LEN          1400 /* bytes */

#define FLAG_NW_LATENCY_COMPUTED           1
#define FLAG_APPL_LATENCY_COMPUTED         2
#define FLAG_FRAGMENTED_PACKET_SRC2DST     3
#define FLAG_FRAGMENTED_PACKET_DST2SRC     4


#define nwLatencyComputed(a)          (NPROBE_FD_ISSET(FLAG_NW_LATENCY_COMPUTED,       &(a->flags)))
#define applLatencyComputed(a)        (NPROBE_FD_ISSET(FLAG_APPL_LATENCY_COMPUTED,     &(a->flags)))


#ifdef WIN32

#define _WS2TCPIP_H_ /* Avoid compilation problems */
#define IPV4_ONLY    /* On Win32 we support just IPv4 as transport */

/* IPv6 address */
/* Already defined in WS2tcpip.h */
struct win_in6_addr
  {
    union
      {
        u_int8_t u6_addr8[16];
        u_int16_t u6_addr16[8];
        u_int32_t u6_addr32[4];
      } in6_u;
#ifdef s6_addr
#undef s6_addr
#endif

#ifdef s6_addr16
#undef s6_addr16
#endif

#ifdef s6_addr32
#undef s6_addr32
#endif

#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32

};

#define in6_addr win_in6_addr

struct ip6_hdr
  {
    union
      {
        struct ip6_hdrctl
          {
            u_int32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
            u_int16_t ip6_un1_plen;   /* payload length */
            u_int8_t  ip6_un1_nxt;    /* next header */
            u_int8_t  ip6_un1_hlim;   /* hop limit */
          } ip6_un1;
        u_int8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

/* Generic extension header.  */
struct ip6_ext
  {
    u_int8_t  ip6e_nxt;		/* next header.  */
    u_int8_t  ip6e_len;		/* length in units of 8 octets.  */
  };

#else /* WIN32 */

#ifndef s6_addr32
#ifdef linux
#define s6_addr32 in6_u.u6_addr32
#else
#if defined(sun) 
#define	s6_addr32	_S6_un._S6_u32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif
#endif
#endif /* WIN32*/

/* ********************************** */

#define MAX_NUM_MPLS_LABELS     10
#define MPLS_LABEL_LEN           3

/* ********************************** */

typedef struct ipAddress {
  u_int8_t ipVersion; /* Either 4 or 6 */
  
  union {
    struct in6_addr ipv6;
    u_int32_t ipv4; /* Host byte code */
  } ipType;
} IpAddress;

struct mpls_labels {
  u_short numMplsLabels;
  u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
};

struct pluginInfo; /* engine.h */

typedef struct pluginInformation {
  struct pluginInfo *pluginPtr;
  void *pluginData;
  struct pluginInformation *next;
} PluginInformation;

/* *************************************** */

typedef struct hostTrafficStats {
  u_int32_t num_flows_client, num_flows_server;
  u_int32_t num_pkts_sent, num_pkts_rcvd;
  u_int32_t num_bytes_sent, num_bytes_rcvd;
  u_int32_t num_tcp_flows_client, num_udp_flows_client, num_icmp_flows_client;
  u_int32_t num_tcp_flows_server, num_udp_flows_server, num_icmp_flows_server;
} HostTraffic;

/* *************************************** */

typedef struct hostStats {
  time_t nextMinUpdate;
  HostTraffic accumulateStats, lastMinStats;
  pthread_rwlock_t host_lock;
  u_int32_t num_references; /* number of flows that reference this host */
  void *next; /* recast to (struct hostHashBucket*) */
} HostStats;

/*
 * If the host is local then stats points to a valid
 * memory area, otherwise it points to NULL
 */

typedef struct hostHashBucket {
  IpAddress host;
  u_int32_t ifHost;
  u_int16_t ifIdx;
  HostStats *stats; /* NULL for untracked hosts */
#ifdef HAVE_GEOIP
  GeoIPRecord *geo; /* GeoIP */
#endif
  u_int8_t aspath_len; /* Number of entries != 0 in aspath */
  u_int32_t *aspath; /* If allocated it will be MAX_AS_PATH_LEN long */
} HostHashBucket;

/* *************************************** */

typedef enum {
  src2dst_direction = 0,
  dst2src_direction
} FlowDirection;

/* *************************************** */

typedef struct flowHashBucket {
#ifdef ENABLE_MAGIC
  u_char magic;
#endif
  u_int32_t flow_idx;
  u_int32_t subflow_id;    /* Usually is 0: user for subflows on UDP-based proto such as DNS */
  u_int8_t swap_flow;      /* 0= don't swap, 1=in case of bidirectional flow send the reverse only */
  u_int8_t sampled_flow;   /* 0=normal flow, 1=sampled flow (i.e. to discard) */
  u_char bucket_expired;  /* Force bucket to expire */
  u_int8_t proto;          /* protocol (e.g. UDP/TCP..) */
  u_int32_t tunnel_id;     /* E.g. GTP tunnel */
  u_int16_t if_input, if_output;
  u_int32_t src_as, dst_as;
  u_int8_t src_mask, dst_mask;
  u_char  srcMacAddress[6];
  HostHashBucket *src;
  u_short sport;
  HostHashBucket *dst;
  u_char  dstMacAddress[6];
  u_short dport;
  u_char src2dstTos, dst2srcTos;
  u_short vlanId;
  struct mpls_labels *mplsInfo;
  
  struct {
    /* This entry is filled only in case of tunneled addresses */
    u_int8_t proto;
    HostHashBucket *src, *dst;
    u_short sport, dport;
  } untunneled;

  /* **************** */
  
  struct {
    struct timeval firstSeenSent, lastSeenSent;
    struct timeval firstSeenRcvd, lastSeenRcvd;
    u_int32_t prev_lastSeenSent, prev_lastSeenRcvd;
  } flowTimers;

  struct {
    u_int32_t bytesSent, pktSent;
    u_int32_t bytesRcvd, pktRcvd;
    u_int32_t sentFragPkts, rcvdFragPkts;

    struct {
      u_int32_t sentRetransmitted, rcvdRetransmitted;
      u_int32_t sentOOOrder, rcvdOOOrder;
    } tcpPkts;

    struct {
      u_int16_t longest, shortest;
    } pktSize; /* bytes */
  } flowCounters;

  u_int16_t src2dstTcpFlags, dst2srcTcpFlags;
  u_int32_t src2dstIcmpFlags, dst2srcIcmpFlags;  /* ICMP bitmask */
  u_int16_t src2dstIcmpType, dst2srcIcmpType;    /* ICMP type */
  
  u_char src2dstPayloadLen;   /* # of bytes stored on the payload */
  unsigned char *src2dstPayload;
  u_char dst2srcPayloadLen;   /* # of bytes stored on the payload */
  unsigned char *dst2srcPayload;
  u_int32_t flags;               /* bitmask (internal) */
  struct timeval synTime, synAckTime; /* network Latency (3-way handshake) */
  FlowDirection terminationInitiator; /* src2dst = client, dst2src = server */

  /* TCP Sequence number counters */
  u_int32_t src2dstNextSeqNum, dst2srcNextSeqNum;

  /*
     client <------------> nprobe <-------------------> server 
     |<- clientNwDelay ->|        |<- serverNwDelay --------->|
     |<----------- network delay/latency -------------------->|
  */
  struct timeval clientNwDelay; /* The RTT between the client and nprobe */
  struct timeval serverNwDelay; /* The RTT between nprobe and the server */
  struct timeval src2dstApplLatency, dst2srcApplLatency; /* Application Latency */
  PluginInformation *plugin;
 
  struct flowHashBucket *next;
} FlowHashBucket;

#endif /* _BUCKET_H_ */
