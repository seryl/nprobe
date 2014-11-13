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

#ifndef _BUCKET_H_
#define _BUCKET_H_

/* ********************************** */

#define MAGIC_NUMBER   67

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


#define NPROBE_UNKNOWN_VALUE              0
#define NPROBE_UNKNOWN_VALUE_STR          "0"

#define nwLatencyComputed(a)          (a && NPROBE_FD_ISSET(FLAG_NW_LATENCY_COMPUTED,   &(a->flags)))
#define applLatencyComputed(a)        (a && NPROBE_FD_ISSET(FLAG_APPL_LATENCY_COMPUTED, &(a->flags)))


#ifdef WIN32

#define _WS2TCPIP_H_ /* Avoid compilation problems */
#define HAVE_SIN6_LEN

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

/*
   NOTE

   whenever you change this datastructure
   please update sortFlowIndex()
*/
typedef struct flow_index {
  u_int8_t vlanId, proto;
  u_int32_t srcHost, dstHost;
  u_int16_t sport, dport;
  u_int8_t tos;
  u_int16_t subflow_id;
} FlowIndex;

/* ********************************** */

typedef struct ipAddress {
  u_int8_t ipVersion:3 /* Either 4 or 6 */,
    localHost:1, /* -L: filled up during export not before (see exportBucket()) */
    notUsed:4 /* Future use */;

  union {
    struct in6_addr ipv6;
    u_int32_t ipv4; /* Host byte code */
  } ipType;
} IpAddress;

struct mpls_labels {
  u_short numMplsLabels;
  u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
};

struct pluginEntryPoint; /* engine.h */

typedef struct pluginInformation {
  struct pluginEntryPoint *pluginPtr;
  void *pluginData;
  u_int8_t plugin_used;
  struct pluginInformation *next;
} PluginInformation;

/*
 * If the host is local then stats points to a valid
 * memory area, otherwise it points to NULL
 */

typedef struct hostInfo {
  u_char macAddress[6];
  u_int8_t mask;
  u_int16_t ifIdx;
  u_int32_t ifHost, asn;
#ifdef HAVE_GEOIP
  GeoIPRecord *geo; /* GeoIP */
#endif
  char *collected_country_code, *collected_city;
  u_int8_t aspath_len; /* Number of entries != 0 in aspath */
  u_int32_t *aspath; /* If allocated it will be MAX_AS_PATH_LEN long */
} HostInfo;

/* *************************************** */

typedef enum {
  unknown_direction = 0,
  src2dst_direction,
  dst2src_direction
} FlowDirection;

/* *************************************** */

typedef struct tv {
  u_int32_t tv_sec, tv_usec;
} _tv;

typedef struct {
  u_int32_t num_pkts_up_to_128_bytes, num_pkts_128_to_256_bytes,
    num_pkts_256_to_512_bytes, num_pkts_512_to_1024_bytes,
    num_pkts_1024_to_1514_bytes, num_pkts_over_1514_bytes;
} EtherStats;

typedef struct {
  u_int32_t num_pkts_eq_1, num_pkts_2_5,
  num_pkts_5_32, num_pkts_32_64, num_pkts_64_96,
    num_pkts_96_128, num_pkts_128_160, num_pkts_160_192,
    num_pkts_192_224, num_pkts_224_255;
} TTLStats;

struct tcp_seq_num {
  u_int32_t last, next;
};

typedef struct {
  struct mpls_labels *mplsInfo;

  struct {
    /* This entry is filled only in case of tunneled addresses */
    u_int8_t proto;
    IpAddress src, dst;
    u_int16_t sport, dport;
  } untunneled;

  struct {
    char *ssap, *dsap;
  } osi;

  struct timeval synTime, synAckTime; /* network Latency (3-way handshake) */

  struct {
    EtherStats src2dst, dst2src;
  } etherstats;

  /* TCP Sequence number counters */
  struct {
    struct tcp_seq_num src2dst, dst2src;
  } tcpseq;

  struct {
    TTLStats src2dst, dst2src;
  } ttlstats;

  /*
    client <--------------> nprobe <-----------------------------> server
    |<- clientNwLatency ->|        |<- serverNwLatency --------->|
    |<--------------- network delay/latency -------------------->|
  */
  struct timeval clientNwLatency; /* The RTT/2 between the client and nprobe */
  struct timeval serverNwLatency; /* The RTT/2 between nprobe and the server */
  struct timeval src2dstApplLatency, dst2srcApplLatency; /* Application Latency */
} FlowHashBucketExtensions;

/* *************************************** */

struct flowHashBucket; /* Forward */

typedef struct {
  struct flowHashBucket *prev, *next;
} CircularList;

/* *************************************** */

typedef struct {
  IpAddress src, dst;
  u_int16_t sport, dport;
  u_int8_t proto; /* protocol (e.g. UDP/TCP..) */
} IPKey;

typedef struct {
  u_int32_t teid;
  u_int16_t cell_id;
} GTPKey;

typedef struct {
  u_int8_t src[6], dst[6];
} MacKey;

/* *************************************** */

typedef struct flowHashBucketKeyFields {
  u_int8_t is_gtp_flow:1, is_ip_flow:7; /* 1=IPv4/v6 flow, 0=Ethernet (no IP) flow */
  u_int16_t vlanId;

  union {
    IPKey ipKey;
    MacKey macKey;
    GTPKey gtpKey;
  } k;

} FlowHashBucketKeyFields;

/* *************************************** */

typedef struct flowHashBucketCoreFields {
  u_int32_t flow_idx, flow_hash, flow_serial;
  u_int8_t do_not_expire_for_max_duration; /* Flags */

  /* Key */
  FlowHashBucketKeyFields key;

  /* Value */
  struct {
    struct timeval firstSeenSent, lastSeenSent;
    struct timeval firstSeenRcvd, lastSeenRcvd;
  } flowTimers;

  struct {
    u_int32_t bytesSent, pktSent;
    u_int32_t bytesRcvd, pktRcvd;
  } flowCounters;

} FlowHashBucketCoreFields;

/* *************************************** */

#define NO_PROTO_TYPE        0
#define NDPI_PROTO_TYPE      1
#define NBAR2_PROTO_TYPE     2
#define IXIA_PROTO_TYPE      3

typedef struct flowHashMicroBucket {
  FlowHashBucketCoreFields tuple; /* Flow core fields */
  u_int8_t dont_export_flow; /*
			       Set it to 1 if when the flow has to be exported, its memory
			       will be freed but the flow will not be exported
			     */
  u_int8_t engine_type, engine_id; /* 0=use default */

  struct direction {
    u_int8_t src2dst, dst2src; /* 1=RX [receive], 0=TX [transmit] (packet direction) */
  } rx_direction;

  /* L7 protocol */
  struct {
    u_int8_t proto_type /* ***_PROTO_TYPE */;

    union {
      struct {
	u_int8_t searched_port_based_protocol, detection_completed;
	u_int16_t ndpi_proto;
	struct ndpi_flow_struct *flow;
	struct ndpi_id_struct *src, *dst;
      } ndpi;

      u_int32_t collected_application_id;
    } proto;
  } l7;

  /* Flow -> User Mapping */
  struct {
    u_int8_t user_searched; /* 0=we have not yet tried to match the user
			       1=we have already tried to match the user
			         thus if username==NULL it means that
				 we failed
			    */
    char *username;
  } user;

  /* Flow -> Server Mapping */
  struct {
    u_int8_t server_searched;
    char *name;
  } server;

  u_int8_t bucket_expired; /* Force bucket to expire */
  u_int8_t purge_at_next_loop;

  CircularList hash; /* Hash collision list pointers */

  /* Expire List (max flow duration) */
  CircularList max_duration;

  /* Idle flows (no traffic [idle]) */
  CircularList no_traffic;
} FlowHashMicroBucket;

/* *************************************** */

typedef struct {
  u_int8_t thread_id;      /* Thread on which the bucket was allocated */
  u_int32_t subflow_id;    /*
			     Usually is 0: user for subflows on UDP-based proto such as DNS
			     or sequence number in GTP
			   */
  u_int8_t swap_flow;      /* 0= don't swap, 1=in case of bidirectional flow send the reverse only */
  u_int8_t sampled_flow;   /* 0=normal flow, 1=sampled flow (i.e. to discard) */
  u_int32_t src2dst_tunnel_id, dst2src_tunnel_id;     /* E.g. GTP tunnel */

  u_int32_t if_input, if_output;
  u_int8_t src2dstTos, dst2srcTos;
  u_int8_t src2dstMinTTL, dst2srcMinTTL, src2dstMaxTTL, dst2srcMaxTTL;
  IpAddress nextHop;
  HostInfo srcInfo, dstInfo; /* src and dst host metadata information */

  FlowHashBucketExtensions *extensions;

  /* **************** */

  struct {
    u_int16_t sentFragPkts, rcvdFragPkts;

    struct {
      u_int16_t longest, shortest;
    } pktSize; /* bytes */
  } flowCounters;

  union {
    struct {
      u_int32_t bytesRcvdRetransmitted, pktRcvdRetransmitted;
      u_int32_t bytesSentRetransmitted, pktSentRetransmitted;
      u_int32_t sentOOOrder, rcvdOOOrder;
      u_int16_t src2dstTcpFlags, dst2srcTcpFlags;
      u_int16_t src2dstLastWin, dst2srcLastWin;
      u_int16_t tcpMaxSegmentSize;
      u_int8_t tcpWinScale;
    } tcp;

    struct {
      u_int32_t src2dstIcmpFlags, dst2srcIcmpFlags;  /* ICMP bitmask */
      u_int16_t src2dstIcmpType, dst2srcIcmpType;    /* ICMP type */
    } icmp;
  } protoCounters;

  FlowDirection lastPktDirection; /* Direction of the last flow packet */
  FlowDirection beginInitiator, terminationInitiator;
  u_int32_t flags;                    /* bitmask (internal) */

  PluginInformation *plugin;
} FlowHashExtendedBucket;

/* *************************************** */

typedef struct flowHashBucket {
  u_int8_t magic;

  FlowHashMicroBucket core;
  FlowHashExtendedBucket *ext;
} FlowHashBucket;

#endif /* _BUCKET_H_ */
