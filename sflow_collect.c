/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2009-11 Luca Deri <deri@ntop.org> 
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

/*
 *  ntop includes sFlow(TM), freely available from http://www.inmon.com/".
 *
 * Some code has been copied from the InMon sflowtool
 */

#include "nprobe.h"

/* #define DEBUG_FLOWS */

#define INET6 1

u_int32_t numsFlowsV2Rcvd = 0, numsFlowsV4Rcvd = 0, numsFlowsV5Rcvd = 0, numBadsFlowsVersionsRcvd = 0;

/* ********************************* */

enum SFLAddress_type {
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef union _SFLAddress_value {
  struct in_addr ip_v4;
  struct in6_addr ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
  u_int32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  u_int32_t header_protocol;            /* (enum SFLHeader_protocol) */
  u_int32_t frame_length;               /* Original length of packet before sampling */
  u_int32_t stripped;                   /* header/trailer bytes stripped by sender */
  u_int32_t header_length;              /* length of sampled header bytes to follow */
  u_int8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  u_int32_t eth_len;       /* The length of the MAC packet excluding
			      lower layer encapsulations */
  u_int8_t src_mac[8];    /* 6 bytes + 2 pad */
  u_int8_t dst_mac[8];
  u_int32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  u_int32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;   /* TCP flags */
  u_int32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */
#ifdef INET6
typedef struct _SFLSampled_ipv6 {
  u_int32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;    /* TCP flags */
  u_int32_t priority;     /* IP priority */
} SFLSampled_ipv6;
#endif

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority;   /* The 802.1p priority */
  u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  u_int32_t src_mask;               /* Source address prefix mask bits */
  u_int32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};

typedef struct _SFLExtended_as_path_segment {
  u_int32_t type;   /* enum SFLExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t *set;
    u_int32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t *communities;                   /* set of communities */
  u_int32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  u_int32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  u_int32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  u_int32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  u_int32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  u_int32_t depth;
  u_int32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

/* Extended NAT data
   Packet header records report addresses as seen at the sFlowDataSource.
   The extended_nat structure reports on translated source and/or destination
   addesses for this packet. If an address was not translated it should
   be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

/* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
  SFLString tunnel_lsp_name;  /* Tunnel name */
  u_int32_t tunnel_id;        /* Tunnel ID */
  u_int32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
  SFLString vc_instance_name; /* VC instance name */
  u_int32_t vll_vc_id;        /* VLL/VC instance ID */
  u_int32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
   - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
  SFLString mplsFTNDescr;
  u_int32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
   - Definition from MPLS-LDP-STD-MIB mplsFecTable
   Note: mplsFecAddrType, mplsFecAddr information available
   from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
  u_int32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information
   Record outer VLAN encapsulations that have
   been stripped. extended_vlantunnel information
   should only be reported if all the following conditions are satisfied:
   1. The packet has nested vlan tags, AND
   2. The reporting device is VLAN aware, AND
   3. One or more VLAN tags have been stripped, either
   because they represent proprietary encapsulations, or
   because switch hardware automatically strips the outer VLAN
   encapsulation.
   Reporting extended_vlantunnel information is not a substitute for
   reporting extended_switch information. extended_switch data must
   always be reported to describe the ingress/egress VLAN information
   for the packet. The extended_vlantunnel information only applies to
   nested VLAN tags, and then only when one or more tags has been
   stripped. */

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel {
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each
			  TPID,TCI pair is represented as a single 32 bit
			  integer. Layers listed from outermost to
			  innermost. */
} SFLExtended_vlan_tunnel;

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
#ifdef INET6
  SFLSampled_ipv6 ipv6;
#endif
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  u_int32_t tag;  /* SFLFlow_type_tag */
  u_int32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};

/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t source_id;            /* fsSourceId */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

/* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t ds_class;             /* EXPANDED */
  u_int32_t ds_index;             /* EXPANDED */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t inputFormat;          /* EXPANDED */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t outputFormat;         /* EXPANDED */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} SFLVlan_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC      = 1,
  SFLCOUNTERS_ETHERNET     = 2,
  SFLCOUNTERS_TOKENRING    = 3,
  SFLCOUNTERS_VG           = 4,
  SFLCOUNTERS_VLAN         = 5
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  u_int32_t tag; /* SFLCounters_type_tag */
  u_int32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t source_id;          /* fsSourceId */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t ds_class;           /* EXPANDED */
  u_int32_t ds_index;           /* EXPANDED */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  u_int32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  u_int32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  u_int32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  u_int32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  u_int32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#define YES 1
#define NO  0



enum INMAddress_type {
  INMADDRESSTYPE_IP_V4 = 1,
  INMADDRESSTYPE_IP_V6 = 2
};

typedef union _INMAddress_value {
  struct in_addr ip_v4;
#ifdef INET6
  struct in6_addr ip_v6;
#endif
} INMAddress_value;

typedef struct _INMAddress {
  u_int32_t type;           /* enum INMAddress_type */
  INMAddress_value address;
} INMAddress;

/* Packet header data */

#define INM_MAX_HEADER_SIZE 256   /* The maximum sampled header size. */
#define INM_DEFAULT_HEADER_SIZE 128
#define INM_DEFAULT_COLLECTOR_PORT 6343
#define INM_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum INMHeader_protocol {
  INMHEADER_ETHERNET_ISO8023     = 1,
  INMHEADER_ISO88024_TOKENBUS    = 2,
  INMHEADER_ISO88025_TOKENRING   = 3,
  INMHEADER_FDDI                 = 4,
  INMHEADER_FRAME_RELAY          = 5,
  INMHEADER_X25                  = 6,
  INMHEADER_PPP                  = 7,
  INMHEADER_SMDS                 = 8,
  INMHEADER_AAL5                 = 9,
  INMHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  INMHEADER_IPv4                 = 11,
  INMHEADER_IPv6                 = 12
};

typedef struct _INMSampled_header {
  u_int32_t header_protocol;            /* (enum INMHeader_protocol) */
  u_int32_t frame_length;               /* Original length of packet before sampling */
  u_int32_t header_length;              /* length of sampled header bytes to follow */
  u_int8_t header[INM_MAX_HEADER_SIZE]; /* Header bytes */
} INMSampled_header;

/* Packet IP version 4 data */

typedef struct _INMSampled_ipv4 {
  u_int32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;   /* TCP flags */
  u_int32_t tos;         /* IP type of service */
} INMSampled_ipv4;

/* Packet IP version 6 data */
#ifdef INET6
typedef struct _INMSampled_ipv6 {
  u_int32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;    /* TCP flags */
  u_int32_t tos;          /* IP type of service */
} INMSampled_ipv6;
#endif

/* Packet data */

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 4 data */
};

typedef union _INMPacket_data_type {
  INMSampled_header header;
  INMSampled_ipv4 ipv4;
#ifdef INET6
  INMSampled_ipv6 ipv6;
#endif
} INMPacket_data_type;

/* Extended data types */

/* Extended switch data */

typedef struct _INMExtended_switch {
  u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority;   /* The 802.1p priority */
  u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority;   /* The 802.1p priority */
} INMExtended_switch;

/* Extended router data */

typedef struct _INMExtended_router {
  INMAddress nexthop;               /* IP address of next hop router */
  u_int32_t src_mask;               /* Source address prefix mask bits */
  u_int32_t dst_mask;               /* Destination address prefix mask bits */
} INMExtended_router;

/* Extended gateway data */

enum INMExtended_as_path_segment_type {
  INMEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  INMEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};

typedef struct _INMExtended_as_path_segment {
  u_int32_t type;   /* enum INMExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t *set;
    u_int32_t *seq;
  } as;
} INMExtended_as_path_segment;

/* note: the INMExtended_gateway structure has changed between v2 and v4.
   Here is the old version first... */

typedef struct _INMExtended_gateway_v2 {
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_length;             /* number of AS numbers in path */
  u_int32_t *dst_as_path;
} INMExtended_gateway_v2;

/* now here is the new version... */

typedef struct _INMExtended_gateway_v4 {
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  INMExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t *communities;                   /* set of communities */
  u_int32_t localpref;                      /* LocalPref associated with this route */
} INMExtended_gateway_v4;

/* Extended user data */
typedef struct _INMExtended_user {
  u_int32_t src_user_len;
  char *src_user;
  u_int32_t dst_user_len;
  char *dst_user;
} INMExtended_user;
enum INMExtended_url_direction {
  INMEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  INMEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _INMExtended_url {
  u_int32_t direction; /* enum INMExtended_url_direction */
  u_int32_t url_len;
  char *url;
} INMExtended_url;

/* Extended data */

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

/* Format of a single sample */

typedef struct _INMFlow_sample {
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t source_id;            /* fsSourceId */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  u_int32_t packet_data_tag;       /* enum INMPacket_information_type */
  INMPacket_data_type packet_data; /* Information about sampled packet */

  /* in the sFlow packet spec the next field is the number of extended objects
     followed by the data for each one (tagged with the type).  Here we just
     provide space for each one, and flags to enable them.  The correct format
     is then put together by the serialization code */
  int gotSwitch;
  INMExtended_switch switchDevice;
  int gotRouter;
  INMExtended_router router;
  int gotGateway;
  union {
    INMExtended_gateway_v2 v2;  /* make the version explicit so that there is */
    INMExtended_gateway_v4 v4;  /* less danger of mistakes when upgrading code */
  } gateway;
  int gotUser;
  INMExtended_user user;
  int gotUrl;
  INMExtended_url url;
} INMFlow_sample;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _INMIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2239)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} INMIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _INMEthernet_specific_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} INMEthernet_specific_counters;

typedef struct _INMEthernet_counters {
  INMIf_counters generic;
  INMEthernet_specific_counters ethernet;
} INMEthernet_counters;

/* FDDI interface counters - see RFC 1512 */
typedef struct _INMFddi_counters {
  INMIf_counters generic;
} INMFddi_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _INMTokenring_specific_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} INMTokenring_specific_counters;

typedef struct _INMTokenring_counters {
  INMIf_counters generic;
  INMTokenring_specific_counters tokenring;
} INMTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _INMVg_specific_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} INMVg_specific_counters;

typedef struct _INMVg_counters {
  INMIf_counters generic;
  INMVg_specific_counters vg;
} INMVg_counters;

/* WAN counters */

typedef struct _INMWan_counters {
  INMIf_counters generic;
} INMWan_counters;

typedef struct _INMVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} INMVlan_counters;

/* Counters data */

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

typedef union _INMCounters_type {
  INMIf_counters generic;
  INMEthernet_counters ethernet;
  INMTokenring_counters tokenring;
  INMFddi_counters fddi;
  INMVg_counters vg;
  INMWan_counters wan;
  INMVlan_counters vlan;
} INMCounters_type;

typedef struct _INMCounters_sample_hdr {
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t source_id;          /* fsSourceId */
  u_int32_t sampling_interval;  /* fsCounterSamplingInterval */
} INMCounters_sample_hdr;

typedef struct _INMCounters_sample {
  INMCounters_sample_hdr hdr;
  u_int32_t counters_type_tag;  /* Enum INMCounters_version */
  INMCounters_type counters;    /* Counter set for this interface type */
} INMCounters_sample;

enum INMSample_types {
  FLOWSAMPLE  = 1,
  COUNTERSSAMPLE = 2
};

typedef union _INMSample_type {
  INMFlow_sample flowsample;
  INMCounters_sample counterssample;
} INMSample_type;

/* Format of a sample datagram */

enum INMDatagram_version {
  INMDATAGRAM_VERSION2 = 2,
  INMDATAGRAM_VERSION4 = 4
};

typedef struct _INMSample_datagram_hdr {
  u_int32_t datagram_version;      /* (enum INMDatagram_version) = VERSION4 */
  INMAddress agent_address;        /* IP address of sampling agent */
  u_int32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  u_int32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  u_int32_t num_samples;           /* Number of flow and counters samples to follow */
} INMSample_datagram_hdr;

#define INM_MAX_DATAGRAM_SIZE 1500
#define INM_MIN_DATAGRAM_SIZE 200
#define INM_DEFAULT_DATAGRAM_SIZE 1400

#define INM_DATA_PAD 400




/* define my own IP header struct - to ease portability */
struct myiphdr
{
  u_int8_t version_and_headerLen;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
};

/* same for tcp */
struct mytcphdr
{
  u_int16_t th_sport;		/* source port */
  u_int16_t th_dport;		/* destination port */
  u_int32_t th_seq;		/* sequence number */
  u_int32_t th_ack;		/* acknowledgement number */
  u_int8_t th_off_and_unused;
  u_int8_t th_flags;
  u_int16_t th_win;		/* window */
  u_int16_t th_sum;		/* checksum */
  u_int16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
  u_int16_t uh_sport;           /* source port */
  u_int16_t uh_dport;           /* destination port */
  u_int16_t uh_ulen;            /* udp length */
  u_int16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  /* ignore the rest */
};

#ifdef SPOOFSOURCE
#define SPOOFSOURCE_SENDPACKET_SIZE 2000
struct mySendPacket {
  struct myiphdr ip;
  struct myudphdr udp;
  u_char data[SPOOFSOURCE_SENDPACKET_SIZE];
};
#endif

typedef struct _SFConfig {
  /* sflow options */
  u_int16_t sFlowInputPort;
  /* netflow options */
  u_int16_t netFlowOutputPort;
  struct in_addr netFlowOutputIP;
  int netFlowOutputSocket;
  u_int16_t netFlowPeerAS;
  int disableNetFlowScale;
  /* tcpdump options */
  int tcpdumpFormat;
  u_int32_t tcpdumpHdrPad;
  u_char zeroPad[100];

#ifdef SPOOFSOURCE
  int spoofSource;
  u_int16_t ipid;
  struct mySendPacket sendPkt;
  u_int32_t packetLen;
#endif
} SFConfig;

/* make the options structure global to the program */

typedef struct _SFSample {
  struct in_addr sourceIP;
  SFLAddress agent_addr;
  u_int32_t agentSubId;

  /* the raw pdu */
  u_char *rawSample;
  u_int32_t rawSampleLen;
  u_char *endp;

  /* decode cursor */
#if 0
  u_int32_t *datap;
#else
  u_char *datap;
#endif

  u_int32_t datagramVersion;
  u_int32_t sampleType;
  u_int32_t ds_class;
  u_int32_t ds_index;

  /* generic interface counter sample */
  SFLIf_counters ifCounters;

  /* sample stream info */
  u_int32_t sysUpTime;
  u_int32_t sequenceNo;
  u_int32_t sampledPacketSize;
  u_int32_t samplesGenerated;
  u_int32_t meanSkipCount;
  u_int32_t samplePool;
  u_int32_t dropEvents;

  /* the sampled header */
  u_int32_t packet_data_tag;
  u_int32_t headerProtocol;
  u_char *header;
  int headerLen;
  u_int32_t stripped;

  /* header decode */
  int gotIPV4;
  int offsetToIPV4;
  struct in_addr dcd_srcIP;
  struct in_addr dcd_dstIP;
  u_int32_t dcd_ipProtocol;
  u_int32_t dcd_ipTos;
  u_int32_t dcd_ipTTL;
  u_int32_t dcd_sport;
  u_int32_t dcd_dport;
  u_int32_t dcd_tcpFlags;
  u_int32_t ip_fragmentOffset;
  u_int32_t udp_pduLen;

  /* ports */
  u_int32_t inputPortFormat;
  u_int32_t outputPortFormat;
  u_int32_t inputPort;
  u_int32_t outputPort;

  /* ethernet */
  u_int32_t eth_type;
  u_int32_t eth_len;
  u_char eth_src[8];
  u_char eth_dst[8];

  /* vlan */
  u_int32_t in_vlan;
  u_int32_t in_priority;
  u_int32_t internalPriority;
  u_int32_t out_vlan;
  u_int32_t out_priority;

  /* extended data fields */
  u_int32_t num_extended;
  u_int32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

  /* IP forwarding info */
  SFLAddress nextHop;
  u_int32_t srcMask;
  u_int32_t dstMask;

  /* BGP info */
  SFLAddress bgp_nextHop;
  u_int32_t my_as;
  u_int32_t src_as;
  u_int32_t src_peer_as;
  u_int32_t dst_as_path_len;
  u_int32_t *dst_as_path;
  /* note: version 4 dst as path segments just get printed, not stored here, however
   * the dst_peer and dst_as are filled in, since those are used for netflow encoding
   */
  u_int32_t dst_peer_as;
  u_int32_t dst_as;

  u_int32_t communities_len;
  u_int32_t *communities;
  u_int32_t localpref;

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  u_int32_t src_user_charset;
  u_int32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  u_int32_t dst_user_charset;
  u_int32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  u_int32_t url_direction;
  u_int32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  u_int32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  /* mpls */
  SFLAddress mpls_nextHop;

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* counter blocks */
  u_int32_t statsSamplingInterval;
  u_int32_t counterBlockVersion;
} SFSample;

/* ********************************* */

#ifdef DEBUG_FLOWS
#define SFLOW_DEBUG(a) (1)
#else
#define SFLOW_DEBUG(a) (0)
#endif

/* ****************************** */

/* =============================================================== */

static void handleSflowSample(SFSample *sample, int deviceId) {
  struct pcap_pkthdr pkthdr;

  pkthdr.ts.tv_sec = time(NULL);
  pkthdr.ts.tv_usec = 0;
  pkthdr.caplen = sample->headerLen;
  pkthdr.len = sample->sampledPacketSize;
#ifdef DEBUG_FLOWS
  traceEvent(TRACE_NORMAL, "decodePacket(len=%d/%d)", pkthdr.caplen, pkthdr.len);
#endif
  decodePacket(&pkthdr, sample->header, 
	       1 /* sampledPacket */, sample->samplePool,
	       sample->ifCounters.ifIndex,
	       sample->ifCounters.ifIndex,
	       ntohl(sample->sourceIP.s_addr)); /* Pass the packet to nProbe */
}

/* =============================================================== */

/* Forward */
void SFABORT(SFSample *s, int r);
int printHex(const u_char *a, int len, u_char *buf, int bufLen, int marker, int bytesPerOutputLine);
char *IP_to_a(u_int32_t ipaddr, char *buf);

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

void SFABORT(SFSample *s, int r) {
#ifdef DEBUG_FLOWS
  traceEvent(TRACE_WARNING, "SFABORT: %d\n", r);
#endif
}



/*_________________---------------------------__________________
  _________________        printHex           __________________
  -----------------___________________________------------------
*/

static u_char bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

int printHex(const u_char *a, int len, u_char *buf, int bufLen, int marker, int bytesPerOutputLine)
{
  int b = 0, i = 0;
  for(; i < len; i++) {
    u_char byte;
    if(b > (bufLen - 10)) break;
    if(marker > 0 && i == marker) {
      buf[b++] = '<';
      buf[b++] = '*';
      buf[b++] = '>';
      buf[b++] = '-';
    }
    byte = a[i];
    buf[b++] = bin2hex(byte >> 4);
    buf[b++] = bin2hex(byte & 0x0f);
    if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
    else {
      // separate the bytes with a dash
      if (i < (len - 1)) buf[b++] = '-';
    }
  }
  buf[b] = '\0';
  return b;
}

/*_________________---------------------------__________________
  _________________      IP_to_a              __________________
  -----------------___________________________------------------
*/

char *IP_to_a(u_int32_t ipaddr, char *buf)
{
  u_char *ip = (u_char *)&ipaddr;
  sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return buf;
}


/*_________________---------------------------__________________
  _________________    receiveError           __________________
  -----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump)
{
  char ipbuf[51];
  u_char scratch[6000];
  char *msg = "";
  char *hex = "";
  u_int32_t markOffset = (u_char *)sample->datap - sample->rawSample;
  if(errm) msg = errm;
  if(hexdump) {
    printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
    hex = (char*)scratch;
  }
  fprintf(stderr, "%s (source IP = %s) %s\n", msg, IP_to_a(sample->sourceIP.s_addr, ipbuf), hex);

  SFABORT(sample, SF_ABORT_DECODE_ERROR);
}

static void skipBytes(SFSample *sample, int skip) {
#if 0
  int quads = (skip + 3) / 4;

  sample->datap += quads;
#else
  /* Luca's fix */
  sample->datap += skip;
#endif
  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);
}

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len) {
  u_int32_t actualLen = (u_char *)sample->datap - start;

  if(actualLen != len)
  {
    traceEvent(TRACE_WARNING, "%s length error (expected %d, found %d)", description, len, actualLen);
    SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample, int deviceId)
{
  u_char *start = (u_char *)sample->header;
  u_char *end = start + sample->headerLen;
  u_char *ptr = start;
  u_int16_t type_len;

  /* assume not found */
  sample->gotIPV4 = NO;

  if(sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  ptr += 6;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  ptr += 6;
  type_len = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if(type_len == 0x8100) {
    /* VLAN  - next two bytes */
    u_int32_t vlanData = (ptr[0] << 8) + ptr[1];
    u_int32_t vlan = vlanData & 0x0fff;
    u_int32_t priority = vlanData >> 13;
    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "decodedVLAN %lu\n", (long unsigned int)vlan);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "decodedPriority %lu\n", (long unsigned int)priority);
    /* now get the type_len again (next two bytes) */
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;
  }

  /* now we're just looking for IP */
  if(sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */

  /* peek for IPX */
  if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
    int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
    int ipxLen = (ptr[2] << 8) + ptr[3];
    if(ipxChecksum &&
       ipxLen >= IPX_HDR_LEN &&
       ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
      /* we don't do anything with IPX here */
      return;
  }

  if(type_len <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
      }
      else return;
    }
  }

  /* assume type_len is an ethernet-type now */

  if(type_len == 0x0800) {
    /* IPV4 */
    if((end - ptr) < sizeof(struct myiphdr)) return;
    /* look at first byte of header.... */
    /*  ___________________________ */
    /* |   version   |    hdrlen   | */
    /*  --------------------------- */
    if((*ptr >> 4) != 4) return; /* not version 4 */
    if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
    /* survived all the tests - store the offset to the start of the ip header */
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = (ptr - start);
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample, int deviceId)
{
  if(sample->gotIPV4) {
    char buf[51];
    u_char *ptr = sample->header + sample->offsetToIPV4;
    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct myiphdr ip;
    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->dcd_srcIP.s_addr = ip.saddr;
    sample->dcd_dstIP.s_addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ip.tot_len = %d\n", ntohs(ip.tot_len));
    /* Log out the decoded IP fields */
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPProtocol %u\n", sample->dcd_ipProtocol);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPTOS %u\n", sample->dcd_ipTos);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPTTL %u\n", sample->dcd_ipTTL);
    /* check for fragments */
    sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if(sample->ip_fragmentOffset > 0) {
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPFragmentOffset %u\n", sample->ip_fragmentOffset);
    }
    else {
      /* advance the pointer to the next protocol layer */
      /* ip headerLen is expressed as a number of quads */
      ptr += (ip.version_and_headerLen & 0x0f) * 4;

      switch(ip.protocol) {
      case 1: /* ICMP */
	{
	  struct myicmphdr icmp;
	  memcpy(&icmp, ptr, sizeof(icmp));
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ICMPType %u\n", icmp.type);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ICMPCode %u\n", icmp.code);
	}
	break;
      case 6: /* TCP */
	{
	  struct mytcphdr tcp;
	  memcpy(&tcp, ptr, sizeof(tcp));
	  sample->dcd_sport = ntohs(tcp.th_sport);
	  sample->dcd_dport = ntohs(tcp.th_dport);
	  sample->dcd_tcpFlags = tcp.th_flags;
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPSrcPort %u\n", sample->dcd_sport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPDstPort %u\n",sample->dcd_dport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPFlags %u\n", sample->dcd_tcpFlags);
	  if(sample->dcd_dport == 80) {
	    int bytesLeft;
	    int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	    ptr += headerBytes;
	    bytesLeft = sample->header + sample->headerLen - ptr;
	  }
	}
	break;
      case 17: /* UDP */
	{
	  struct myudphdr udp;
	  memcpy(&udp, ptr, sizeof(udp));
	  sample->dcd_sport = ntohs(udp.uh_sport);
	  sample->dcd_dport = ntohs(udp.uh_dport);
	  sample->udp_pduLen = ntohs(udp.uh_ulen);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "UDPSrcPort %u\n", sample->dcd_sport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "UDPDstPort %u\n", sample->dcd_dport);
	  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "UDPBytes %u\n", sample->udp_pduLen);
	}
	break;
      default: /* some other protcol */
	break;
      }
    }
  }
}

#if 0
/*_________________---------------------------__________________
  _________________      in_checksum          __________________
  -----------------___________________________------------------
*/
static u_int16_t in_checksum(u_int16_t *addr, int len)
{
  int nleft = len;
  u_short *w = addr;
  u_short answer;
  int sum = 0;

  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) sum += *(u_char *)w;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

#endif

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

static u_int32_t getData32(SFSample *sample, int deviceId) {
  u_int32_t *val;

  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);
  val = (u_int32_t*)sample->datap;
  skipBytes(sample, 4);

  return ntohl(*val);
}

static u_int32_t getData32_nobswap(SFSample *sample, int deviceId) {
  u_int32_t *val;

  if((u_char *)sample->datap > sample->endp) SFABORT(sample, SF_ABORT_EOS);

  val = (u_int32_t*)sample->datap;
  skipBytes(sample, 4);

  return *val;
}

static u_int64_t getData64(SFSample *sample, int deviceId) {
  u_int64_t tmpLo, tmpHi;
  tmpHi = getData32(sample, deviceId);
  tmpLo = getData32(sample, deviceId);
  return (tmpHi << 32) + tmpLo;
}

static u_int32_t sf_log_next32(SFSample *sample, char *fieldName, int deviceId) {
  u_int32_t val = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%s %lu\n", fieldName, (long unsigned int)val);
  return(val);
}

static u_int64_t sf_log_next64(SFSample *sample, char *fieldName, int deviceId) {
  u_int64_t val = getData64(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%s %llu\n", fieldName, (long long unsigned int)val);
  return(val);
}

static u_int32_t getString(SFSample *sample, char *buf, int bufLen, int deviceId) {
  u_int32_t len, read_len;
  len = getData32(sample, deviceId);
  // truncate if too long
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, sample->datap, read_len);
  buf[read_len] = '\0';   // null terminate
  skipBytes(sample, len);
  return len;
}

static u_int32_t getAddress(SFSample *sample, SFLAddress *address, int deviceId) {
  address->type = getData32(sample, deviceId);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.s_addr = getData32_nobswap(sample, deviceId);
#ifdef INET6
  else {
    memcpy(&address->address.ip_v6.s6_addr, sample->datap, 16);
    skipBytes(sample, 16);
  }
#endif
  return address->type;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen, int deviceId) {
  if(address->type == SFLADDRESSTYPE_IP_V4)
    IP_to_a(address->address.ip_v4.s_addr, buf);
#ifdef INET6
  else {
    u_char *b = address->address.ip_v6.s6_addr;
    // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
    sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
  }
#endif
  return buf;
}

static char *printTag(u_int32_t tag, char *buf, int bufLen, int deviceId) {
  // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
  sprintf(buf, "%lu:%lu", (long unsigned int)(tag >> 12), (long unsigned int)(tag & 0x00000FFF));
  return buf;
}

static u_int32_t skipTLVRecord(SFSample *sample, u_int32_t tag, char *description, int deviceId) {
  char buf[51];
  u_int32_t len;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "skipping unknown %s: %s\n", description, printTag(tag, buf, 50, deviceId));
  len = getData32(sample, deviceId);
  // sanity check
  if(len > sample->rawSampleLen) SFABORT(sample, SF_ABORT_EOS);
  else skipBytes(sample, len);
  return len;
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType SWITCH\n");
  sample->in_vlan = getData32(sample, deviceId);
  sample->in_priority = getData32(sample, deviceId);
  sample->out_vlan = getData32(sample, deviceId);
  sample->out_priority = getData32(sample, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "in_vlan %lu\n", (long unsigned int)sample->in_vlan);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "in_priority %lu\n", (long unsigned int)sample->in_priority);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "out_vlan %lu\n", (long unsigned int)sample->out_vlan);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "out_priority %lu\n", (long unsigned int)sample->out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType ROUTER\n");
  getAddress(sample, &sample->nextHop, deviceId);
  sample->srcMask = getData32(sample, deviceId);
  sample->dstMask = getData32(sample, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "nextHop %s\n",
				       printAddress(&sample->nextHop, buf, 50, deviceId));
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "srcSubnetMask %lu\n", (long unsigned int)sample->srcMask);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dstSubnetMask %lu\n", (long unsigned int)sample->dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType GATEWAY\n");

  sample->my_as = getData32(sample, deviceId);
  sample->src_as = getData32(sample, deviceId);
  sample->src_peer_as = getData32(sample, deviceId);
  sample->dst_as_path_len = getData32(sample, deviceId);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    sample->dst_as_path = (u_int32_t*)sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    // fill in the dst and dst_peer fields too
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "my_as %lu\n",
				       (long unsigned int)sample->my_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_as %lu\n",
				       (long unsigned int)sample->src_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_peer_as %lu\n",
				       (long unsigned int)sample->src_peer_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_as %lu\n",
				       (long unsigned int)sample->dst_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_peer_as %lu\n",
				       (long unsigned int)sample->dst_peer_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_as_path_len %lu\n",
				       (long unsigned int)sample->dst_as_path_len);

  if(sample->dst_as_path_len > 0) {
    u_int32_t i = 0;
    for(; i < sample->dst_as_path_len; i++) {
      if(i == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_as_path "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "-");
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%lu", (long unsigned int)ntohl(sample->dst_as_path[i]));
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "\n");
  }
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample, int deviceId)
{
  u_int32_t segments;
  int seg;
  char buf[51];

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType GATEWAY\n");

  if(sample->datagramVersion >= 5) {
    getAddress(sample, &sample->bgp_nextHop, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "bgp_nexthop %s\n",
					 printAddress(&sample->bgp_nextHop, buf, 50, deviceId));
  }

  sample->my_as = getData32(sample, deviceId);
  sample->src_as = getData32(sample, deviceId);
  sample->src_peer_as = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "my_as %lu\n", (long unsigned int)sample->my_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_as %lu\n", (long unsigned int)sample->src_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_peer_as %lu\n", (long unsigned int)sample->src_peer_as);
  segments = getData32(sample, deviceId);
  if(segments > 0) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_as_path ");
    for(seg = 0; seg < segments; seg++) {
      u_int32_t seg_type;
      u_int32_t seg_len;
      int i;
      seg_type = getData32(sample, deviceId);
      seg_len = getData32(sample, deviceId);
      for(i = 0; i < seg_len; i++) {
	u_int32_t asNumber;
	asNumber = getData32(sample, deviceId);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "(");
	if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%lu", (long unsigned int)asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
      }
      if(seg_type == SFLEXTENDED_AS_SET) if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, ")");
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "\n");
  }
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_as %lu\n", (long unsigned int)sample->dst_as);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_peer_as %lu\n", (long unsigned int)sample->dst_peer_as);

  sample->communities_len = getData32(sample, deviceId);
  /* just point at the communities array */
  if(sample->communities_len > 0) sample->communities = (u_int32_t*)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->communities_len * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  if(sample->communities_len > 0) {
    int j = 0;
    for(; j < sample->communities_len; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "BGP_communities "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "-");
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%lu", (long unsigned int)ntohl(sample->communities[j]));
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "\n");
  }

  sample->localpref = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "BGP_localpref %lu\n", (long unsigned int)sample->localpref);

}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType USER\n");

  if(sample->datagramVersion >= 5) {
    sample->src_user_charset = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_user_charset %d\n", sample->src_user_charset);
  }

  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN, deviceId);

  if(sample->datagramVersion >= 5) {
    sample->dst_user_charset = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_user_charset %d\n", sample->dst_user_charset);
  }

  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN, deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "src_user %s\n", sample->src_user);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType URL\n");

  sample->url_direction = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "url_direction %lu\n", (long unsigned int)sample->url_direction);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "url %s\n", sample->url);
  if(sample->datagramVersion >= 5) {
    sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "host %s\n", sample->host);
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName, int deviceId)
{
  SFLLabelStack lstk;
  u_int32_t lab;
  lstk.depth = getData32(sample, deviceId);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    int j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%s ", fieldName); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "-");
      lab = ntohl(lstk.stack[j]);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "%lu.%lu.%lu.%lu",
					   (long unsigned int)(lab >> 12),     // label
					   (long unsigned int)(lab >> 9) & 7,  // experimental
					   (long unsigned int)(lab >> 8) & 1,  // bottom of stack
					   (long unsigned int)(lab &  255));   // TTL
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "\n");
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType MPLS\n");
  getAddress(sample, &sample->mpls_nextHop, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50, deviceId));

  mplsLabelStack(sample, "mpls_input_stack", deviceId);
  mplsLabelStack(sample, "mpls_output_stack", deviceId);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample, int deviceId)
{
  char buf[51];
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "extendedType NAT\n");
  getAddress(sample, &sample->nat_src, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "nat_src %s\n", printAddress(&sample->nat_src, buf, 50, deviceId));
  getAddress(sample, &sample->nat_dst, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50, deviceId));
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample, int deviceId)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  u_int32_t tunnel_id, tunnel_cos;

  if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_tunnel_lsp_name %s\n", tunnel_name);
  tunnel_id = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_tunnel_id %lu\n", (long unsigned int)tunnel_id);
  tunnel_cos = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_tunnel_cos %lu\n", (long unsigned int)tunnel_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample, int deviceId)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];
  u_int32_t vll_vc_id, vc_cos;
  if(getString(sample, vc_name, SA_MAX_VCNAME_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_vc_name %s\n", vc_name);
  vll_vc_id = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_vll_vc_id %lu\n", (long unsigned int)vll_vc_id);
  vc_cos = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_vc_cos %lu\n", (long unsigned int)vc_cos);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample, int deviceId)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];
  u_int32_t ftn_mask;
  if(getString(sample, ftn_descr, SA_MAX_FTN_LEN, deviceId) > 0)
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_ftn_descr %s\n", ftn_descr);
  ftn_mask = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_ftn_mask %lu\n", (long unsigned int)ftn_mask);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample, int deviceId)
{
  u_int32_t fec_addr_prefix_len = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "mpls_fec_addr_prefix_len %lu\n",
				       (long unsigned int)fec_addr_prefix_len);
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample, int deviceId)
{
  u_int32_t lab;
  SFLLabelStack lstk;
  lstk.depth = getData32(sample, deviceId);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  if(lstk.depth > 0) {
    int j = 0;
    for(; j < lstk.depth; j++) {
      if(j == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "vlan_tunnel "); }
      else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "-");
      lab = ntohl(lstk.stack[j]);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "0x%04x.%lu.%lu.%lu",
					   (lab >> 16),       // TPI
					   (long unsigned int)(lab >> 13) & 7,   // priority
					   (long unsigned int)(lab >> 12) & 1,   // CFI
					   (long unsigned int)(lab & 4095));     // VLAN
    }
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "\n");
  }
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample, int deviceId)
{
  uint toSkip;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "flowSampleType HEADER\n");
  sample->headerProtocol = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "headerProtocol %lu\n", (long unsigned int)sample->headerProtocol);
  sample->sampledPacketSize = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
  if(sample->datagramVersion > 4) {
    // stripped count introduced in sFlow version 5
    sample->stripped = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "strippedBytes %lu\n", (long unsigned int)sample->stripped);
  }
  sample->headerLen = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "headerLen %lu\n", (long unsigned int)sample->headerLen);

  sample->header = (u_char *)sample->datap; /* just point at the header */

  toSkip = ((sample->headerLen + 3) / 4) * 4; /* L.Deri */
  skipBytes(sample, toSkip);
  {
    char scratch[2000];
    printHex(sample->header, sample->headerLen, (u_char*)scratch, 2000, 0, 2000);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "headerBytes %s\n", scratch);
  }

  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample, deviceId);
    break;
  case SFLHEADER_IPv4:
    sample->gotIPV4 = YES;
    sample->offsetToIPV4 = 0;
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_PPP:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  case SFLHEADER_IPv6:
  case SFLHEADER_MPLS:
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
    break;
  default:
    fprintf(stderr, "undefined headerProtocol = %d\n", sample->headerProtocol);
    exit(-12);
  }

  if(sample->gotIPV4) {
    // report the size of the original IPPdu (including the IP header)
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
    decodeIPV4(sample, deviceId);
  }
}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, int deviceId)
{
  char *p;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "flowSampleType ETHERNET\n");
  sample->eth_len = getData32(sample, deviceId);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ethernet_type %lu\n", (long unsigned int)sample->eth_type);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ethernet_len %lu\n", (long unsigned int)sample->eth_len);
  p = (char*)sample->eth_src;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
  p = (char*)sample->eth_dst;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "flowSampleType IPV4\n");
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (u_char *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    char buf[51];
    SFLSampled_ipv4 nfKey;
    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPSize %d\n",  sample->sampledPacketSize);
    sample->dcd_srcIP = nfKey.src_ip;
    sample->dcd_dstIP = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf));
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPProtocol %u\n", sample->dcd_ipProtocol);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "IPTOS %u\n", sample->dcd_ipTos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
    switch(sample->dcd_ipProtocol) {
    case 1: /* ICMP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "ICMPType %u\n", sample->dcd_dport);
      /* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
      break;
    case 6: /* TCP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPSrcPort %u\n", sample->dcd_sport);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPDstPort %u\n", sample->dcd_dport);
      sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "TCPFlags %u\n", sample->dcd_tcpFlags);
      break;
    case 17: /* UDP */
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "UDPSrcPort %u\n", sample->dcd_sport);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "UDPDstPort %u\n", sample->dcd_dport);
      break;
    default: /* some other protcol */
      break;
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

#ifdef INET6
static void readFlowSample_IPv6(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "flowSampleType IPV6\n");
  sample->header = (u_char *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);
  {
    SFLSampled_ipv6 nfKey6;
    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampledPacketSize %lu\n", (long unsigned int)sample->sampledPacketSize);
  }
  /* bug: more decode to do here */
}
#endif

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleType FLOWSAMPLE\n");

  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
    if(SFLOW_DEBUG(deviceId))
      traceEvent(TRACE_INFO, "sourceId %lu:%lu\n",
		 (long unsigned int)sample->ds_class,
		 (long unsigned int)sample->ds_index);
  }

  sample->meanSkipCount = getData32(sample, deviceId);
  sample->samplePool = getData32(sample, deviceId);
  sample->dropEvents = getData32(sample, deviceId);
  sample->inputPort = getData32(sample, deviceId);
  sample->outputPort = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "meanSkipCount %lu\n", (long unsigned int)sample->meanSkipCount);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "samplePool %lu\n", (long unsigned int)sample->samplePool);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dropEvents %lu\n", (long unsigned int)sample->dropEvents);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "inputPort %lu\n", (long unsigned int)sample->inputPort);
  if(sample->outputPort & 0x80000000) {
    u_int32_t numOutputs = sample->outputPort & 0x7fffffff;
    if(numOutputs > 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort multiple %d\n", numOutputs); }
    else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort multiple >1\n");
  }
  else if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort %lu\n", (long unsigned int)sample->outputPort);

  sample->packet_data_tag = getData32(sample, deviceId);

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "packet_data_tag=%d",  sample->packet_data_tag);
  switch(sample->packet_data_tag) {
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample, deviceId); break;
  case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample, deviceId); break;
#ifdef INET6
  case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample, deviceId); break;
#endif
  default: receiveError(sample, "unexpected packet_data_tag", YES); break;
  }

  sample->extended_data_tag = 0;
  {
    u_int32_t x;
    sample->num_extended = getData32(sample, deviceId);
    for(x = 0; x < sample->num_extended; x++) {
      u_int32_t extended_tag;
      extended_tag = getData32(sample, deviceId);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample, deviceId); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample, deviceId); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample, deviceId);
	else readExtendedGateway(sample, deviceId);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample, deviceId); break;
      case INMEXTENDED_URL: readExtendedUrl(sample, deviceId); break;
      default: receiveError(sample, "unrecognized extended data tag", YES); break;
      }
    }
  }
}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded, int deviceId)
{
  u_int32_t num_elements, sampleLength;
  u_char *sampleStart;

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleType FLOWSAMPLE\n");
  sampleLength = getData32(sample, deviceId);
  sampleStart = (u_char *)sample->datap;
  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample, deviceId);
    sample->ds_index = getData32(sample, deviceId);
  }
  else {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  if(SFLOW_DEBUG(deviceId))
    traceEvent(TRACE_INFO, "sourceId %lu:%lu\n",
	       (long unsigned int)sample->ds_class,
	       (long unsigned int)sample->ds_index);

  sample->meanSkipCount = getData32(sample, deviceId);
  sample->samplePool = getData32(sample, deviceId);
  sample->dropEvents = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "meanSkipCount %lu\n", (long unsigned int)sample->meanSkipCount);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "samplePool %lu\n", (long unsigned int)sample->samplePool);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "dropEvents %lu\n", (long unsigned int)sample->dropEvents);
  if(expanded) {
    sample->inputPortFormat = getData32(sample, deviceId);
    sample->inputPort = getData32(sample, deviceId);
    sample->outputPortFormat = getData32(sample, deviceId);
    sample->outputPort = getData32(sample, deviceId);
  }
  else {
    u_int32_t inp, outp;
    inp = getData32(sample, deviceId);
    outp = getData32(sample, deviceId);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp & 0x3fffffff;
    sample->outputPort = outp & 0x3fffffff;
  }
  if(sample->inputPortFormat == 3) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "inputPort format==3 %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 2) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "inputPort multiple %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 1) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "inputPort dropCode %lu\n", (long unsigned int)sample->inputPort); }
  else if(sample->inputPortFormat == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "inputPort %lu\n", (long unsigned int)sample->inputPort); }
  if(sample->outputPortFormat == 3) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort format==3 %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 2) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort multiple %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 1) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort dropCode %lu\n", (long unsigned int)sample->outputPort); }
  else if(sample->outputPortFormat == 0) { if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "outputPort %lu\n", (long unsigned int)sample->outputPort); }

  num_elements = getData32(sample, deviceId);
  {
    int el;
    for(el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      u_char *start;
      char buf[51];
      tag = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "flowBlock_tag %s\n", printTag(tag, buf, 50, deviceId));
      length = getData32(sample, deviceId);
      start = (u_char *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample, deviceId); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample, deviceId); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample, deviceId); break;
#ifdef INET6
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample, deviceId); break;
#endif
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample, deviceId); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample, deviceId); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample, deviceId); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample, deviceId); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample, deviceId); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample, deviceId); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample, deviceId); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample, deviceId); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample, deviceId); break;
      default: skipTLVRecord(sample, tag, "flow_sample_element", deviceId); break;
      }
      lengthCheck(sample, "flow_sample_element", start, length);
    }
  }

  lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
}

/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample, int deviceId)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex", deviceId);
  sample->ifCounters.ifType = sf_log_next32(sample, "networkType", deviceId);
  sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed", deviceId);
  sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection", deviceId);
  sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus", deviceId);
  /* the generic counters always come first */
  sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets", deviceId);
  sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts", deviceId);
  sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts", deviceId);
  sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts", deviceId);
  sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards", deviceId);
  sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors", deviceId);
  sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos", deviceId);
  sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets", deviceId);
  sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts", deviceId);
  sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts", deviceId);
  sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts", deviceId);
  sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards", deviceId);
  sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors", deviceId);
  sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode", deviceId);
}

/*_________________---------------------------__________________
  _________________  readCounters_ethernet    __________________
  -----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot3StatsAlignmentErrors", deviceId);
  sf_log_next32(sample, "dot3StatsFCSErrors", deviceId);
  sf_log_next32(sample, "dot3StatsSingleCollisionFrames", deviceId);
  sf_log_next32(sample, "dot3StatsMultipleCollisionFrames", deviceId);
  sf_log_next32(sample, "dot3StatsSQETestErrors", deviceId);
  sf_log_next32(sample, "dot3StatsDeferredTransmissions", deviceId);
  sf_log_next32(sample, "dot3StatsLateCollisions", deviceId);
  sf_log_next32(sample, "dot3StatsExcessiveCollisions", deviceId);
  sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors", deviceId);
  sf_log_next32(sample, "dot3StatsCarrierSenseErrors", deviceId);
  sf_log_next32(sample, "dot3StatsFrameTooLongs", deviceId);
  sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors", deviceId);
  sf_log_next32(sample, "dot3StatsSymbolErrors", deviceId);
}


/*_________________---------------------------__________________
  _________________  readCounters_tokenring   __________________
  -----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot5StatsLineErrors", deviceId);
  sf_log_next32(sample, "dot5StatsBurstErrors", deviceId);
  sf_log_next32(sample, "dot5StatsACErrors", deviceId);
  sf_log_next32(sample, "dot5StatsAbortTransErrors", deviceId);
  sf_log_next32(sample, "dot5StatsInternalErrors", deviceId);
  sf_log_next32(sample, "dot5StatsLostFrameErrors", deviceId);
  sf_log_next32(sample, "dot5StatsReceiveCongestions", deviceId);
  sf_log_next32(sample, "dot5StatsFrameCopiedErrors", deviceId);
  sf_log_next32(sample, "dot5StatsTokenErrors", deviceId);
  sf_log_next32(sample, "dot5StatsSoftErrors", deviceId);
  sf_log_next32(sample, "dot5StatsHardErrors", deviceId);
  sf_log_next32(sample, "dot5StatsSignalLoss", deviceId);
  sf_log_next32(sample, "dot5StatsTransmitBeacons", deviceId);
  sf_log_next32(sample, "dot5StatsRecoverys", deviceId);
  sf_log_next32(sample, "dot5StatsLobeWires", deviceId);
  sf_log_next32(sample, "dot5StatsRemoves", deviceId);
  sf_log_next32(sample, "dot5StatsSingles", deviceId);
  sf_log_next32(sample, "dot5StatsFreqErrors", deviceId);
}


/*_________________---------------------------__________________
  _________________  readCounters_vg          __________________
  -----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample, int deviceId)
{
  sf_log_next32(sample, "dot12InHighPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12InHighPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12InNormPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12InNormPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12InIPMErrors", deviceId);
  sf_log_next32(sample, "dot12InOversizeFrameErrors", deviceId);
  sf_log_next32(sample, "dot12InDataErrors", deviceId);
  sf_log_next32(sample, "dot12InNullAddressedFrames", deviceId);
  sf_log_next32(sample, "dot12OutHighPriorityFrames", deviceId);
  sf_log_next64(sample, "dot12OutHighPriorityOctets", deviceId);
  sf_log_next32(sample, "dot12TransitionIntoTrainings", deviceId);
  sf_log_next64(sample, "dot12HCInHighPriorityOctets", deviceId);
  sf_log_next64(sample, "dot12HCInNormPriorityOctets", deviceId);
  sf_log_next64(sample, "dot12HCOutHighPriorityOctets", deviceId);
}



/*_________________---------------------------__________________
  _________________  readCounters_vlan        __________________
  -----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample, int deviceId)
{
  sample->in_vlan = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "in_vlan %lu\n", (long unsigned int)sample->in_vlan);
  sf_log_next64(sample, "octets", deviceId);
  sf_log_next32(sample, "ucastPkts", deviceId);
  sf_log_next32(sample, "multicastPkts", deviceId);
  sf_log_next32(sample, "broadcastPkts", deviceId);
  sf_log_next32(sample, "discards", deviceId);
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample, int deviceId)
{
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleType COUNTERSSAMPLE\n");
  sample->samplesGenerated = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sourceId %lu:%lu\n", (long unsigned int)sample->ds_class, (long unsigned int)sample->ds_index);


  sample->statsSamplingInterval = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "statsSamplingInterval %lu\n", (long unsigned int)sample->statsSamplingInterval);
  /* now find out what sort of counter blocks we have here... */
  sample->counterBlockVersion = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "counterBlockVersion %lu\n", (long unsigned int)sample->counterBlockVersion);

  /* first see if we should read the generic stats */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: readCounters_generic(sample, deviceId); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: receiveError(sample, "unknown stats version", YES); break;
  }

  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample, deviceId); break;
  case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample, deviceId); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: readCounters_vg(sample, deviceId); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample, deviceId); break;
  default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
  }
}

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded, int deviceId)
{
  u_int32_t sampleLength;
  u_int32_t num_elements;
  char *sampleStart;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleType COUNTERSSAMPLE\n");
  sampleLength = getData32(sample, deviceId);
  sampleStart = (char *)sample->datap;
  sample->samplesGenerated = getData32(sample, deviceId);

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleSequenceNo %lu\n", (long unsigned int)sample->samplesGenerated);
  if(expanded) {
    sample->ds_class = getData32(sample, deviceId);
    sample->ds_index = getData32(sample, deviceId);
  }
  else {
    u_int32_t samplerId = getData32(sample, deviceId);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sourceId %lu:%lu\n", (long unsigned int)sample->ds_class, (long unsigned int)sample->ds_index);

  num_elements = getData32(sample, deviceId);
  {
    int el;
    for(el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      char *start;
      char buf[51];
      tag = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "counterBlock_tag %s\n", printTag(tag, buf, 50, deviceId));
      length = getData32(sample, deviceId);
      start = (char *)sample->datap;

      switch(tag) {
      case SFLCOUNTERS_GENERIC: readCounters_generic(sample, deviceId); break;
      case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample, deviceId); break;
      case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample, deviceId); break;
      case SFLCOUNTERS_VG: readCounters_vg(sample, deviceId); break;
      case SFLCOUNTERS_VLAN: readCounters_vlan(sample, deviceId); break;
      default: skipTLVRecord(sample, tag, "counters_sample_element", deviceId); break;
      }

      lengthCheck(sample, "counters_sample_element", (u_char*)start, length);
    }
  }

  lengthCheck(sample, "counters_sample", (u_char*)sampleStart, sampleLength);
}

/*_________________---------------------------__________________
  _________________      readSFlowDatagram    __________________
  -----------------___________________________------------------
*/

static void readSFlowDatagram(SFSample *sample, int deviceId)
{
  u_int32_t samplesInPacket;
  struct timeval now;
  char buf[51];

  /* log some datagram info */
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "datagramSourceIP %s\n", IP_to_a(sample->sourceIP.s_addr, buf));
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "datagramSize %lu\n", (long unsigned int)sample->rawSampleLen);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "unixSecondsUTC %lu\n", now.tv_sec);

  /* check the version */
  sample->datagramVersion = getData32(sample, deviceId);

  switch(sample->datagramVersion) {
  case 2:
    numsFlowsV2Rcvd++;
    break;
  case 4:
    numsFlowsV4Rcvd++;
    break;
  case 5:
    numsFlowsV5Rcvd++;
    break;
  default:
    numBadsFlowsVersionsRcvd++;
    break;
  }

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "datagramVersion %d\n", sample->datagramVersion);
  if(sample->datagramVersion != 2 &&
     sample->datagramVersion != 4 &&
     sample->datagramVersion != 5) {
    receiveError(sample,  "unexpected datagram version number\n", YES);
  }

  /* get the agent address */
  getAddress(sample, &sample->agent_addr, deviceId);

  /* version 5 has an agent sub-id as well */
  if(sample->datagramVersion >= 5) {
    sample->agentSubId = getData32(sample, deviceId);
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "agentSubId %lu\n", (long unsigned int)sample->agentSubId);
  }

  sample->sequenceNo = getData32(sample, deviceId);  /* this is the packet sequence number */
  sample->sysUpTime = getData32(sample, deviceId);
  samplesInPacket = getData32(sample, deviceId);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "agent %s\n", printAddress(&sample->agent_addr, buf, 50, deviceId));
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "packetSequenceNo %lu\n", (long unsigned int)sample->sequenceNo);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sysUpTime %lu\n", (long unsigned int)sample->sysUpTime);
  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "samplesInPacket %lu\n", (long unsigned int)samplesInPacket);

  /* now iterate and pull out the flows and counters samples */
  {
    u_int32_t samp = 0;

    for(; samp < samplesInPacket; samp++) {
      // just read the tag, then call the approriate decode fn
      sample->sampleType = getData32(sample, deviceId);
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "startSample ----------------------\n");
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_INFO, "sampleType_tag %s\n", printTag(sample->sampleType, buf, 50, deviceId));
      if(sample->datagramVersion >= 5) {
	switch(sample->sampleType) {
	case SFLFLOW_SAMPLE: readFlowSample(sample, NO, deviceId); break;
	case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO, deviceId); break;
	case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES, deviceId); break;
	case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES, deviceId); break;
	default: skipTLVRecord(sample, sample->sampleType, "sample", deviceId); break;
	}
      } else {
	switch(sample->sampleType) {
	case FLOWSAMPLE: readFlowSample_v2v4(sample, deviceId); break;
	case COUNTERSSAMPLE: readCountersSample_v2v4(sample, deviceId); break;
	default: receiveError(sample, "unexpected sample type", YES); break;
	}
      }

      if(SFLOW_DEBUG(deviceId))
	traceEvent(TRACE_INFO, "endSample [%d]  ----------------------\n", sample->sampleType);

      // traceEvent(TRACE_INFO, "endSample [%d]  ----------------------\n", sample->sampleType);

      if((sample->sampleType == SFLFLOW_SAMPLE)
	 || (sample->sampleType == SFLFLOW_SAMPLE_EXPANDED)) {
	handleSflowSample(sample, deviceId);
      }
    }
  }
}


/* =============================================================== */

/* ****************************** */

#ifdef MAKE_WITH_SFLOWSIGTRAP
RETSIGTYPE sflowcleanup(int signo) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  if(msgSent<10) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_FATALERROR, "SFLOW: caught signal %d %s", signo,
					 signo == SIGHUP ? "SIGHUP" :
					 signo == SIGINT ? "SIGINT" :
					 signo == SIGQUIT ? "SIGQUIT" :
					 signo == SIGILL ? "SIGILL" :
					 signo == SIGABRT ? "SIGABRT" :
					 signo == SIGFPE ? "SIGFPE" :
					 signo == SIGKILL ? "SIGKILL" :
					 signo == SIGSEGV ? "SIGSEGV" :
					 signo == SIGPIPE ? "SIGPIPE" :
					 signo == SIGALRM ? "SIGALRM" :
					 signo == SIGTERM ? "SIGTERM" :
					 signo == SIGUSR1 ? "SIGUSR1" :
					 signo == SIGUSR2 ? "SIGUSR2" :
					 signo == SIGCHLD ? "SIGCHLD" :
#ifdef SIGCONT
					 signo == SIGCONT ? "SIGCONT" :
#endif
#ifdef SIGSTOP
					 signo == SIGSTOP ? "SIGSTOP" :
#endif
#ifdef SIGBUS
					 signo == SIGBUS ? "SIGBUS" :
#endif
#ifdef SIGSYS
					 signo == SIGSYS ? "SIGSYS"
#endif
					 : "other");
    msgSent++;
  }

#ifdef HAVE_BACKTRACE
  /* Don't double fault... */
  /* signal(signo, SIG_DFL); */

  /* Grab the backtrace before we do much else... */
  size = backtrace(array, 20);
  strings = (char**)backtrace_symbols(array, size);

  if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_ERROR, "SFLOW: BACKTRACE:     backtrace is:");
  if (size < 2) {
    if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_ERROR, "SFLOW: BACKTRACE:         **unavailable!");
  } else {
    /* Ignore the 0th entry, that's our cleanup() */
    for (i=1; i<size; i++) {
      if(SFLOW_DEBUG(deviceId)) traceEvent(TRACE_ERROR, "SFLOW: BACKTRACE:          %2d. %s", i, strings[i]);
    }
  }
#endif /* HAVE_BACKTRACE */

  traceEvent(TRACE_FATALERROR, "SFLOW: ntop shutting down...");
  exit(102);
}
#endif /* MAKE_WITH_SFLOWSIGTRAP */

/* ****************************************** */

void dissectSflow(u_char *buffer, uint buffer_len, struct sockaddr_in *fromHost) {
  SFSample sample;

  memset(&sample, 0, sizeof(sample));
  sample.rawSample = buffer;
  sample.rawSampleLen = buffer_len;
  sample.sourceIP = fromHost->sin_addr;
  sample.datap = (u_char *)sample.rawSample;
  sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;

  readSFlowDatagram(&sample, 0 /* deviceId */);
}

