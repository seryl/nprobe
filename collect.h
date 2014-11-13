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

#define MAX_PACKET_LEN   256

struct generic_netflow_record {
  /* v5 */
  IpAddress srcaddr;    /* Source IP Address */
  IpAddress dstaddr;    /* Destination IP Address */
  IpAddress nexthop;    /* Next hop router's IP Address */
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
  u_int8_t  minTTL, maxTTL; /* IP Time-to-Live */
  u_int32_t dst_as;     /* dst peer/origin Autonomous System */
  u_int32_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */

  /* v9 */
  u_int16_t vlanId, icmpType;

  /*
    Collected info: if 0 it means they have not been
    set so we use the nprobe default (-E)
  */
  u_int8_t engine_type, engine_id;

  /* IPFIX */
  u_int32_t firstEpoch, lastEpoch;

  struct {
    /* Latency extensions */
    u_int32_t nw_latency_sec, nw_latency_usec;

    /* VoIP Extensions */
    char sip_call_id[50], sip_calling_party[50], sip_called_party[50];
  } ntop;

  struct {
    u_int8_t hasSampling;
    u_int16_t packet_len /* 103 */, original_packet_len /* 312/242 */, packet_offset /* 102 */;
    u_int32_t samplingPopulation /* 310 */, observationPointId /* 300 */;
    u_int16_t selectorId /* 302 */;
    u_char packet[MAX_PACKET_LEN] /* 104 */;

    /* Cisco NBAR 2 */
    u_int32_t nbar2_application_id /* NBAR - 95 */;
  } cisco;

  struct {
    u_int32_t l7_application_id /* 3054.110/35932 */;
    char l7_application_name[64] /* 3054.111/35933 */, /* NOT HANDLED */
      src_ip_country[4] /* 3054.120/35942 */,
      src_ip_city[64] /* 3054.125/35947 */,
      dst_ip_country[4] /* 3054.140/35962 */,
      dst_ip_city[64] /* 3054.145/35967 */,
      os_device_name[64] /* 3054.161/35983 */; /* NOT HANDLED */
  } ixia;
};

extern void handleCollectionFilter(char *filter);
extern void freeCollectionFilters();
