/*
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6
 *
 *       Copyright (C) 2002-11 Luca Deri <deri@ntop.org>
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

#ifdef HAVE_TEMPLATE_EXTENSIONS
#include "../nProbe-utils/extensions/templates.c"
#else
#ifdef HAVE_TEMPLATE_EXTENSIONS
#include "templates.c"
#endif
#endif

/* ********* NetFlow v9/IPFIX ***************************** */

/*
  Cisco Systems NetFlow Services Export Version 9

  http://www.faqs.org/rfcs/rfc3954.html

  IPFIX - Information Model for IP Flow Information Export
  http://www.faqs.org/rfcs/rfc5102.html

  See http://www.plixer.com/blog/tag/in_bytes/ for IN/OUT directions
*/

#define PROTO_NAME_LEN    16
#define CUSTOM_FIELD_LEN  16

/*
   IMPORTANT NOTE
   Whenever you add an element to the array below update printRecordWithTemplate() in util.c
*/
V9V10TemplateElementId ver9_templates[] = {
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IN_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_BYTES", "octetDeltaCount", "Incoming flow bytes (src->dst)" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, SYSTEM_ID,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SYSTEM_ID", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IN_PKTS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "IN_PKTS", "packetDeltaCount", "Incoming flow packets (src->dst)" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, INTERFACE_ID,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "INTERFACE_ID", "", "" }, /* Hack for options template */
  //  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   FLOWS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "FLOWS", "<reserved>", "Number of flows" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, LINE_CARD,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "LINE_CARD", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   PROTOCOL,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "PROTOCOL", "protocolIdentifier", "IP protocol byte" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   PROTOCOL_MAP, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, ascii_format, dump_as_ascii,  "PROTOCOL_MAP", "", "IP protocol name" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, NETFLOW_CACHE,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "NETFLOW_CACHE", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   SRC_TOS,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SRC_TOS", "ipClassOfService", "Type of service byte" },
  { 0, BOTH_IPV4_IPV6, OPTION_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, TEMPLATE_ID,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "TEMPLATE_ID", "", "" }, /* Hack for options template */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   TCP_FLAGS,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "TCP_FLAGS", "tcpControlBits", "Cumulative of all flow TCP flags" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_SRC_PORT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_SRC_PORT", "sourceTransportPort", "IPv4 source port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_SRC_PORT_MAP, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, ascii_format, dump_as_ascii,  "L4_SRC_PORT_MAP", "", "Layer 4 source port symbolic name" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV4_SRC_ADDR,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_SRC_ADDR", "sourceIPv4Address", "IPv4 source address" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV4_SRC_MASK,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV4_SRC_MASK", "sourceIPv4PrefixLength", "IPv4 source subnet mask (/<bits>)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   INPUT_SNMP,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "INPUT_SNMP", "ingressInterface", "Input interface SNMP idx" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_DST_PORT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_DST_PORT", "destinationTransportPort", "IPv4 destination port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_DST_PORT_MAP, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, ascii_format, dump_as_ascii,  "L4_DST_PORT_MAP", "", "Layer 4 destination port symbolic name" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_SRV_PORT, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "L4_SRV_PORT", "", "Layer 4 server port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   L4_SRV_PORT_MAP, STATIC_FIELD_LEN, CUSTOM_FIELD_LEN, ascii_format, dump_as_ascii,  "L4_SRV_PORT_MAP", "", "Layer 4 server port symbolic name" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV4_DST_ADDR,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_DST_ADDR", "destinationIPv4Address", "IPv4 destination address" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV4_DST_MASK,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV4_DST_MASK", "destinationIPv4PrefixLength", "IPv4 dest subnet mask (/<bits>)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   OUTPUT_SNMP,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "OUTPUT_SNMP", "egressInterface", "Output interface SNMP idx" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV4_NEXT_HOP,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "IPV4_NEXT_HOP", "ipNextHopIPv4Address", "IPv4 next hop address" },

  /* In earlier versions AS were 16 bit in 'modern' NetFlow v9 and later, they are 32 bit */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   SRC_AS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SRC_AS", "bgpSourceAsNumber", "Source BGP AS" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   DST_AS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "DST_AS", "bgpDestinationAsNumber", "Destination BGP AS" },
  /*
    { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   BGP_IPV4_NEXT_HOP,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "BGP_IPV4_NEXT_HOP", "bgpNexthopIPv4Address", "" },
    { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MUL_DST_PKTS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_PKTS", "postMCastPacketDeltaCount", "" },
    { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MUL_DST_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "MUL_DST_BYTES", "postMCastOctetDeltaCount", "" },
  */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   LAST_SWITCHED,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "LAST_SWITCHED", "flowEndSysUpTime", "SysUptime (msec) of the last flow pkt" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   FIRST_SWITCHED,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "FIRST_SWITCHED", "flowStartSysUpTime", "SysUptime (msec) of the first flow pkt" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   OUT_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_BYTES", "postOctetDeltaCount", "Outgoing flow bytes (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   OUT_PKTS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "OUT_PKTS", "postPacketDeltaCount", "Outgoing flow packets (dst->src)" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV6_SRC_ADDR,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_SRC_ADDR", "sourceIPv6Address", "IPv6 source address" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV6_DST_ADDR,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_DST_ADDR", "destinationIPv6Address", "IPv6 destination address" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV6_SRC_MASK,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_SRC_MASK", "sourceIPv6PrefixLength", "IPv6 source mask" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV6_DST_MASK,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IPV6_DST_MASK", "destinationIPv6PrefixLength", "IPv6 destination mask" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   ICMP_TYPE,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "ICMP_TYPE", "icmpTypeCodeIPv4", "ICMP Type * 256 + ICMP code" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   SAMPLING_INTERVAL,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SAMPLING_INTERVAL", "<reserved>", "Sampling rate" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   SAMPLING_ALGORITHM,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM", "<reserved>", "Sampling type (deterministic/random)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   FLOW_ACTIVE_TIMEOUT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_ACTIVE_TIMEOUT", "flowActiveTimeout", "Activity timeout of flow cache entries" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   FLOW_INACTIVE_TIMEOUT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FLOW_INACTIVE_TIMEOUT", "flowIdleTimeout", "Inactivity timeout of flow cache entries" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   ENGINE_TYPE,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_TYPE", "<reserved>", "Flow switching engine" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   ENGINE_ID,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "ENGINE_ID", "<reserved>", "Id of the flow switching engine" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   TOTAL_BYTES_EXP,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_BYTES_EXP", "exportedOctetTotalCount", "Total bytes exported" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   TOTAL_PKTS_EXP,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_PKTS_EXP", "exportedMessageTotalCount", "Total flow packets exported" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   TOTAL_FLOWS_EXP,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint,  "TOTAL_FLOWS_EXP", "exportedFlowRecordTotalCount", "Total number of exported flows" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MIN_TTL,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MIN_TTL", "minimumTTL", "Min flow TTL" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MAX_TTL,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "MAX_TTL", "maximumTTL", "Max flow TTL" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IN_SRC_MAC,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "IN_SRC_MAC", "sourceMacAddress", "Source MAC Address" }, 
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SRC_VLAN,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SRC_VLAN", "vlanId", "Source VLAN" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   DST_VLAN,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "DST_VLAN", "postVlanId", "Destination VLAN" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IP_PROTOCOL_VERSION,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "IP_PROTOCOL_VERSION", "ipVersion", "[4=IPv4][6=IPv6]" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   DIRECTION,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "DIRECTION", "flowDirection", "It indicates where a sample has been taken (always 0)" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   IPV6_NEXT_HOP,  STATIC_FIELD_LEN, 16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_NEXT_HOP", "ipNextHopIPv6Address", "IPv6 next hop address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_1,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_1", "mplsTopLabelStackSection", "MPLS label at position 1" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_2,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_2", "mplsLabelStackSection2", "MPLS label at position 2" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_3,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_3", "mplsLabelStackSection3", "MPLS label at position 3" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_4,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_4", "mplsLabelStackSection4", "MPLS label at position 4" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_5,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_5", "mplsLabelStackSection5", "MPLS label at position 5" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_6,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_6", "mplsLabelStackSection6", "MPLS label at position 6" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_7,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_7", "mplsLabelStackSection7", "MPLS label at position 7" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_8,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_8", "mplsLabelStackSection8", "MPLS label at position 8" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_9,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_9", "mplsLabelStackSection9", "MPLS label at position 9" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   MPLS_LABEL_10,  STATIC_FIELD_LEN, 3, numeric_format, dump_as_uint,  "MPLS_LABEL_10", "mplsLabelStackSection10", "MPLS label at position 10" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   OUT_DST_MAC,  STATIC_FIELD_LEN, 6, hex_format, dump_as_mac_address,  "OUT_DST_MAC", "destinationMacAddress", "Destination MAC Address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,   APPLICATION_ID,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPLICATION_ID",   "application_id", "Collected Application Id (Cisco or IXIA)" },

  /* Fields not yet fully supported (collection only) */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  PACKET_SECTION_OFFSET,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "PACKET_SECTION_OFFSET", "<reserved>", "Packet section offset" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SAMPLED_PACKET_SIZE,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_SIZE", "<reserved>", "Sampled packet size" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SAMPLED_PACKET_ID,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "SAMPLED_PACKET_ID",   "<reserved>", "Sampled packet id" },
  { 0, ONLY_IPV4, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  EXPORTER_IPV4_ADDRESS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "EXPORTER_IPV4_ADDRESS",   "exporterIPv4Address", "Exporter IPv4 Address" },
  { 0, ONLY_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  EXPORTER_IPV6_ADDRESS,  STATIC_FIELD_LEN, 16, numeric_format, dump_as_uint, "EXPORTER_IPV6_ADDRESS",   "exporterIPv6Address", "Exporter IPv6 Address" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FLOW_ID, STATIC_FIELD_LEN,  4, numeric_format, dump_as_uint, "FLOW_ID", "flowId", "Serial Flow Identifier" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FLOW_START_SEC, STATIC_FIELD_LEN,  4, numeric_format, dump_as_uint, "FLOW_START_SEC", "flowStartSeconds", "Seconds (epoch) of the first flow packet" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FLOW_END_SEC, STATIC_FIELD_LEN,  4, numeric_format, dump_as_uint, "FLOW_END_SEC",   "flowEndSeconds",   "Seconds (epoch) of the last flow packet" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FLOW_START_MILLISECONDS, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_START_MILLISECONDS", "flowStartMilliseconds", "Msec (epoch) of the first flow packet" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FLOW_END_MILLISECONDS, STATIC_FIELD_LEN,  8, numeric_format, dump_as_uint, "FLOW_END_MILLISECONDS",   "flowEndMilliseconds",   "Msec (epoch) of the last flow packet" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  BIFLOW_DIRECTION, STATIC_FIELD_LEN,  1, numeric_format, dump_as_uint, "BIFLOW_DIRECTION",   "biflow_direction",   "1=initiator, 2=reverseInitiator" },

  /* Fields not yet fully supported (collection only) */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  OBSERVATION_POINT_TYPE, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_TYPE", "<reserved>",  "Observation point type" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  OBSERVATION_POINT_ID, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "OBSERVATION_POINT_ID", "<reserved>",  "Observation point id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SELECTOR_ID, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_ID", "<reserved>",  "Selector id" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  IPFIX_SAMPLING_ALGORITHM, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "IPFIX_SAMPLING_ALGORITHM", "<reserved>",  "Sampling algorithm" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SAMPLING_SIZE, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_SIZE", "<reserved>",  "Number of packets to sample" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SAMPLING_POPULATION, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SAMPLING_POPULATION", "<reserved>", "Sampling population" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  FRAME_LENGTH, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "FRAME_LENGTH", "<reserved>", "Original L2 frame length" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  PACKETS_OBSERVED, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_OBSERVED", "<reserved>", "Tot number of packets seen" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  PACKETS_SELECTED, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "PACKETS_SELECTED", "<reserved>", "Number of pkts selected for sampling" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID,  SELECTOR_NAME, STATIC_FIELD_LEN,  2, numeric_format, dump_as_uint,  "SELECTOR_NAME", "<reserved>", "Sampler name" },

  /*
    ntop Extensions

    IMPORTANT
    if you change/add constants here/below make sure
    you change them into ntop too.
  */

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   FRAGMENTS,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "FRAGMENTS", "", "Number of fragmented flow packets" },
  /* 81 is available */
#ifdef DEPRECATED_INFORMATION_ELEMENTS
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   CLIENT_NW_DELAY_SEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_SEC", "",  "Network latency client <-> nprobe (sec) [deprecated]" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   CLIENT_NW_DELAY_USEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_USEC", "", "Network latency client <-> nprobe (residual usec) [deprecated]" },
#endif
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   CLIENT_NW_LATENCY_MS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CLIENT_NW_LATENCY_MS", "", "Network RTT/2 client <-> nprobe (msec)" },

#ifdef DEPRECATED_INFORMATION_ELEMENTS
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SERVER_NW_DELAY_SEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_SEC", "",  "Network latency nprobe <-> server (sec) [deprecated]" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SERVER_NW_DELAY_USEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_USEC", "", "Network latency nprobe <-> server (residual usec) [deprecated]" },
#endif
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SERVER_NW_LATENCY_MS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "SERVER_NW_LATENCY_MS", "", "Network RTT/2 nprobe <-> server (residual msec)" },

#ifdef DEPRECATED_INFORMATION_ELEMENTS
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   APPL_LATENCY_SEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_SEC", "", "Application latency (sec) [deprecated]" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   APPL_LATENCY_USEC,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_USEC", "", "Application latency (residual usec) [deprecated]" },
#endif
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   APPL_LATENCY_MS,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "APPL_LATENCY_MS", "", "Application latency (msec)" },


  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_UP_TO_128_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_UP_TO_128_BYTES", "", "# packets whose size <= 128" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_128_TO_256_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_128_TO_256_BYTES", "", "# packets whose size > 128 and <= 256" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_256_TO_512_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_256_TO_512_BYTES", "", "# packets whose size > 256 and < 512" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_512_TO_1024_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_512_TO_1024_BYTES", "", "# packets whose size > 512 and < 1024" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_1024_TO_1514_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_1024_TO_1514_BYTES", "", "# packets whose size > 1024 and <= 1514" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_OVER_1514_BYTES,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_OVER_1514_BYTES", "", "# packets whose size > 1514" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   CUMULATIVE_ICMP_TYPE,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "CUMULATIVE_ICMP_TYPE", "", "Cumulative OR of ICMP type packets" },
#ifdef HAVE_GEOIP
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SRC_IP_COUNTRY, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "SRC_IP_COUNTRY", "", "Country where the src IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SRC_IP_CITY, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "SRC_IP_CITY", "", "City where the src IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   DST_IP_COUNTRY, STATIC_FIELD_LEN, 2,  ascii_format, dump_as_ascii, "DST_IP_COUNTRY", "", "Country where the dst IP is located" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   DST_IP_CITY, STATIC_FIELD_LEN, 16, ascii_format, dump_as_ascii, "DST_IP_CITY", "", "City where the dst IP is located" },
#endif
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   FLOW_PROTO_PORT, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "FLOW_PROTO_PORT", "", "L7 port that identifies the flow protocol or 0 if unknown" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UPSTREAM_TUNNEL_ID, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "UPSTREAM_TUNNEL_ID", "", "Upstream tunnel identifier (e.g. GTP TEID) or 0 if unknown" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   LONGEST_FLOW_PKT, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "LONGEST_FLOW_PKT", "", "Longest packet (bytes) of the flow" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   SHORTEST_FLOW_PKT, STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint, "SHORTEST_FLOW_PKT", "", "Shortest packet (bytes) of the flow" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   RETRANSMITTED_IN_BYTES, STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint, "RETRANSMITTED_IN_BYTES", "", "Number of retransmitted TCP flow bytes (src->dst)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   RETRANSMITTED_IN_PKTS, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_IN_PKTS", "", "Number of retransmitted TCP flow packets (src->dst)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   RETRANSMITTED_OUT_BYTES, STATIC_FIELD_LEN, 4, numeric_format, dump_as_formatted_uint, "RETRANSMITTED_OUT_BYTES", "", "Number of retransmitted TCP flow bytes (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   RETRANSMITTED_OUT_PKTS, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "RETRANSMITTED_OUT_PKTS", "", "Number of retransmitted TCP flow packets (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   OOORDER_IN_PKTS, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_IN_PKTS", "", "Number of out of order TCP flow packets (dst->src)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   OOORDER_OUT_PKTS, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "OOORDER_OUT_PKTS", "", "Number of out of order TCP flow packets (dst->src)" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UNTUNNELED_PROTOCOL,  STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint,  "UNTUNNELED_PROTOCOL", "", "Untunneled IP protocol byte" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UNTUNNELED_IPV4_SRC_ADDR,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_SRC_ADDR", "", "Untunneled IPv4 source address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UNTUNNELED_L4_SRC_PORT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_SRC_PORT", "", "Untunneled IPv4 source port" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UNTUNNELED_IPV4_DST_ADDR,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_ipv4_address,  "UNTUNNELED_IPV4_DST_ADDR", "", "Untunneled IPv4 destination address" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   UNTUNNELED_L4_DST_PORT,  STATIC_FIELD_LEN, 2, numeric_format, dump_as_uint,  "UNTUNNELED_L4_DST_PORT", "", "Untunneled IPv4 destination port" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   L7_PROTO,  STATIC_FIELD_LEN, 2,  numeric_format, dump_as_uint,  "L7_PROTO", "", "Layer 7 protocol (numeric)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   L7_PROTO_NAME, VARIABLE_FIELD_LEN, PROTO_NAME_LEN, ascii_format,   dump_as_ascii, "L7_PROTO_NAME", "", "Layer 7 protocol name" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,  DOWNSTREAM_TUNNEL_ID, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DOWNSTREAM_TUNNEL_ID", "", "Downstream tunnel identifier (e.g. GTP TEID) or 0 if unknown" },

  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   FLOW_USER_NAME, VARIABLE_FIELD_LEN, 32, ascii_format, dump_as_ascii, "FLOW_USER_NAME", "", "Flow username of the tunnel (if known)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   FLOW_SERVER_NAME, VARIABLE_FIELD_LEN, 32, ascii_format, dump_as_ascii, "FLOW_SERVER_NAME", "", "Flow server name (if known)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   PLUGIN_NAME, VARIABLE_FIELD_LEN, 8, ascii_format, dump_as_ascii, "PLUGIN_NAME", "", "Plugin name used by this flow (if any)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_EQ_1,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_EQ_1", "", "# packets with TTL = 1" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_2_5,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_2_5", "", "# packets with TTL > 1 and TTL <= 5" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_5_32,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_5_32", "", "# packets with TTL > 5 and TTL <= 32" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_32_64,   STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_32_64", "", "# packets with TTL > 32 and <= 64 " },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_64_96,   STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_64_96", "", "# packets with TTL > 64 and <= 96" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_96_128,  STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_96_128", "", "# packets with TTL > 96 and <= 128" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_128_160, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_128_160", "", "# packets with TTL > 128 and <= 160" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_160_192, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_160_192", "", "# packets with TTL > 160 and <= 192" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_192_224, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_192_224", "", "# packets with TTL > 192 and <= 224" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   NUM_PKTS_TTL_224_255, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint,  "NUM_PKTS_TTL_224_255", "", "# packets with TTL > 224 and <= 255" },
  { 0, ONLY_IPV4,      FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   IN_SRC_OSI_SAP, STATIC_FIELD_LEN, 37, ascii_format,  dump_as_ascii, "IN_SRC_OSI_SAP", "", "OSI Source SAP (OSI Traffic Only)" },
  { 0, ONLY_IPV4,      FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   OUT_DST_OSI_SAP, STATIC_FIELD_LEN, 37, ascii_format, dump_as_ascii, "OUT_DST_OSI_SAP", "", "OSI Destination SAP (OSI Traffic Only)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   DURATION_CLI_SRV, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DURATION_CLI_SRV", "", "Client to Server stream duration (msec)" },
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, NTOP_ENTERPRISE_ID,   DURATION_SRV_CLI, STATIC_FIELD_LEN, 4, numeric_format, dump_as_uint, "DURATION_SRV_CLI", "", "Client to Server stream duration (msec)" },

  /* That's all folks */
  { 0, BOTH_IPV4_IPV6, FLOW_TEMPLATE, SHORT_SNAPLEN, STANDARD_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL, NULL }
};

/* ******************************************** */

void printTemplateInfo(V9V10TemplateElementId *templates,
		       u_char show_private_elements) {
  int j = 0;

  while(templates[j].netflowElementName != NULL) {
    if(!templates[j].isOptionTemplate) {
      if(((!show_private_elements)
	  && (templates[j].templateElementLen > 0))
	 || (show_private_elements && (templates[j].templateElementId >= 0xFF))) {

	if(templates[j].templateElementEnterpriseId == NTOP_ENTERPRISE_ID) {
	  printf("[NFv9 %3d][IPFIX %5d.%d] %%%-26s\t%s\n",
		 (int)templates[j].templateElementId,
		 templates[j].templateElementEnterpriseId, templates[j].templateElementId-NTOP_BASE_ID,
		 templates[j].netflowElementName,
		 templates[j].templateElementDescr);
	} else {
	  char ipfixName[64];

	  switch(templates[j].ipfixElementName[0]) {
	  case '\0':
	  case '<':
	    ipfixName[0] = '\0';
	    break;
	  default:
	    snprintf(ipfixName, sizeof(ipfixName), "%%%s", templates[j].ipfixElementName);
	  }

	  printf("[%3d] %%%-26s %-26s\t%s\n",
		 templates[j].templateElementId,
		 templates[j].netflowElementName,
		 ipfixName, templates[j].templateElementDescr);
	}
      }
    }

    j++;
  }
}

/* ******************************************** */

char* getStandardFieldId(u_int id) {
  int i = 0;

  while(ver9_templates[i].netflowElementName != NULL) {
    if(ver9_templates[i].templateElementId == id)
      return((char*)ver9_templates[i].netflowElementName);
    else
      i++;
  }

  return("");
}

/* ******************************************** */

void checkTemplates(void) {
  int i, j;

  /* Sanity check */
  for(j = 0; ver9_templates[j].netflowElementName != NULL; j++)
    for(i = 0; ver9_templates[i].netflowElementName != NULL; i++) {
      if(i == j) continue;
      if(ver9_templates[j].isOptionTemplate != ver9_templates[i].isOptionTemplate) continue;

      if((strcmp(ver9_templates[j].netflowElementName, ver9_templates[i].netflowElementName) == 0)
	 || (ver9_templates[j].templateElementId == ver9_templates[i].templateElementId)) {
	traceEvent(TRACE_WARNING, "Internal error: element clash [%s/%d] vs [%s/%d]",
		   ver9_templates[j].netflowElementName, ver9_templates[j].templateElementId,
		   ver9_templates[i].netflowElementName, ver9_templates[i].templateElementId);
	exit(0);
      }
    }
}

/* ******************************************** */

/*
   This function changes as necessary ver9_templates[]
   because some flow elememts have different length in
   IPFIX than on v9
*/
void fixTemplatesToIPFIX(void) {
  int i;

  if(readOnlyGlobals.netFlowVersion != 10) return;

  i = 0;
  while(ver9_templates[i].netflowElementName != NULL) {
    switch(ver9_templates[i].templateElementId) {
    case 10: /* INPUT_SNMP */
    case 14: /* OUTPUT_SNMP */
      ver9_templates[i].templateElementLen = 4;
      break;
    }

    i++;
  }
}

/* ******************************************** */

void sanitizeV4Template(char *str) {
  int i = 0;

  while(str[i] != '\0') {
    if(str[i+1] == '\0') break;

    if((str[i] == 'V') && (str[i+1] == '6')) {
      str[i+1] = '4';
      i++;
    }

    i++;
  }
}

/* ******************************************** */

void v4toV6Template(char *str) {
  int i = 0;

  while(str[i] != '\0') {
    if(str[i+1] == '\0') break;

    if((str[i] == 'V') && (str[i+1] == '4')) {
      str[i+1] = '6';
      i++;
    }

    i++;
  }
}

/* ******************************************** */

static void copyIpV6(struct in6_addr ipv6, char *outBuffer,
		     u_int *outBufferBegin, u_int *outBufferMax) {
  copyLen((u_char*)&ipv6, sizeof(ipv6), outBuffer,
	  outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMac(u_char *macAddress, char *outBuffer,
		    u_int *outBufferBegin, u_int *outBufferMax) {
  copyLen(macAddress, 6 /* lenght of mac address */,
	  outBuffer, outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMplsLabel(struct mpls_labels *mplsInfo, int labelId,
			  char *outBuffer, u_int *outBufferBegin,
			  u_int *outBufferMax) {
  if(mplsInfo == NULL) {
    int i;

    for(i=0; (i < 3) && (*outBufferBegin < *outBufferMax); i++) {
      outBuffer[*outBufferBegin] = 0;
      (*outBufferBegin)++;
    }
  } else {
    if(((*outBufferBegin)+MPLS_LABEL_LEN) < (*outBufferMax)) {
      memcpy(outBuffer, mplsInfo->mplsLabels[labelId-1], MPLS_LABEL_LEN);
      (*outBufferBegin) += MPLS_LABEL_LEN;
    }
  }
}

/* ******************************************** */

void copyVariableLenString(V9V10TemplateElementId *theTemplateElement,
			   char *name, char *outBuffer,
			   u_int *outBufferBegin, u_int *outBufferMax) {
  int len, name_len = strlen(name);

  if((readOnlyGlobals.netFlowVersion == 10)
     && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
    len = min(name_len, theTemplateElement->templateElementLen);
    name_len = min(name_len, len);
    copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
  } else
    len = theTemplateElement->templateElementLen;

  memcpy(&outBuffer[*outBufferBegin], name, name_len);

  if(len > name_len)
    memset(&outBuffer[*outBufferBegin+name_len], 0, len-name_len);

  if(readOnlyGlobals.enable_debug)
    traceEvent(TRACE_INFO, "==> %s='%s' [len=%d]",
	       theTemplateElement->netflowElementName, name, len);

  (*outBufferBegin) += len;
}

/* ******************************************** */

static void handleTemplate(V9V10TemplateElementId *theTemplateElement,
			   PluginEntryPoint *pluginEntryPoint,
			   u_int8_t ipv4_template,
			   char *outBuffer, u_int *outBufferBegin,
			   u_int *outBufferMax,
			   char buildTemplate, int *numElements,
			   FlowHashBucket *theFlow, FlowDirection direction,
			   int addTypeLen, int optionTemplate,
			   u_int8_t json_mode) {
  u_char null_data[128] = { 0 };
  u_char minus_one_data[128] = { -1 };
  char proto_name[PROTO_NAME_LEN+1] = { 0 }, *country, *city;
  u_int16_t t16;

  if(buildTemplate || addTypeLen) {
    /* Type */
    t16 = theTemplateElement->templateElementId;

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      if(theTemplateElement->templateElementEnterpriseId == NTOP_ENTERPRISE_ID)
	t16 -= NTOP_BASE_ID; /* Just to make sure we don't mess-up the template */

      t16 = t16 | 0x8000; /* Enable the PEN bit */
    }

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    /* Len */
    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->variableFieldLength == VARIABLE_FIELD_LEN)) {
      t16 = 65535; /* Reserved len as specified in rfc5101 */
    } else
      t16 = theTemplateElement->templateElementLen;

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID)) {
      /* PEN */
      copyInt32(theTemplateElement->templateElementEnterpriseId,
		outBuffer, outBufferBegin, outBufferMax);
    }
  }

  if(!buildTemplate) {
    if(theTemplateElement->templateElementLen == 0)
      ; /* Nothing to do: all fields have zero length */
    else {
      u_char custom_field[CUSTOM_FIELD_LEN] = { '\0' };

#ifdef DEBUG
      traceEvent(TRACE_INFO, "[%d][%s][%d]",
		 theTemplateElement->templateElementId,
		 theTemplateElement->netflowElementName,
		 theTemplateElement->templateElementLen);
#endif

      if(theTemplateElement->isOptionTemplate) {
	copyLen(null_data, theTemplateElement->templateElementLen,
		outBuffer, outBufferBegin, outBufferMax);
      } else {
	/*
	 * IMPORTANT
	 *
	 * Any change below need to be ported also in printRecordWithTemplate()
	 *
	 */
	int t;
	u_char dummy_mac[6] = { 0 };
#ifdef HAVE_GEOIP
	GeoIPRecord *geo;
#endif
  
	switch(theTemplateElement->templateElementId) {
	case IN_BYTES:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesRcvd : theFlow->core.tuple.flowCounters.bytesSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IN_PKTS:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case PROTOCOL:
	  copyInt8((u_int8_t)theFlow->core.tuple.key.k.ipKey.proto, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SRC_TOS:
	  copyInt8((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? theFlow->ext->src2dstTos : theFlow->ext->dst2srcTos),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case TCP_FLAGS:
	  copyInt8(((theFlow->core.tuple.key.k.ipKey.proto != IPPROTO_TCP) || (theFlow->ext == NULL)) ? 0 : 
		   ((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.src2dstTcpFlags : theFlow->ext->protoCounters.tcp.dst2srcTcpFlags),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case L4_SRC_PORT:
	  copyInt16(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.sport : theFlow->core.tuple.key.k.ipKey.dport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV4_SRC_ADDR:
	  if(theFlow->core.tuple.key.is_ip_flow && (theFlow->core.tuple.key.k.ipKey.src.ipVersion == 4) && (theFlow->core.tuple.key.k.ipKey.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.src.ipType.ipv4 : theFlow->core.tuple.key.k.ipKey.dst.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV4_SRC_MASK:
	  if((!theFlow->core.tuple.key.is_ip_flow) || (theFlow->ext == NULL))
	    copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt8(((direction == src2dst_direction) ? ip2mask(&theFlow->core.tuple.key.k.ipKey.src, &theFlow->ext->srcInfo) :
		      ip2mask(&theFlow->core.tuple.key.k.ipKey.dst, &theFlow->ext->dstInfo)),
		     outBuffer, outBufferBegin, outBufferMax);
	  break;
	case INPUT_SNMP:
	  if(readOnlyGlobals.netFlowVersion == 10)
	    copyInt32((theFlow->ext == NULL) ? 0 : ((direction == src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output), outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16((theFlow->ext == NULL) ? 0 : ((direction == src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case L4_DST_PORT:
	  copyInt16(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.dport : theFlow->core.tuple.key.k.ipKey.sport, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV4_DST_ADDR:
	  if(theFlow->core.tuple.key.is_ip_flow & (theFlow->core.tuple.key.k.ipKey.src.ipVersion == 4) && (theFlow->core.tuple.key.k.ipKey.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.dst.ipType.ipv4 : theFlow->core.tuple.key.k.ipKey.src.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV4_DST_MASK:
	  if(!theFlow->core.tuple.key.is_ip_flow)
	    copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt8((theFlow->ext == NULL) ? 0 : ((direction == dst2src_direction) ? ip2mask(&theFlow->core.tuple.key.k.ipKey.src, &theFlow->ext->srcInfo)
						   : ip2mask(&theFlow->core.tuple.key.k.ipKey.dst, &theFlow->ext->dstInfo)),
		     outBuffer, outBufferBegin, outBufferMax);
	  break;
	case OUTPUT_SNMP:
	  if(readOnlyGlobals.netFlowVersion == 10)
	    copyInt32((theFlow->ext == NULL) ? 0 : ((direction != src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output), outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16((theFlow->ext == NULL) ? 0 : ((direction != src2dst_direction) ? theFlow->ext->if_input : theFlow->ext->if_output), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV4_NEXT_HOP:
	  copyInt32((theFlow->ext && (theFlow->ext->nextHop.ipVersion == 4)) ? theFlow->ext->nextHop.ipType.ipv4 : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SRC_AS:
	  copyInt32((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? getAS(&theFlow->core.tuple.key.k.ipKey.src, &theFlow->ext->srcInfo) :
						  getAS(&theFlow->core.tuple.key.k.ipKey.dst, &theFlow->ext->dstInfo)),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case DST_AS:
	  copyInt32((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? getAS(&theFlow->core.tuple.key.k.ipKey.dst, &theFlow->ext->dstInfo) :
						  getAS(&theFlow->core.tuple.key.k.ipKey.src, &theFlow->ext->srcInfo)),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case LAST_SWITCHED:
 	  copyInt32(msTimeDiff(getFlowEndTime(theFlow, direction), &readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case FIRST_SWITCHED:
	  copyInt32(msTimeDiff(getFlowBeginTime(theFlow, direction), &readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case OUT_BYTES:
	  copyInt32(direction == dst2src_direction ? theFlow->core.tuple.flowCounters.bytesSent : theFlow->core.tuple.flowCounters.bytesRcvd,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case OUT_PKTS:
	  copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowCounters.pktRcvd : theFlow->core.tuple.flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV6_SRC_ADDR:
	  if(theFlow->core.tuple.key.is_ip_flow
	     && (theFlow->core.tuple.key.k.ipKey.src.ipVersion == 6) && (theFlow->core.tuple.key.k.ipKey.dst.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.src.ipType.ipv6 : theFlow->core.tuple.key.k.ipKey.dst.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case IPV6_DST_ADDR:
	  if((theFlow->core.tuple.key.k.ipKey.src.ipVersion == 6) && theFlow->core.tuple.key.is_ip_flow
	     && (theFlow->core.tuple.key.k.ipKey.dst.ipVersion == 6))
	    copyIpV6(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.dst.ipType.ipv6 : theFlow->core.tuple.key.k.ipKey.dst.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case IPV6_SRC_MASK:
	case IPV6_DST_MASK:
	  copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case ICMP_TYPE:
	  copyInt16((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpType : theFlow->ext->protoCounters.icmp.dst2srcIcmpType),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SAMPLING_INTERVAL:
	  copyInt32(readOnlyGlobals.pktSampleRate /* 1:1 = no sampling */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SAMPLING_ALGORITHM:
	  copyInt8(0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case FLOW_ACTIVE_TIMEOUT:
	  copyInt16(readOnlyGlobals.lifetimeTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case FLOW_INACTIVE_TIMEOUT:
	  copyInt16(readOnlyGlobals.idleTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case ENGINE_TYPE:
	  copyInt8(theFlow->core.engine_type, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case ENGINE_ID:
	  copyInt8(theFlow->core.engine_id, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case TOTAL_BYTES_EXP:
	  copyInt32(readWriteGlobals->flowExportStats.totExportedBytes, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case TOTAL_PKTS_EXP:
	  copyInt32(readWriteGlobals->flowExportStats.totExportedPkts, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case TOTAL_FLOWS_EXP:
	  copyInt32(readWriteGlobals->flowExportStats.totExportedFlows, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MIN_TTL:
	  copyInt8((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? theFlow->ext->src2dstMinTTL : theFlow->ext->dst2srcMinTTL), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MAX_TTL:
	  copyInt8((theFlow->ext == NULL) ? 0 : (direction == src2dst_direction ? theFlow->ext->src2dstMaxTTL : theFlow->ext->dst2srcMaxTTL), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IN_SRC_MAC:
	  copyMac((theFlow->ext == NULL) ? dummy_mac : (direction == src2dst_direction ? theFlow->ext->srcInfo.macAddress : theFlow->ext->dstInfo.macAddress),
		  outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SRC_VLAN:
	  /* no break */
	case DST_VLAN:
	  copyInt16(theFlow->core.tuple.key.vlanId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IP_PROTOCOL_VERSION:
	  copyInt8((theFlow->core.tuple.key.k.ipKey.src.ipVersion == 4) && (theFlow->core.tuple.key.k.ipKey.dst.ipVersion == 4) ? 4 : 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case DIRECTION: /* Flow Direction [ 0=RX, 1=TX ] */
	  copyInt8(theFlow->core.rx_direction.src2dst == 1 /* RX */ ? 0 /* RX */: 1 /* TX */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case IPV6_NEXT_HOP:
	  if(theFlow->ext && (theFlow->ext->nextHop.ipVersion == 6))
	    copyIpV6(theFlow->ext->nextHop.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  else {
	    IpAddress addr;

	    memset(&addr, 0, sizeof(addr));
	    copyIpV6(addr.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;

	case MPLS_LABEL_1: /* MPLS: label 1 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 1, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_2: /* MPLS: label 2 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 2, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_3: /* MPLS: label 3 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 3, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_4: /* MPLS: label 4 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 4, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_5: /* MPLS: label 5 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 5, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_6: /* MPLS: label 6 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_7: /* MPLS: label 7 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 7, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_8: /* MPLS: label 8 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 8, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_9: /* MPLS: label 9 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 9, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case MPLS_LABEL_10: /* MPLS: label 10 */
	  copyMplsLabel(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : theFlow->ext->extensions->mplsInfo, 10, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case OUT_DST_MAC:
	  copyMac((theFlow->ext == NULL) ? dummy_mac : (direction == src2dst_direction ? theFlow->ext->dstInfo.macAddress : theFlow->ext->srcInfo.macAddress),
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case APPLICATION_ID:
	  /* We need the check below as the NBAR and nDPI applicationIds are shared */
	  copyInt32((theFlow->core.l7.proto_type != NDPI_PROTO_TYPE) ? theFlow->core.l7.proto.collected_application_id : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case EXPORTER_IPV4_ADDRESS:
	  copyInt32((theFlow->ext == NULL) ? 0 : theFlow->ext->srcInfo.ifHost, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case EXPORTER_IPV6_ADDRESS:
	  {
	    IpAddress addr;

	    memset(&addr, 0, sizeof(addr));
	    copyIpV6(addr.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;

	case FLOW_ID:
	  if(theFlow->core.tuple.flow_serial == 0) theFlow->core.tuple.flow_serial = get_flow_serial();
	  copyInt32(theFlow->core.tuple.flow_serial, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_START_SEC:
	  if(readOnlyGlobals.flowCollection.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.firstSeenSent.tv_sec : theFlow->core.tuple.flowTimers.firstSeenRcvd.tv_sec,
		      outBuffer, outBufferBegin, outBufferMax);
	  break;
	case FLOW_END_SEC:
	  if(readOnlyGlobals.flowCollection.collectorInPort > 0)
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(direction == src2dst_direction ? theFlow->core.tuple.flowTimers.lastSeenSent.tv_sec : theFlow->core.tuple.flowTimers.lastSeenRcvd.tv_sec,
		      outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_START_MILLISECONDS:
	  copyInt64(direction == src2dst_direction ? to_msec(&theFlow->core.tuple.flowTimers.firstSeenSent) : to_msec(&theFlow->core.tuple.flowTimers.firstSeenRcvd),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_END_MILLISECONDS:
	  copyInt64(direction == src2dst_direction ? to_msec(&theFlow->core.tuple.flowTimers.lastSeenSent) : to_msec(&theFlow->core.tuple.flowTimers.lastSeenRcvd),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case BIFLOW_DIRECTION:
	  copyInt8((direction == src2dst_direction) ? 1 /* Initiator */ : 2 /* Reverse Initiator */, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ************************************ */

	  /* nProbe Extensions */
	case FRAGMENTS:
	  copyInt16(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (direction == src2dst_direction ? theFlow->ext->flowCounters.sentFragPkts : theFlow->ext->flowCounters.rcvdFragPkts),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

#ifdef DEPRECATED_INFORMATION_ELEMENTS
	case CLIENT_NW_DELAY_SEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->clientNwLatency.tv_sec : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case CLIENT_NW_DELAY_USEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->clientNwLatency.tv_usec : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
#endif

	case CLIENT_NW_LATENCY_MS:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? (u_int32_t)toMs(&theFlow->ext->extensions->clientNwLatency) : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

#ifdef DEPRECATED_INFORMATION_ELEMENTS
	case SERVER_NW_DELAY_SEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->serverNwLatency.tv_sec : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case SERVER_NW_DELAY_USEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? theFlow->ext->extensions->serverNwLatency.tv_usec : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
#endif

	case SERVER_NW_LATENCY_MS:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (nwLatencyComputed(theFlow->ext) ? (u_int32_t)toMs(&theFlow->ext->extensions->serverNwLatency) : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case APPL_LATENCY_SEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (applLatencyComputed(theFlow->ext) ? (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_sec
										       : theFlow->ext->extensions->dst2srcApplLatency.tv_sec) : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case APPL_LATENCY_USEC:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (applLatencyComputed(theFlow->ext) ?
						  (direction == src2dst_direction ? theFlow->ext->extensions->src2dstApplLatency.tv_usec :
						   theFlow->ext->extensions->dst2srcApplLatency.tv_usec) : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case APPL_LATENCY_MS:
	  copyInt32(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL))? 0 : (applLatencyComputed(theFlow->ext) ?
						  (u_int32_t)(direction == src2dst_direction ? toMs(&theFlow->ext->extensions->src2dstApplLatency) :
							      toMs(&theFlow->ext->extensions->dst2srcApplLatency)) : 0),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_UP_TO_128_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_up_to_128_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_up_to_128_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_up_to_128_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_up_to_128_bytes;
	  } else
	    t = 0;

	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_128_TO_256_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_128_to_256_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_128_to_256_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_128_to_256_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_128_to_256_bytes;
	  } else
	    t = 0;
	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_256_TO_512_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_256_to_512_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_256_to_512_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_256_to_512_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_256_to_512_bytes;
	  } else
	    t = 0;
	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_512_TO_1024_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_512_to_1024_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_512_to_1024_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_512_to_1024_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_512_to_1024_bytes;
	  } else
	    t = 0;

	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_1024_TO_1514_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_1024_to_1514_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_1024_to_1514_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_1024_to_1514_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_1024_to_1514_bytes;
	  } else
	    t = 0;

	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_OVER_1514_BYTES:
	  if(theFlow->ext && theFlow->ext->extensions) {
	    if(readOnlyGlobals.bidirectionalFlows) 
	      t = theFlow->ext->extensions->etherstats.src2dst.num_pkts_over_1514_bytes+theFlow->ext->extensions->etherstats.dst2src.num_pkts_over_1514_bytes;
	    else
	      t = (direction == src2dst_direction) ? theFlow->ext->extensions->etherstats.src2dst.num_pkts_over_1514_bytes : theFlow->ext->extensions->etherstats.dst2src.num_pkts_over_1514_bytes;
	  } else
	    t = 0;

	  copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ****************** */

	case CUMULATIVE_ICMP_TYPE:
	  copyInt32(direction == src2dst_direction ? theFlow->ext->protoCounters.icmp.src2dstIcmpFlags
		    : theFlow->ext->protoCounters.icmp.dst2srcIcmpFlags,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case SRC_IP_COUNTRY:
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
	  country = (geo && geo->country_code) ? geo->country_code : NULL;
#else
	  country = (direction == src2dst_direction) ? theFlow->ext->srcInfo.collected_country_code : theFlow->ext->dstInfo.collected_country_code;
#endif

	  copyLen((u_char*)(country ? country : "  "), 2, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case SRC_IP_CITY:
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->srcInfo.geo : theFlow->ext->dstInfo.geo;
	  city = (geo && geo->city) ? geo->city : NULL;
#else
	  city = (direction == src2dst_direction) ? theFlow->ext->srcInfo.collected_city : theFlow->ext->dstInfo.collected_city;
#endif

	  copyLen((u_char*)(city ? city : "                "), 16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case DST_IP_COUNTRY:
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
	  country = (geo && geo->country_code) ? geo->country_code : NULL;
#else
	  country = (direction == src2dst_direction) ? theFlow->ext->dstInfo.collected_country_code : theFlow->ext->srcInfo.collected_country_code;
#endif

	  copyLen((u_char*)(country ? country : "  "), 2, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case DST_IP_CITY:
#ifdef HAVE_GEOIP
	  geo = (direction == src2dst_direction) ? theFlow->ext->dstInfo.geo : theFlow->ext->srcInfo.geo;
	  city = (geo && geo->city) ? geo->city : NULL;
#else
	  city = (direction == src2dst_direction) ? theFlow->ext->dstInfo.collected_city : theFlow->ext->srcInfo.collected_city;
#endif

	  copyLen((u_char*)(city ? city : "                "), 16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_PROTO_PORT:
	  t16 = getFlowApplProtocol(theFlow);
	  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UPSTREAM_TUNNEL_ID:
	  copyInt32(theFlow->ext->src2dst_tunnel_id, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case LONGEST_FLOW_PKT:
	  copyInt16(theFlow->ext->flowCounters.pktSize.longest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case SHORTEST_FLOW_PKT:
	  copyInt16(theFlow->ext->flowCounters.pktSize.shortest, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case RETRANSMITTED_IN_BYTES:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ?
		    (direction == dst2src_direction ? theFlow->ext->protoCounters.tcp.bytesRcvdRetransmitted : 
		    theFlow->ext->protoCounters.tcp.bytesSentRetransmitted) : 0,
		    outBuffer, outBufferBegin, outBufferMax); 
	  break;

	case RETRANSMITTED_IN_PKTS:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ? 
		    ((direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.pktRcvdRetransmitted : 
		     theFlow->ext->protoCounters.tcp.pktSentRetransmitted) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case RETRANSMITTED_OUT_BYTES:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ?
		    (direction == src2dst_direction ? theFlow->ext->protoCounters.tcp.bytesRcvdRetransmitted : 
		    theFlow->ext->protoCounters.tcp.bytesSentRetransmitted) : 0,
		    outBuffer, outBufferBegin, outBufferMax); 
	  break;

	case RETRANSMITTED_OUT_PKTS:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ?
		    ((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.pktRcvdRetransmitted : 
		     theFlow->ext->protoCounters.tcp.pktSentRetransmitted) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case OOORDER_IN_PKTS:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ? 
		    ((direction == dst2src_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder : 
		     theFlow->ext->protoCounters.tcp.sentOOOrder) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case OOORDER_OUT_PKTS:
	  copyInt32((theFlow->core.tuple.key.k.ipKey.proto == IPPROTO_TCP) ? 
		    ((direction == src2dst_direction) ? theFlow->ext->protoCounters.tcp.rcvdOOOrder : 
		     theFlow->ext->protoCounters.tcp.sentOOOrder) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UNTUNNELED_PROTOCOL:
	  copyInt8(((theFlow->ext == NULL) || (theFlow->ext->extensions == NULL)) ? 0 : (u_int8_t)theFlow->ext->extensions->untunneled.proto, 
		   outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UNTUNNELED_IPV4_SRC_ADDR:
	  if(readOnlyGlobals.tunnel_mode 
	     && (theFlow->ext != NULL)
	     && (theFlow->ext->extensions != NULL)
	     && theFlow->core.tuple.key.is_ip_flow
	     && (theFlow->ext->extensions->untunneled.src.ipVersion == 4) 
	     && (theFlow->ext->extensions->untunneled.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.src.ipType.ipv4 : 
		      theFlow->ext->extensions->untunneled.dst.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UNTUNNELED_L4_SRC_PORT:
	  if(readOnlyGlobals.tunnel_mode 
	     && (theFlow->ext != NULL)
	     && (theFlow->ext->extensions != NULL))
	    copyInt16(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.sport : 
		      theFlow->ext->extensions->untunneled.dport, outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UNTUNNELED_IPV4_DST_ADDR:
	  if(readOnlyGlobals.tunnel_mode 
	     && (theFlow->ext != NULL)
	     && (theFlow->ext->extensions != NULL)
	     && theFlow->core.tuple.key.is_ip_flow
	     && (theFlow->ext->extensions->untunneled.src.ipVersion == 4) 
	     && (theFlow->ext->extensions->untunneled.dst.ipVersion == 4))
	    copyInt32(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dst.ipType.ipv4 
		      : theFlow->ext->extensions->untunneled.src.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case UNTUNNELED_L4_DST_PORT:
	  if(readOnlyGlobals.tunnel_mode && theFlow->ext && theFlow->ext->extensions)
	    copyInt16(direction == src2dst_direction ? theFlow->ext->extensions->untunneled.dport : 
		      theFlow->ext->extensions->untunneled.sport,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case L7_PROTO:
	  copyInt16((theFlow->core.l7.proto_type == NDPI_PROTO_TYPE) ?
		    theFlow->core.l7.proto.ndpi.ndpi_proto : 0, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case L7_PROTO_NAME:
	  snprintf(proto_name, sizeof(proto_name)-1, "%s",
		   (theFlow->core.l7.proto_type == NDPI_PROTO_TYPE) ?
		   getProtoName(theFlow->core.l7.proto.ndpi.ndpi_proto) : 
		   getProtoName(NDPI_PROTOCOL_UNKNOWN));

	  copyVariableLenString(theTemplateElement, proto_name,
				outBuffer, outBufferBegin, outBufferMax);
	  break;

	case DOWNSTREAM_TUNNEL_ID:
	  copyInt32(theFlow->ext->dst2src_tunnel_id, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_USER_NAME:
	  copyVariableLenString(theTemplateElement,
				theFlow->core.user.username ? theFlow->core.user.username : "",
				outBuffer, outBufferBegin, outBufferMax);
	  break;

	case FLOW_SERVER_NAME:
	  mapServerName(theFlow);

	  copyVariableLenString(theTemplateElement,
				theFlow->core.server.name ? theFlow->core.server.name : "",
				outBuffer, outBufferBegin, outBufferMax);
	  break;

	case PLUGIN_NAME:
	  // name = pluginEntryPoint ? pluginEntryPoint->short_name : "";

	  copyVariableLenString(theTemplateElement,
				pluginEntryPoint ? pluginEntryPoint->short_name : "",
				outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_EQ_1:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_eq_1 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_eq_1) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_2_5:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_2_5 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_2_5) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_5_32:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_5_32 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_5_32) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_32_64:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_32_64 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_32_64) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_64_96:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_64_96 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_64_96) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_96_128:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_96_128 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_96_128) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_128_160:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_128_160 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_128_160) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_160_192:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_160_192 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_160_192) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_192_224:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_192_224 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_192_224) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NUM_PKTS_TTL_224_255:
	  copyInt32((theFlow->ext && theFlow->ext->extensions) ? (direction == src2dst_direction ? theFlow->ext->extensions->ttlstats.src2dst.num_pkts_224_255 : 
				    theFlow->ext->extensions->ttlstats.dst2src.num_pkts_224_255) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case IN_SRC_OSI_SAP:
	  copyLen((u_char*)((theFlow->ext && theFlow->ext->extensions && theFlow->ext->extensions->osi.ssap) ? theFlow->ext->extensions->osi.ssap : 
			    "                  "), 37, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case OUT_DST_OSI_SAP:
	  copyLen((u_char*)((theFlow->ext && theFlow->ext->extensions && theFlow->ext->extensions->osi.ssap) ? theFlow->ext->extensions->osi.dsap : 
			    "                  "), 37, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case DURATION_CLI_SRV:
 	  copyInt32(msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenSent, &theFlow->core.tuple.flowTimers.firstSeenSent), outBuffer, outBufferBegin, outBufferMax);
	  break;

	case DURATION_SRV_CLI:
 	  copyInt32(msTimeDiff(&theFlow->core.tuple.flowTimers.lastSeenRcvd, &theFlow->core.tuple.flowTimers.firstSeenRcvd), outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* Custom fields */
	case PROTOCOL_MAP:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", proto2name(theFlow->core.tuple.key.k.ipKey.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case L4_SRC_PORT_MAP:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s",
		   port2name(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.sport
			     : theFlow->core.tuple.key.k.ipKey.dport, theFlow->core.tuple.key.k.ipKey.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case L4_DST_PORT_MAP:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s",
		   port2name(direction == src2dst_direction ? theFlow->core.tuple.key.k.ipKey.dport
			     : theFlow->core.tuple.key.k.ipKey.sport, theFlow->core.tuple.key.k.ipKey.proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;

	case L4_SRV_PORT:
	  copyInt16(getServerPort(theFlow), outBuffer, outBufferBegin, outBufferMax);
	  break;

	case L4_SRV_PORT_MAP:
	  snprintf((char*)custom_field, sizeof(custom_field), "%u", getServerPort(theFlow));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;

	default:
	  if(checkPluginExport(theTemplateElement, direction, theFlow,
			       outBuffer, outBufferBegin, outBufferMax) == -1) {
	    /*
	      This flow is the one we like, however we need
	      to store some values anyway, so we put an empty value
	    */
	    u_char *what;

	    if(strcmp(theTemplateElement->netflowElementName, "RTP_OUT_PAYLOAD_TYPE") == 0)
	      what = minus_one_data;
	    else
	      what = null_data;

	    copyVariableLenString(theTemplateElement, (char*)what, outBuffer, outBufferBegin, outBufferMax);
	  }
	}
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "name=%s/Id=%d/len=%d [len=%d][outBufferMax=%d]\n",
	       theTemplateElement->netflowElementName,
	       theTemplateElement->templateElementId,
	       theTemplateElement->templateElementLen,
	       *outBufferBegin, *outBufferMax);
#endif
  }

  (*numElements) = (*numElements)+1;

  return;
}

/* ******************************************** */

PluginEntryPoint* compileTemplate(char **__fmt, V9V10TemplateElementId **templateList,
				  int templateElements, u_int8_t isOptionTemplate,
				  u_int8_t isIPv6OnlyTemplate) {
  int idx=0, endIdx, i, templateIdx, len;
  char fmt[4096], tmpChar, found, *_fmt;
  u_int8_t ignored;
  PluginEntryPoint *plugin = NULL;

  _fmt = expandPluginTemplate(__fmt);
  len = strlen(_fmt);

  /* Change \n and \r (if any) to space */
  for(i=0; _fmt[i] != '\0'; i++) {
    switch(_fmt[i]) {
    case '\r':
    case '\n':
      _fmt[i] = ' ';
      break;
    }
  }

  templateIdx = 0;
  snprintf(fmt, sizeof(fmt), "%s", _fmt);

  while((idx < len) && (fmt[idx] != '\0')) {	/* scan format string characters */
    switch(fmt[idx]) {
    case '%':	        /* special format follows */
      endIdx = ++idx;
      while(fmt[endIdx] != '\0') {
	if((fmt[endIdx] == ' ') || (fmt[endIdx] == '%'))
	  break;
	else
	  endIdx++;
      }

      if((endIdx == (idx+1)) && (fmt[endIdx] == '\0')) return(plugin);
      tmpChar = fmt[endIdx]; fmt[endIdx] = '\0';

      ignored = 0;

      if(strstr(&fmt[idx], "MYSQL")) readOnlyGlobals.enableMySQLPlugin = 1;

      if(strstr(&fmt[idx], "_COUNTRY") || strstr(&fmt[idx], "_CITY")) {
	if(readOnlyGlobals.flowCollection.collectorInPort == 0) {
#ifdef HAVE_GEOIP
	  if(readOnlyGlobals.geo_ip_city_db == NULL) {
	    static u_int8_t shown = 0;

	    if(!shown) {
	      traceEvent(TRACE_WARNING, "Geo-location requires --city-list to be specified: ignored %s", &fmt[idx]);
	      shown = 1;
	    }

	    ignored = 1;
	  }
#else
	  ignored = 1;
#endif
	}
      }

#if 0
      if(readOnlyGlobals.enable_debug)
	traceEvent(TRACE_NORMAL, "Checking '%s' [ignored=%d]", &fmt[idx], ignored);
#endif

      if(!ignored) {
	int duplicate_found = 0;
	char *element = &fmt[idx];

	i = 0, found = 0;

	/* Code used to avoid breaking existing systems */
	if(!strcmp(element, "SRC_MASK"))
	  element = isIPv6OnlyTemplate ? "IPV6_SRC_MASK" : "IPV4_SRC_MASK";
	else if(!strcmp(element, "DST_MASK"))
	  element = isIPv6OnlyTemplate ? "IPV6_DST_MASK" : "IPV4_DST_MASK";

	while(ver9_templates[i].netflowElementName != NULL) {
#if 0
	  traceEvent(TRACE_WARNING, "===>>>> %s", ver9_templates[i].netflowElementName);
#endif
	  if(isOptionTemplate
	     || ((!isOptionTemplate) && (ver9_templates[i].isOptionTemplate == 0))) {
	    if(
	       ((strcmp(element, ver9_templates[i].netflowElementName) == 0)
		|| (strcmp(element, ver9_templates[i].ipfixElementName) == 0))
#if 0
	       ||
	       ((((strlen(ver9_templates[i].netflowElementName) > 0)
		  && (strncmp(ver9_templates[i].netflowElementName, element, strlen(ver9_templates[i].netflowElementName)) == 0))
		 || ((strlen(ver9_templates[i].ipfixElementName) > 0)
		     && (strncmp(ver9_templates[i].ipfixElementName, element, strlen(ver9_templates[i].ipfixElementName)) == 0))
		 ) && (ver9_templates[i].variableFieldLength == VARIABLE_FIELD_LEN))
#endif
	       ) {
	      int j;

	      for(j=0; j<templateIdx; j++) {
		if(templateList[j] == &ver9_templates[i]) {
		  traceEvent(TRACE_INFO, "Duplicate template element found %s: skipping", ver9_templates[i].netflowElementName);
		  duplicate_found = 1;
		  break;
		}
	      }

	      if(!duplicate_found) {
		templateList[templateIdx] = &ver9_templates[i];
		if(ver9_templates[i].useLongSnaplen)
		  readOnlyGlobals.snaplen = max(readOnlyGlobals.snaplen, PCAP_LONG_SNAPLEN);
		found = 1, templateList[templateIdx]->isInUse = 1;
		templateIdx++;
	      }

	      break;
	    }

#if 0
	    traceEvent(TRACE_WARNING, "Checking [%s][%s][found=%d]",
		       element, ver9_templates[i].netflowElementName, found);
#endif
	  }

	  i++;
	}

	if(!duplicate_found) {
	  /* traceEvent(TRACE_WARNING, "Checking [%s][found=%d]", &fmt[idx], found); */

	  if(!found) {
	    if((templateList[templateIdx] = getPluginTemplate(&fmt[idx], &plugin)) != NULL) {
	      if(templateList[templateIdx]->useLongSnaplen)
		readOnlyGlobals.snaplen = max(readOnlyGlobals.snaplen, PCAP_LONG_SNAPLEN);
	      templateList[templateIdx]->isInUse = 1;
	      /* traceEvent(TRACE_WARNING, "Added field '%s' with index %d", &fmt[idx], templateIdx); */
	      templateIdx++;
	    } else {
	      traceEvent(TRACE_WARNING, "Unable to locate template '%s'. Discarded.", &fmt[idx]);
	    }
	  }

	  if(templateIdx >= (templateElements-1)) {
	    traceEvent(TRACE_WARNING, "Unable to add further template elements (%d).", templateIdx);
	    break;
	  }
	}
      }

      fmt[endIdx] = tmpChar;
      if(tmpChar == '%')
	idx = endIdx;
      else
	idx = endIdx+1;
      break;

    default:
      idx++;
      break;
    }
  }

  templateList[templateIdx] = NULL;
  return(plugin);
}

/* ******************************************** */

void flowPrintf(V9V10TemplateElementId **templateList,
		PluginEntryPoint *pluginEntryPoint,
		u_int8_t ipv4_template, char *outBuffer,
		u_int *outBufferBegin, u_int *outBufferMax,
		int *numElements, char buildTemplate,
		FlowHashBucket *theFlow, FlowDirection direction,
		int addTypeLen, int optionTemplate,
		u_int8_t json_mode) {
  int idx = 0;

  (*numElements) = 0;

  while(templateList[idx] != NULL) {
    handleTemplate(templateList[idx], pluginEntryPoint,
		   ipv4_template,
		   outBuffer, outBufferBegin, outBufferMax,
		   buildTemplate, numElements,
		   theFlow, direction, addTypeLen,
		   optionTemplate, json_mode);
    idx++;
  }
}
