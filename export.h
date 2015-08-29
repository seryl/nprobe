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

#ifndef _EXPORT_H_
#define _EXPORT_H_

#ifdef HAVE_VOIP_EXTENSIONS
#include "plugins/hep.h"
#endif

extern int exportBucketToNetflow(FlowHashBucket *myBucket, FlowDirection direction);
extern void setBucketExpired(FlowHashBucket *myBucket);
extern void checkNetFlowExport(int forceExport);

extern void sendNetFlow(void *buffer, u_int32_t bufferLength,
			u_char lastFlow, int sequenceIncrement,
			u_char broadcastToAllCollectors);
extern void sendNetFlowV5(NetFlow5Record *theV5Flow, u_char lastFlow);
extern void sendNetFlowV9V10(u_char lastFlow, u_char sendTemplate,
			     u_char sendOnlyTheTemplate);
extern void setServerName(FlowHashBucket *bkt, char *name);
extern void mapServerName(FlowHashBucket *bkt);
extern void teid2user(FlowHashBucket *bkt, u_int32_t teid);
extern void mapTrafficToUser(FlowHashBucket *bkt);
extern void initNetFlowV5Header(NetFlow5Record *theV5Flow);
extern void initNetFlowV9Header(V9FlowHeader *v9Header);
extern void initIPFIXHeader(IPFIXFlowHeader *v10Header);
extern int is_locked_send(void);

extern int set_tcp_client_address(char *host_and_port, struct sockaddr_in *servaddr);
extern void close_socket(int sock);
extern int connect_to_server(struct sockaddr *servaddr);
extern int send_tcp(int sock, char *msg, u_int msg_len);

#endif /* _EXPORT_H_ */
