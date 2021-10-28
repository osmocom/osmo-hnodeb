/* (C) 2015 by Daniel Willmann <dwillmann@sysmocom.de>
 * (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/lienses/>.
 *
 */

#include "config.h"

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/netif/stream.h>

#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/hnodeb.h>

static int hnb_iuh_read_cb(struct osmo_stream_cli *conn)
{
	struct osmo_fd *fd = osmo_stream_cli_get_ofd(conn);
	struct hnb *hnb = osmo_stream_cli_get_data(conn);
	struct sctp_sndrcvinfo sinfo;
	struct msgb *msg = msgb_alloc(IUH_MSGB_SIZE, "Iuh rx");
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	rc = sctp_recvmsg(fd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error during sctp_recvmsg()\n");
		/* FIXME: clean up after disappeared HNB */
		osmo_stream_cli_close(conn);
		return rc;
	} else if (rc == 0) {
		LOGP(DMAIN, LOGL_INFO, "Connection to HNB closed\n");
		osmo_stream_cli_close(conn);
		return -1;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		LOGP(DMAIN, LOGL_DEBUG, "Ignoring SCTP notification\n");
		msgb_free(msg);
		return 0;
	}

	sinfo.sinfo_ppid = ntohl(sinfo.sinfo_ppid);

	switch (sinfo.sinfo_ppid) {
	case IUH_PPI_HNBAP:
		LOGP(DHNBAP, LOGL_INFO, "HNBAP message received\n");
		rc = hnb_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		LOGP(DRUA, LOGL_INFO, "RUA message received\n");
		rc = hnb_rua_rx(hnb, msg);
		break;
	case IUH_PPI_SABP:
	case IUH_PPI_RNA:
	case IUH_PPI_PUA:
		LOGP(DMAIN, LOGL_ERROR, "Unimplemented SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "Unknown SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	}

	msgb_free(msg);
	return rc;
}

static int hnb_iuh_connect_cb(struct osmo_stream_cli *conn)
{
	LOGP(DMAIN, LOGL_NOTICE, "Iuh connected to HNBGW\n");
	struct hnb *hnb = osmo_stream_cli_get_data(conn);

	hnb_send_register_req(hnb);
	return 0;
}

struct hnb *hnb_alloc(void *tall_ctx)
{
	struct hnb *hnb;
	struct osmo_stream_cli *cli;

	hnb = talloc_zero(tall_ctx, struct hnb);
	if (!hnb)
		return NULL;

	hnb->plmn = (struct osmo_plmn_id){
		.mcc = 1,
		.mnc = 1,
	};

	hnb->iuh.local_addr = talloc_strdup(hnb, "0.0.0.0");
	hnb->iuh.local_port = 0;
	hnb->iuh.remote_addr = talloc_strdup(hnb, "127.0.0.1");
	hnb->iuh.remote_port = IUH_DEFAULT_SCTP_PORT;

	cli = osmo_stream_cli_create(hnb);
	OSMO_ASSERT(cli);
	hnb->iuh.client = cli;
	osmo_stream_cli_set_nodelay(cli, true);
	osmo_stream_cli_set_proto(cli, IPPROTO_SCTP);
	osmo_stream_cli_set_reconnect_timeout(cli, 5);
	osmo_stream_cli_set_connect_cb(cli, hnb_iuh_connect_cb);
	osmo_stream_cli_set_read_cb(cli, hnb_iuh_read_cb);
	osmo_stream_cli_set_data(cli, hnb);

	return hnb;
}

void hnb_free(struct hnb *hnb)
{
	if (hnb->iuh.client) {
		osmo_stream_cli_destroy(hnb->iuh.client);
		hnb->iuh.client = NULL;
	}
	talloc_free(hnb);
}

int hnb_connect(struct hnb *hnb)
{
	int rc;

	LOGP(DMAIN, LOGL_INFO, "Iuh Connect: %s[:%u] => %s[:%u]\n",
	     hnb->iuh.local_addr, hnb->iuh.local_port, hnb->iuh.remote_addr, hnb->iuh.remote_port);

	osmo_stream_cli_set_addrs(hnb->iuh.client, (const char**)&hnb->iuh.remote_addr, 1);
	osmo_stream_cli_set_port(hnb->iuh.client, hnb->iuh.remote_port);
	osmo_stream_cli_set_local_addrs(hnb->iuh.client, (const char**)&hnb->iuh.local_addr, 1);
	osmo_stream_cli_set_local_port(hnb->iuh.client, hnb->iuh.local_port);
	rc = osmo_stream_cli_open(hnb->iuh.client);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Unable to open stream client for Iuh %s[:%u] => %s[:%u]\n",
		     hnb->iuh.local_addr, hnb->iuh.local_port, hnb->iuh.remote_addr, hnb->iuh.remote_port);
		/* we don't return error in here because osmo_stream_cli_open()
		   will continue to retry (due to timeout being explicitly set with
		   osmo_stream_cli_set_reconnect_timeout() above) to connect so the error is transient */
	}
	return 0;
}

int hnb_iuh_send(struct hnb *hnb, struct msgb *msg)
{
	osmo_stream_cli_send(hnb->iuh.client, msg);
	return 0;
}
