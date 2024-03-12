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
#include <osmocom/netif/sctp.h>

#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/hnb_shutdown_fsm.h>

static int get_logevel_by_sn_type(int sn_type)
{
	switch (sn_type) {
	case SCTP_ADAPTATION_INDICATION:
	case SCTP_PEER_ADDR_CHANGE:
#ifdef SCTP_AUTHENTICATION_INDICATION
	case SCTP_AUTHENTICATION_INDICATION:
#endif
#ifdef SCTP_SENDER_DRY_EVENT
	case SCTP_SENDER_DRY_EVENT:
#endif
		return LOGL_INFO;
	case SCTP_ASSOC_CHANGE:
		return LOGL_NOTICE;
	case SCTP_SHUTDOWN_EVENT:
	case SCTP_PARTIAL_DELIVERY_EVENT:
		return LOGL_NOTICE;
	case SCTP_SEND_FAILED:
	case SCTP_REMOTE_ERROR:
		return LOGL_ERROR;
	default:
		return LOGL_NOTICE;
	}
}

static void log_sctp_notification(union sctp_notification *notif)
{
	int log_level;

	LOGP(DSCTP, LOGL_INFO, "Iuh SCTP NOTIFICATION %u flags=0x%0x\n",
	     notif->sn_header.sn_type, notif->sn_header.sn_flags);

	log_level = get_logevel_by_sn_type(notif->sn_header.sn_type);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		LOGP(DSCTP, log_level, "Iuh SCTP_ASSOC_CHANGE: %s\n",
		     osmo_sctp_assoc_chg_str(notif->sn_assoc_change.sac_state));
		break;
	default:
		LOGP(DSCTP, log_level, "Iuh %s\n",
		     osmo_sctp_sn_type_str(notif->sn_header.sn_type));
		break;
	}
}

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
		LOGP(DSCTP, LOGL_ERROR, "Error during sctp_recvmsg()\n");
		osmo_stream_cli_close(conn);
		hnb_shutdown(hnb, "sctp_recvmsg() error", false);
		goto free_ret;
	} else if (rc == 0) {
		LOGP(DSCTP, LOGL_INFO, "Connection to HNBGW closed\n");
		osmo_stream_cli_close(conn);
		hnb_shutdown(hnb, "Iuh HNBGW conn closed", false);
		rc = -1;
		goto free_ret;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		log_sctp_notification(notif);
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_fsm_inst_dispatch(hnb->shutdown_fi, HNB_SHUTDOWN_EV_START, NULL);
			hnb_shutdown(hnb, "Iuh HNBGW conn notification (SCTP_SHUTDOWN_EVENT)", false);
			break;
		default:
			break;
		}
		rc = 0;
		goto free_ret;
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
		LOGP(DSCTP, LOGL_ERROR, "Unimplemented SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	default:
		LOGP(DSCTP, LOGL_ERROR, "Unknown SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	}

free_ret:
	msgb_free(msg);
	return rc;
}

static int hnb_iuh_connect_cb(struct osmo_stream_cli *conn)
{
	LOGP(DSCTP, LOGL_NOTICE, "Iuh connected to HNBGW\n");
	struct hnb *hnb = osmo_stream_cli_get_data(conn);

	hnb_send_register_req(hnb);
	return 0;
}

void hnb_iuh_alloc(struct hnb *hnb)
{
	struct osmo_stream_cli *cli;

	hnb->iuh.local_addr = talloc_strdup(hnb, "0.0.0.0");
	hnb->iuh.local_port = 0;
	hnb->iuh.remote_addr = talloc_strdup(hnb, "127.0.0.1");
	hnb->iuh.remote_port = IUH_DEFAULT_SCTP_PORT;

	cli = osmo_stream_cli_create(hnb);
	OSMO_ASSERT(cli);
	hnb->iuh.client = cli;
	osmo_stream_cli_set_name(cli, "Iuh");
	osmo_stream_cli_set_nodelay(cli, true);
	osmo_stream_cli_set_proto(cli, IPPROTO_SCTP);
	osmo_stream_cli_set_reconnect_timeout(cli, 5);
	osmo_stream_cli_set_connect_cb(cli, hnb_iuh_connect_cb);
	osmo_stream_cli_set_read_cb(cli, hnb_iuh_read_cb);
	osmo_stream_cli_set_data(cli, hnb);
}

void hnb_iuh_free(struct hnb *hnb)
{
	if (!hnb->iuh.client)
		return;
	osmo_stream_cli_destroy(hnb->iuh.client);
	hnb->iuh.client = NULL;
}

int hnb_iuh_connect(struct hnb *hnb)
{
	int rc;

	LOGP(DSCTP, LOGL_INFO, "Iuh Connect: %s[:%u] => %s[:%u]\n",
	     hnb->iuh.local_addr, hnb->iuh.local_port, hnb->iuh.remote_addr, hnb->iuh.remote_port);

	osmo_stream_cli_set_addrs(hnb->iuh.client, (const char **)&hnb->iuh.remote_addr, 1);
	osmo_stream_cli_set_port(hnb->iuh.client, hnb->iuh.remote_port);
	osmo_stream_cli_set_local_addrs(hnb->iuh.client, (const char **)&hnb->iuh.local_addr, 1);
	osmo_stream_cli_set_local_port(hnb->iuh.client, hnb->iuh.local_port);
	rc = osmo_stream_cli_open(hnb->iuh.client);
	if (rc < 0) {
		LOGP(DSCTP, LOGL_ERROR, "Unable to open stream client for Iuh %s[:%u] => %s[:%u]\n",
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
