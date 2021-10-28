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

static int sctp_sock_init(int fd)
{
	struct sctp_event_subscribe event;
	int rc;

	/* subscribe for all events */
	memset((uint8_t *)&event, 1, sizeof(event));
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			&event, sizeof(event));

	return rc;
}

static int hnb_read_cb(struct osmo_fd *fd)
{
	struct hnb *hnb = fd->data;
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
		close(fd->fd);
		osmo_fd_unregister(fd);
		return rc;
	} else if (rc == 0) {
		LOGP(DMAIN, LOGL_INFO, "Connection to HNB closed\n");
		close(fd->fd);
		osmo_fd_unregister(fd);
		fd->fd = -1;

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
		printf("HNBAP message received\n");
		rc = hnb_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		printf("RUA message received\n");
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

static int hnb_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	/* struct hnb *ctx = fd->data; */
	struct sctp_sndrcvinfo sinfo = {
		.sinfo_ppid = htonl(msgb_sctp_ppid(msg)),
		.sinfo_stream = 0,
	};
	int rc;

	printf("Sending: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	rc = sctp_send(fd->fd, msgb_data(msg), msgb_length(msg),
			&sinfo, 0);
	/* we don't need to msgb_free(), write_queue does this for us */
	return rc;
}

struct hnb *hnb_alloc(void *tall_ctx)
{
	struct hnb *hnb;
	hnb = talloc_zero(tall_ctx, struct hnb);
	if (!hnb)
		return NULL;

	hnb->iuh.local_addr = NULL;
	hnb->iuh.local_port = 0;
	hnb->iuh.remote_addr = talloc_strdup(hnb, "127.0.0.1");
	hnb->iuh.remote_port = IUH_DEFAULT_SCTP_PORT;

	osmo_wqueue_init(&hnb->wqueue, 16);
	hnb->wqueue.bfd.data = hnb;
	hnb->wqueue.read_cb = hnb_read_cb;
	hnb->wqueue.write_cb = hnb_write_cb;

	return hnb;
}

int hnb_connect(struct hnb *hnb)
{
	int rc;

	LOGP(DMAIN, LOGL_INFO, "Iuh Connect: %s[:%u] => %s[:%u]\n",
	     hnb->iuh.local_addr, hnb->iuh.local_port, hnb->iuh.remote_addr, hnb->iuh.remote_port);

	rc = osmo_sock_init2_ofd(&hnb->wqueue.bfd, AF_INET, SOCK_STREAM, IPPROTO_SCTP,
			   hnb->iuh.local_addr, hnb->iuh.local_port,
			   hnb->iuh.remote_addr, hnb->iuh.remote_port,
			   OSMO_SOCK_F_BIND |OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;
	sctp_sock_init(hnb->wqueue.bfd.fd);
	return 0;
}
