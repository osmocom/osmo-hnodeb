/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <sys/socket.h>

#include <osmocom/trau/osmo_ortp.h>

#include <osmocom/hnodeb/rtp.h>
#include <osmocom/hnodeb/hnodeb.h>


/* Mixture between osmo_rtp_get_bound_addr and osmo_rtp_get_bound_ip_port using osmo_sockaddr */
/*static int rtp_get_bound_addr(struct osmo_rtp_socket *rs, struct osmo_sockaddr *osa)
{
	int rc;
	socklen_t alen = sizeof(*osa);

	rc = getsockname(rs->rtp_bfd.fd, (struct sockaddr *)&osa->u.sa, &alen);
	if (rc < 0) {
		LOGP(DRTP, LOGL_ERROR, "getsockname(%d) failed: %s\n",
		     rs->rtp_bfd.fd, strerror(errno));
		return rc;
	}
	LOGP(DRTP, LOGL_DEBUG, "rtp socket: %s\n", osmo_sock_get_name2(rs->rtp_bfd.fd));
	return 0;
}*/

/* osmo_rtp_socket_connect() is broken, OS#5356 */
static int rtp_get_bound_addr(struct osmo_rtp_socket *rs, const struct osmo_sockaddr *rem_addr, struct osmo_sockaddr *osa)
{
	int rc;
	uint16_t port;
	socklen_t alen = sizeof(*osa);

	/* First, retrieve bound port using getsockname: */
	rc = getsockname(rs->rtp_bfd.fd, (struct sockaddr *)&osa->u.sa, &alen);
	if (rc < 0)
		return rc;
	switch (osa->u.sa.sa_family) {
	case AF_INET6:
		port = ntohs(osa->u.sin6.sin6_port);
		break;
	case AF_INET:
		port = ntohs(osa->u.sin.sin_port);
		break;
	default:
		return -EINVAL;
	}

	/* osmo_rtp_socket_connect() is broken, OS#5356, so we didn't connect()
	 * and hence local_addr may still be unresolved (0.0.0.0) in the socket.
	 * let's get it from OS regular routing: */
	rc = osmo_sockaddr_local_ip(osa, rem_addr);
	if (rc < 0) {
		LOGP(DRTP, LOGL_ERROR, "osmo_sockaddr_local_ip(%d) failed: err=%d\n",
		     rs->rtp_bfd.fd, -rc);
		return rc;
	}
	/* Copy back the correct port to the returned address: */
	switch (osa->u.sa.sa_family) {
	case AF_INET6:
		osa->u.sin6.sin6_port = htons(port);
		break;
	case AF_INET:
		osa->u.sin.sin_port = htons(port);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int rtp_bind(struct hnb *hnb, struct osmo_rtp_socket *rs, const char *ip)
{
	int rc;
	unsigned int i;
	unsigned int tries;

	tries = (hnb->rtp.port_range_end - hnb->rtp.port_range_start) / 2;
	for (i = 0; i < tries; i++) {

		if (hnb->rtp.port_range_next >= hnb->rtp.port_range_end)
			hnb->rtp.port_range_next = hnb->rtp.port_range_start;

		rc = osmo_rtp_socket_bind(rs, ip, hnb->rtp.port_range_next);

		hnb->rtp.port_range_next += 2;

		if (rc != 0)
			continue;

		if (hnb->rtp.ip_dscp != -1) {
			if (osmo_rtp_socket_set_dscp(rs, hnb->rtp.ip_dscp))
				LOGP(DRTP, LOGL_ERROR, "failed to set DSCP=%d: %s\n",
					hnb->rtp.ip_dscp, strerror(errno));
		}
		if (hnb->rtp.priority != -1) {
			if (osmo_rtp_socket_set_priority(rs, hnb->rtp.priority))
				LOGP(DRTP, LOGL_ERROR, "failed to set socket priority %d: %s\n",
					hnb->rtp.priority, strerror(errno));
		}
		return 0;
	}

	return -1;
}

static void rtp_rx_cb(struct osmo_rtp_socket *rs, const uint8_t *rtp_pl,
	       unsigned int rtp_pl_len, uint16_t seq_number,
	       uint32_t timestamp, bool marker)
{
	struct hnb_ue *ue = (struct hnb_ue *)rs->priv;

	LOGUE(ue, DRTP, LOGL_DEBUG, "Rx RTP seq=%u ts=%u M=%u pl=%p len=%u\n",
	      seq_number, timestamp, marker, rtp_pl, rtp_pl_len);
	llsk_audio_tx_conn_data_ind(ue, rtp_pl, rtp_pl_len);
}

int hnb_ue_voicecall_setup(struct hnb_ue *ue, const struct osmo_sockaddr *rem_addr, struct osmo_sockaddr *loc_addr)
{
	int rc;
	char cname[256+4];
	char name[32];
	struct osmo_rtp_socket *rs;
	const char *local_wildcard_ipstr = "0.0.0.0";
	char remote_ipstr[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	struct hnb *hnb = ue->hnb;

	if (osmo_sockaddr_to_str_and_uint(remote_ipstr, sizeof(remote_ipstr), &remote_port, &rem_addr->u.sa) == 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed parsing remote address!\n");
		return -EINVAL;
	}

	if (ue->conn_cs.rtp.socket) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Setting up rtp socket but it already exists!\n");
		return -EINVAL;
	}

	rs = ue->conn_cs.rtp.socket = osmo_rtp_socket_create(ue, 0);
	rc = osmo_rtp_socket_set_param(rs,
				       hnb->rtp.jitter_adaptive ?
				       OSMO_RTP_P_JIT_ADAP :
				       OSMO_RTP_P_JITBUF,
				       hnb->rtp.jitter_buf_ms);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to set RTP socket parameters: %s\n", strerror(-rc));
		goto free_ret;
	}
	rs->priv = ue;
	rs->rx_cb = &rtp_rx_cb;

	rc = rtp_bind(hnb, rs, local_wildcard_ipstr);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to bind RTP/RTCP sockets\n");
		goto free_ret;
	}

	/* Ensure RTCP SDES contains some useful information */
	snprintf(cname, sizeof(cname), "hnb@%s", local_wildcard_ipstr);
	snprintf(name, sizeof(name), "ue@%u", ue->conn_id);
	osmo_rtp_set_source_desc(rs, cname, name, NULL, NULL, NULL,
				 "OsmoHNodeB-" PACKAGE_VERSION, NULL);

	rc = osmo_rtp_socket_connect(rs, remote_ipstr, remote_port);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to connect RTP/RTCP sockets\n");
		goto free_ret;
	}

	/* osmo_rtp_socket_connect() is broken, OS#5356 */
	//rc = rtp_get_bound_addr(rs, loc_addr);
	rc = rtp_get_bound_addr(rs, rem_addr, loc_addr);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Cannot obtain locally bound IP/port: %d\n", rc);
		goto free_ret;
	}

	return rc;
free_ret:
	osmo_rtp_socket_free(ue->conn_cs.rtp.socket);
	ue->conn_cs.rtp.socket = NULL;
	return rc;
}

int hnb_ue_voicecall_release(struct hnb_ue *ue)
{
	if (!ue->conn_cs.rtp.socket)
		return -EINVAL;
	osmo_rtp_socket_free(ue->conn_cs.rtp.socket);
	ue->conn_cs.rtp.socket = NULL;
	return 0;
}