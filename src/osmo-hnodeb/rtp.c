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

#include <osmocom/gsm/prim.h>
#include <osmocom/gsm/iuup.h>
#include <osmocom/trau/osmo_ortp.h>

#include <osmocom/hnodeb/rtp.h>
#include <osmocom/hnodeb/hnodeb.h>

#define HNB_IUUP_MSGB_SIZE 4096

static struct osmo_iuup_rnl_prim *llsk_audio_ce_to_iuup_rnl_cfg(struct rtp_conn *conn, const struct hnb_audio_conn_establish_req_param *ce_req)
{
	struct osmo_iuup_rnl_prim *irp;
	struct osmo_iuup_rnl_config *cfg;
	unsigned int i;
	const struct hnb_audio_conn_establish_req_param_v0 *v0 = &ce_req->v0;
	const struct hnb *hnb = conn->ue->hnb;

	irp = osmo_iuup_rnl_prim_alloc(conn, OSMO_IUUP_RNL_CONFIG, PRIM_OP_REQUEST, HNB_IUUP_MSGB_SIZE);
	cfg = &irp->u.config;
	cfg->transparent = !!v0->transparent;
	cfg->active = true;
	cfg->data_pdu_type = v0->data_pdu_type;
	cfg->supported_versions_mask = v0->supported_versions_mask;
	cfg->num_rfci = v0->num_rfci;
	cfg->num_subflows = v0->num_subflows;
	cfg->IPTIs_present = v0->IPTIs_present;
	OSMO_ASSERT(cfg->num_rfci <= ARRAY_SIZE(cfg->rfci));
	OSMO_ASSERT(cfg->num_subflows <= ARRAY_SIZE(cfg->rfci[0].subflow_sizes));
	for (i = 0; i < cfg->num_rfci; i++) {
		cfg->rfci[i].used = true;
		/* llsk_audio v0 doesn't provide info, assume RFC ID from position: */
		cfg->rfci[i].id = (hnb->llsk.sapi_version_audio > 0) ? ce_req->v1.rfci[i] : i;
		if (cfg->IPTIs_present)
			cfg->rfci[i].IPTI = v0->IPTIs[i];
		if (cfg->num_subflows > 0)
			memcpy(&cfg->rfci[i].subflow_sizes[0], &v0->subflow_sizes[i][0], cfg->num_subflows*sizeof(uint16_t));
	}

	cfg->t_init = (struct osmo_iuup_rnl_config_timer){ .t_ms = IUUP_TIMER_INIT_T_DEFAULT, .n_max = IUUP_TIMER_INIT_N_DEFAULT };
	cfg->t_ta   = (struct osmo_iuup_rnl_config_timer){ .t_ms = IUUP_TIMER_TA_T_DEFAULT, .n_max = IUUP_TIMER_TA_N_DEFAULT };
	cfg->t_rc   = (struct osmo_iuup_rnl_config_timer){ .t_ms = IUUP_TIMER_RC_T_DEFAULT, .n_max = IUUP_TIMER_RC_N_DEFAULT };

	return irp;
}

static int _iuup_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct rtp_conn *conn = (struct rtp_conn *)ctx;
	struct osmo_iuup_rnl_prim *irp = (struct osmo_iuup_rnl_prim *)oph;
	struct msgb *msg = oph->msg;
	int rc;

	switch (OSMO_PRIM_HDR(&irp->oph)) {
	case OSMO_PRIM(OSMO_IUUP_RNL_DATA, PRIM_OP_INDICATION):
		rc = llsk_audio_tx_conn_data_ind(conn, irp->u.data.frame_nr, irp->u.data.fqc,
						 irp->u.data.rfci, msgb_l3(msg), msgb_l3len(msg));
		break;
	default:
		LOGUE(conn->ue, DRTP, LOGL_NOTICE, "Rx Unknown prim=%u op=%u from IuUP layer",
		      irp->oph.primitive, irp->oph.operation);
		rc = -1;
	}

	msgb_free(msg);
	return rc;
}

static int _iuup_transport_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct rtp_conn *conn = (struct rtp_conn *)ctx;
	struct msgb *msg = oph->msg;
	int rc;

	rc = osmo_rtp_send_frame_ext(conn->socket, msgb_l2(msg), msgb_l2len(msg),
				     GSM_RTP_DURATION, false);
	if (rc < 0) {
		LOGUE(conn->ue, DLLSK, LOGL_ERROR,
		      "Rx IuUP Transport UNITDATA.req: Failed sending RTP frame! id=%u data_len=%u\n",
		      conn->id, msgb_l2len(msg));
	}

	msgb_free(msg);
	return rc;
}

struct rtp_conn *rtp_conn_alloc(struct hnb_ue *ue)
{
	struct rtp_conn *conn;
	char iuup_id[64];

	conn = talloc_zero(ue, struct rtp_conn);
	if (!conn)
		return NULL;

	conn->ue = ue;

	snprintf(iuup_id, sizeof(iuup_id), "ue-%u", conn->ue->conn_id);
	conn->iui = osmo_iuup_instance_alloc(conn, iuup_id);
	osmo_iuup_instance_set_user_prim_cb(conn->iui, _iuup_user_prim_cb, conn);
	osmo_iuup_instance_set_transport_prim_cb(conn->iui, _iuup_transport_prim_cb, conn);

	llist_add(&conn->list, &ue->conn_cs.conn_list);

	return conn;
}

void rtp_conn_free(struct rtp_conn *conn)
{
	if (!conn)
		return;

	if (conn->socket) {
		osmo_rtp_socket_free(conn->socket);
		conn->socket = NULL;
	}
	if (conn->iui) {
		osmo_iuup_instance_free(conn->iui);
		conn->iui = NULL;
	}
	llist_del(&conn->list);
	talloc_free(conn);
}

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
		uint16_t port;

		if (hnb->rtp.port_range_next >= hnb->rtp.port_range_end)
			hnb->rtp.port_range_next = hnb->rtp.port_range_start;

		port = hnb->rtp.port_range_next;
		rc = osmo_rtp_socket_bind(rs, ip, port);

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
		return port;
	}

	return -1;
}

static void rtp_rx_cb(struct osmo_rtp_socket *rs, const uint8_t *rtp_pl,
	       unsigned int rtp_pl_len, uint16_t seq_number,
	       uint32_t timestamp, bool marker)
{
	struct rtp_conn *conn = (struct rtp_conn *)rs->priv;
	struct osmo_iuup_tnl_prim *itp;
	int rc;

	LOGUE(conn->ue, DRTP, LOGL_DEBUG, "Rx RTP seq=%u ts=%u M=%u pl=%p len=%u\n",
	      seq_number, timestamp, marker, rtp_pl, rtp_pl_len);

	itp = osmo_iuup_tnl_prim_alloc(conn, OSMO_IUUP_TNL_UNITDATA, PRIM_OP_INDICATION, HNB_IUUP_MSGB_SIZE);
	itp->oph.msg->l2h = msgb_put(itp->oph.msg, rtp_pl_len);
	memcpy(itp->oph.msg->l2h, rtp_pl, rtp_pl_len);
	rc = osmo_iuup_tnl_prim_up(conn->iui, itp);
	if (rc < 0)
		LOGUE(conn->ue, DRTP, LOGL_NOTICE,
		      "Failed passing rx rtp up to IuUP layer: %d\n", rc);
}

int rtp_conn_setup(struct rtp_conn *conn, const struct osmo_sockaddr *rem_addr,
		   const struct hnb_audio_conn_establish_req_param *ce_req)
{
	int rc;
	char cname[256+4];
	char name[32];
	struct osmo_rtp_socket *rs;
	const char *local_wildcard_ipstr = "0.0.0.0";
	char remote_ipstr[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	struct osmo_iuup_rnl_prim *irp;
	struct hnb_ue *ue = conn->ue;
	struct hnb *hnb = ue->hnb;

	if (osmo_sockaddr_to_str_and_uint(remote_ipstr, sizeof(remote_ipstr), &remote_port, &rem_addr->u.sa) == 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed parsing remote address!\n");
		return -EINVAL;
	}

	conn->rem_addr = *rem_addr;

	rs = conn->socket = osmo_rtp_socket_create(ue, 0);
	rc = osmo_rtp_socket_set_param(rs,
				       hnb->rtp.jitter_adaptive ?
				       OSMO_RTP_P_JIT_ADAP :
				       OSMO_RTP_P_JITBUF,
				       hnb->rtp.jitter_buf_ms);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to set RTP socket parameters: %s\n", strerror(-rc));
		goto free_ret;
	}
	/* TS 25.414 Section 5.1.3.3.1.6: A dynamic Payload Type (IETF RFC 1890
	 * [23]) shall be used. Values in the Range between 96 and 127 shall be
	 * used. The value shall be ignored in the receiving entity. */
	rc = osmo_rtp_socket_set_pt(rs, 96);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to set RTP socket Payload-Type 96\n");
		/* Continue, the other side is anyway ignoring it... */
	}
	rs->priv = conn;
	rs->rx_cb = &rtp_rx_cb;

	rc = rtp_bind(hnb, rs, local_wildcard_ipstr);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to bind RTP/RTCP sockets\n");
		goto free_ret;
	}
	conn->id = rc; /* We use local port as rtp conn ID */

	/* Ensure RTCP SDES contains some useful information */
	snprintf(cname, sizeof(cname), "hnb@%s", local_wildcard_ipstr);
	snprintf(name, sizeof(name), "ue@%u-%u", conn->ue->conn_id, conn->id);
	osmo_rtp_set_source_desc(rs, cname, name, NULL, NULL, NULL,
				 "OsmoHNodeB-" PACKAGE_VERSION, NULL);

	rc = osmo_rtp_socket_connect(rs, remote_ipstr, remote_port);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed to connect RTP/RTCP sockets\n");
		goto free_ret;
	}

	/* osmo_rtp_socket_connect() is broken, OS#5356 */
	//rc = rtp_get_bound_addr(rs, &conn->loc_addr);
	rc = rtp_get_bound_addr(rs, rem_addr, &conn->loc_addr);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Cannot obtain locally bound IP/port: %d\n", rc);
		goto free_ret;
	}

	/* Now configure the IuUP layer: */
	irp = llsk_audio_ce_to_iuup_rnl_cfg(conn, ce_req);
	rc = osmo_iuup_rnl_prim_down(conn->iui, irp);
	if (rc < 0) {
		LOGUE(ue, DRTP, LOGL_ERROR, "Failed setting up IuUP layer: %d\n", rc);
		goto free_ret;
	}

	return rc;
free_ret:
	osmo_rtp_socket_free(conn->socket);
	conn->socket = NULL;
	return rc;
}

int rtp_conn_tx_data(struct rtp_conn *conn, uint8_t frame_nr, uint8_t fqc, uint8_t rfci, const uint8_t *data, unsigned int data_len)
{
	struct osmo_iuup_rnl_prim *irp;

	irp = osmo_iuup_rnl_prim_alloc(conn, OSMO_IUUP_RNL_DATA, PRIM_OP_REQUEST, HNB_IUUP_MSGB_SIZE);
	irp->u.data.rfci = rfci;
	irp->u.data.frame_nr = frame_nr;
	irp->u.data.fqc = fqc;
	irp->oph.msg->l3h = msgb_put(irp->oph.msg, data_len);
	memcpy(irp->oph.msg->l3h, data, data_len);
	return osmo_iuup_rnl_prim_down(conn->iui, irp);
}
