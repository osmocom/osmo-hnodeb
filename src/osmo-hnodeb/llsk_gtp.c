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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/llsk.h>
#include <osmocom/hnodeb/hnb_prim.h>
#include <osmocom/hnodeb/gtp.h>

static size_t llsk_gtp_prim_size_tbl[4][_HNB_GTP_PRIM_MAX] = {
	[PRIM_OP_REQUEST] = {
		[HNB_GTP_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_gtp_conn_establish_req_param),
		[HNB_GTP_PRIM_CONN_RELEASE] = sizeof(struct hnb_gtp_conn_release_req_param),
		[HNB_GTP_PRIM_CONN_DATA] = sizeof(struct hnb_gtp_conn_data_req_param),
	},
	[PRIM_OP_RESPONSE] = {},
	[PRIM_OP_INDICATION] = {
		[HNB_GTP_PRIM_CONN_DATA] = sizeof(struct hnb_gtp_conn_data_ind_param),
	},
	[PRIM_OP_CONFIRM] = {
		[HNB_GTP_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_gtp_conn_establish_cnf_param),
	},
};
static inline size_t llsk_gtp_prim_size(enum hnb_gtp_prim_type ptype, enum osmo_prim_operation op)
{
	size_t val = llsk_gtp_prim_size_tbl[op][ptype];
	if (val == 0) {
		LOGP(DLLSK, LOGL_FATAL, "Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
		osmo_panic("Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
	}
	return val;
}

const struct value_string hnb_gtp_prim_type_names[] = {
	OSMO_VALUE_STRING(HNB_GTP_PRIM_CONN_ESTABLISH),
	OSMO_VALUE_STRING(HNB_GTP_PRIM_CONN_RELEASE),
	OSMO_VALUE_STRING(HNB_GTP_PRIM_CONN_DATA),
	{ 0, NULL }
};

static struct hnb_gtp_prim *hnb_gtp_prim_alloc(enum hnb_gtp_prim_type ptype, enum osmo_prim_operation op, size_t extra_len)
{
	struct osmo_prim_hdr *oph;
	size_t len = llsk_gtp_prim_size(ptype, op);

	oph = osmo_prim_msgb_alloc(HNB_PRIM_SAPI_GTP, ptype, op, sizeof(*oph) + len + extra_len);
	if (!oph)
		return NULL;
	msgb_put(oph->msg, len);

	return (struct hnb_gtp_prim *)oph;
}

static struct hnb_gtp_prim *hnb_gtp_makeprim_conn_establish_cnf(uint32_t context_id, uint32_t gtp_conn_id,
								uint8_t error_code, uint32_t local_tei,
								uint8_t local_gtpu_address_type,
								const union u_addr *local_gtpu_addr)
{
	struct hnb_gtp_prim *gtp_prim;

	gtp_prim = hnb_gtp_prim_alloc(HNB_GTP_PRIM_CONN_ESTABLISH, PRIM_OP_CONFIRM, 0);
	gtp_prim->u.conn_establish_cnf.context_id = context_id;
	gtp_prim->u.conn_establish_cnf.gtp_conn_id = gtp_conn_id;
	gtp_prim->u.conn_establish_cnf.local_tei = local_tei;
	gtp_prim->u.conn_establish_cnf.error_code = error_code;
	gtp_prim->u.conn_establish_cnf.local_gtpu_address_type = local_gtpu_address_type;
	if (local_gtpu_addr)
		gtp_prim->u.conn_establish_cnf.local_gtpu_addr = *local_gtpu_addr;

	return gtp_prim;
}

struct hnb_gtp_prim *hnb_gtp_makeprim_conn_data_ind(uint32_t gtp_conn_id, const uint8_t *data, uint32_t data_len)
{
	struct hnb_gtp_prim *gtp_prim;

	gtp_prim = hnb_gtp_prim_alloc(HNB_GTP_PRIM_CONN_DATA, PRIM_OP_INDICATION, data_len);
	gtp_prim->u.conn_data_ind.gtp_conn_id = gtp_conn_id;
	gtp_prim->u.conn_data_ind.data_len = data_len;
	if (data_len) {
		msgb_put(gtp_prim->hdr.msg, data_len);
		memcpy(gtp_prim->u.conn_data_ind.data, data, data_len);
	}

	return gtp_prim;
}

static int _send_conn_establish_cnf_failed(struct hnb *hnb, uint32_t context_id, uint8_t error_code)
{
	struct hnb_gtp_prim *gtp_prim;
	int rc;
	LOGP(DLLSK, LOGL_ERROR, "Tx GTP-CONN_ESTABLISH.cnf: ctx=%u error_code=%u\n",
	     context_id, error_code);
	gtp_prim = hnb_gtp_makeprim_conn_establish_cnf(context_id, 0, error_code, 0, HNB_PRIM_ADDR_TYPE_UNSPEC, NULL);
	if ((rc = osmo_prim_srv_send(hnb->llsk.srv, gtp_prim->hdr.msg)) < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Failed sending GTP-CONN_ESTABLISH.cnf context_id=%u error_code=%u\n",
		     context_id, error_code);
	}
	return rc;
}

static int llsk_rx_gtp_conn_establish_req(struct hnb *hnb, struct hnb_gtp_conn_establish_req_param *ce_req)
{
	struct hnb_ue *ue;
	int rc = 0;
	struct hnb_gtp_prim *gtp_prim;
	int af;
	char rem_addrstr[INET6_ADDRSTRLEN+32];
	struct osmo_sockaddr rem_osa = {0};
	union u_addr loc_uaddr = {0};
	struct gtp_conn *conn = NULL;

	rc = ll_addr2osa(ce_req->remote_gtpu_address_type, &ce_req->remote_gtpu_addr, 2152, &rem_osa);
	if (rc < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: ctx=%u with unexpected address type %u\n",
		     ce_req->context_id, ce_req->remote_gtpu_address_type);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 1);
	}
	osmo_sockaddr_to_str_buf(rem_addrstr, sizeof(rem_addrstr), &rem_osa);

	LOGP(DLLSK, LOGL_INFO, "Rx GTP-CONN_ESTABLISH.req ctx=%u rem_tei=%u rem_addr=%s\n",
	     ce_req->context_id, ce_req->remote_tei, rem_addrstr);

	if ((af = ll_addr_type2af(ce_req->remote_gtpu_address_type)) < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: ctx=%u with unexpected address type %u\n",
		     ce_req->context_id, ce_req->remote_gtpu_address_type);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 1);
	}

	ue = hnb_find_ue_by_id(hnb, ce_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: UE not found! ctx=%u rem_addr=%s\n",
		     ce_req->context_id, rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 2);
	}
	if (!ue->conn_ps.active) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: PS chan not active! rem_addr=%s\n",
		      rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 3);
	}

	/* Create the socket: */
	conn = gtp_conn_alloc(ue);
	if (!conn)
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 4);

	if ((rc = gtp_conn_setup(conn, &rem_osa, ce_req->remote_tei)) < 0) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: Failed to set up gtp socket rem_tei=%u rem_addr=%s\n",
		     ce_req->remote_tei, rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 4);
	}

	/* Convert resulting local address back to LLSK format: */
	if (osa2_ll_addr(&conn->loc_addr, &loc_uaddr,  NULL) != ce_req->remote_gtpu_address_type) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx GTP-CONN_ESTABLISH.req: Failed to provide proper local address rem_addr=%s\n",
		      rem_addrstr);
		rc = _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 4);
		goto release_sock;
	}

	/* Submit successful confirmation */
	LOGUE(ue, DLLSK, LOGL_INFO, "Tx GTP-CONN_ESTABLISH.cnf: error_code=0 rem_addr=%s rem_tei=%u loc_addr=%s local_tei=%u\n",
	     rem_addrstr, ce_req->remote_tei, osmo_sockaddr_to_str(&conn->loc_addr), conn->loc_tei);
	gtp_prim = hnb_gtp_makeprim_conn_establish_cnf(ce_req->context_id, conn->id, 0, conn->loc_tei,
						       ce_req->remote_gtpu_address_type, &loc_uaddr);
	if ((rc = osmo_prim_srv_send(hnb->llsk.srv, gtp_prim->hdr.msg)) < 0) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Failed sending GTP-CONN_ESTABLISH.cnf error_code=0\n");
		goto release_sock;
	}
	return rc;
release_sock:
	gtp_conn_free(conn);
	return rc;
}

static int llsk_rx_gtp_conn_release_req(struct hnb *hnb, struct hnb_gtp_conn_release_req_param *rel_req)
{
	struct gtp_conn *conn;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx GTP-CONN_RELEASE.req id=%u\n", rel_req->gtp_conn_id);

	conn = hnb_find_gtp_conn_by_id(hnb, rel_req->gtp_conn_id);
	if (!conn) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-CONN_RELEASE.req: GTP conn not found! id=%u\n",
		     rel_req->gtp_conn_id);
		return -EINVAL;
	}
	/* release GTP pdp ctx: */
	gtp_conn_free(conn);
	return rc;
}

static int llsk_rx_gtp_conn_data_req(struct hnb *hnb, struct hnb_gtp_conn_data_req_param *data_req)
{
	struct gtp_conn *conn;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx GTP-CONN_DATA.req id=%u data_len=%u\n",
	     data_req->gtp_conn_id, data_req->data_len);

	conn = hnb_find_gtp_conn_by_id(hnb, data_req->gtp_conn_id);
	if (!conn) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-CONN_DATA.req: GTP conn not found! id=%u data_len=%u\n",
		     data_req->gtp_conn_id, data_req->data_len);
		return -EINVAL;
	}

	rc = gtp_conn_tx(conn, data_req->data, data_req->data_len);
	return rc;
}

int llsk_rx_gtp(struct hnb *hnb, struct osmo_prim_hdr *oph)
{
	size_t prim_size = llsk_gtp_prim_size(oph->primitive, oph->operation);

	if (msgb_length(oph->msg) < prim_size) {
		LOGP(DLLSK, LOGL_ERROR, "Rx GTP-%s.%s with length %u < %zu\n",
		     get_value_string(hnb_gtp_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg), prim_size);
		return -EINVAL;
	}

	switch (oph->operation) {
	case PRIM_OP_REQUEST:
		switch (oph->primitive) {
		case HNB_GTP_PRIM_CONN_ESTABLISH:
			return llsk_rx_gtp_conn_establish_req(hnb, (struct hnb_gtp_conn_establish_req_param *)msgb_data(oph->msg));
		case HNB_GTP_PRIM_CONN_RELEASE:
			return llsk_rx_gtp_conn_release_req(hnb, (struct hnb_gtp_conn_release_req_param *)msgb_data(oph->msg));
		case HNB_GTP_PRIM_CONN_DATA:
			return llsk_rx_gtp_conn_data_req(hnb, (struct hnb_gtp_conn_data_req_param *)msgb_data(oph->msg));
		default:
			LOGP(DLLSK, LOGL_ERROR, "Rx llsk-gtp unknown primitive %u (len=%u)\n",
			     oph->primitive, msgb_length(oph->msg));
			return -EINVAL;
		}
		break;

	case PRIM_OP_RESPONSE:
	case PRIM_OP_INDICATION:
	case PRIM_OP_CONFIRM:
	default:
		LOGP(DLLSK, LOGL_ERROR, "Rx llsk-gtp unexpected primitive operation %s::%s (len=%u)\n",
		     get_value_string(hnb_gtp_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg));
		return -EINVAL;
	}
}
