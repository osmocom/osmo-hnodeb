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

#include <osmocom/trau/osmo_ortp.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/llsk.h>
#include <osmocom/hnodeb/hnb_prim.h>
#include <osmocom/hnodeb/rtp.h>

static size_t llsk_audio_prim_size_tbl[4][_HNB_AUDIO_PRIM_MAX] = {
	[PRIM_OP_REQUEST] = {
		[HNB_AUDIO_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_audio_conn_establish_req_param),
		[HNB_AUDIO_PRIM_CONN_RELEASE] = sizeof(struct hnb_audio_conn_release_req_param),
		[HNB_AUDIO_PRIM_CONN_DATA] = sizeof(struct hnb_audio_conn_data_req_param),
	},
	[PRIM_OP_RESPONSE] = {},
	[PRIM_OP_INDICATION] = {
		[HNB_AUDIO_PRIM_CONN_DATA] = sizeof(struct hnb_audio_conn_data_ind_param),
	},
	[PRIM_OP_CONFIRM] = {
		[HNB_AUDIO_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_audio_conn_establish_cnf_param),
	},
};
static inline size_t llsk_audio_prim_size(enum hnb_audio_prim_type ptype, enum osmo_prim_operation op)
{
	size_t val = llsk_audio_prim_size_tbl[op][ptype];
	if (val == 0) {
		LOGP(DLLSK, LOGL_FATAL, "Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
		osmo_panic("Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
	}
	return val;
}

const struct value_string hnb_audio_prim_type_names[] = {
	OSMO_VALUE_STRING(HNB_AUDIO_PRIM_CONN_ESTABLISH),
	OSMO_VALUE_STRING(HNB_AUDIO_PRIM_CONN_RELEASE),
	OSMO_VALUE_STRING(HNB_AUDIO_PRIM_CONN_DATA),
	{ 0, NULL }
};

static struct hnb_audio_prim *hnb_audio_prim_alloc(enum hnb_audio_prim_type ptype, enum osmo_prim_operation op, size_t extra_len)
{
	struct osmo_prim_hdr *oph;
	size_t len = llsk_audio_prim_size(ptype, op);

	oph = osmo_prim_msgb_alloc(HNB_PRIM_SAPI_AUDIO, ptype, op, sizeof(*oph) + len + extra_len);
	if (!oph)
		return NULL;
	msgb_put(oph->msg, len);

	return (struct hnb_audio_prim *)oph;
}

static struct hnb_audio_prim *hnb_audio_makeprim_conn_establish_cnf(uint32_t context_id, uint8_t error_code,
							     uint16_t local_rtp_port, uint8_t local_rtp_address_type,
							     const union u_addr *local_rtp_addr)
{
	struct hnb_audio_prim *audio_prim;

	audio_prim = hnb_audio_prim_alloc(HNB_AUDIO_PRIM_CONN_ESTABLISH, PRIM_OP_CONFIRM, 0);
	audio_prim->u.conn_establish_cnf.context_id = context_id;
	audio_prim->u.conn_establish_cnf.local_rtp_port = local_rtp_port;
	audio_prim->u.conn_establish_cnf.error_code = error_code;
	audio_prim->u.conn_establish_cnf.local_rtp_address_type = local_rtp_address_type;
	if (local_rtp_addr)
		audio_prim->u.conn_establish_cnf.local_rtp_addr = *local_rtp_addr;

	return audio_prim;
}

static struct hnb_audio_prim *hnb_audio_makeprim_conn_data_ind(uint32_t context_id,
							uint8_t domain,
							const uint8_t *data,
							uint32_t data_len)
{
	struct hnb_audio_prim *audio_prim;

	audio_prim = hnb_audio_prim_alloc(HNB_AUDIO_PRIM_CONN_DATA, PRIM_OP_INDICATION, data_len);
	audio_prim->u.conn_data_ind.context_id = context_id;
	audio_prim->u.conn_data_ind.data_len = data_len;
	if (data_len) {
		msgb_put(audio_prim->hdr.msg, data_len);
		memcpy(audio_prim->u.conn_data_ind.data, data, data_len);
	}

	return audio_prim;
}

int llsk_audio_tx_conn_data_ind(struct hnb_ue *ue, const uint8_t *payload, uint32_t len)
{
	struct hnb_audio_prim *audio_prim;
	int rc;

	LOGUE(ue, DLLSK, LOGL_INFO, "Tx AUDIO-CONN_DATA.ind\n");
	audio_prim = hnb_audio_makeprim_conn_data_ind(ue->conn_id, 0 /* CS */, payload, len);
	if ((rc = osmo_prim_srv_send(ue->hnb->llsk, audio_prim->hdr.msg)) < 0)
		LOGUE(ue, DLLSK, LOGL_ERROR, "Failed sending AUDIO-CONN_DATA.ind\n");
	return rc;
}

static int _send_conn_establish_cnf_failed(struct hnb *hnb, uint32_t context_id, uint8_t error_code)
{
	struct hnb_audio_prim *audio_prim;
	int rc;
	LOGP(DLLSK, LOGL_ERROR, "Tx AUDIO-CONN_ESTABLISH.cnf: ctx=%u error_code=%u\n",
	     context_id, error_code);
	audio_prim = hnb_audio_makeprim_conn_establish_cnf(context_id, error_code, 0, HNB_PRIM_ADDR_TYPE_UNSPEC, NULL);
	if ((rc = osmo_prim_srv_send(hnb->llsk, audio_prim->hdr.msg)) < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Failed sending AUDIO-CONN_ESTABLISH.cnf context_id=%u error_code=%u\n",
		     context_id, error_code);
	}
	return rc;
}

static int llsk_rx_audio_conn_establish_req(struct hnb *hnb, struct hnb_audio_conn_establish_req_param *ce_req)
{
	struct hnb_ue *ue;
	int rc = 0;
	struct hnb_audio_prim *audio_prim;
	int af;
	char rem_addrstr[INET6_ADDRSTRLEN+32];
	struct osmo_sockaddr rem_osa = {0};
	struct osmo_sockaddr loc_osa = {0};
	union u_addr loc_uaddr = {0};
	uint16_t loc_port;

	rc = ll_addr2osa(ce_req->remote_rtp_address_type, &ce_req->remote_rtp_addr, ce_req->remote_rtp_port, &rem_osa);
	if (rc < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: ctx=%u with unexpected address type %u\n",
		     ce_req->context_id, ce_req->remote_rtp_address_type);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 1);
	}
	osmo_sockaddr_to_str_buf(rem_addrstr, sizeof(rem_addrstr), &rem_osa);

	LOGP(DLLSK, LOGL_INFO, "Rx AUDIO-CONN_ESTABLISH.req ctx=%u rem_addr=%s\n",
	     ce_req->context_id, rem_addrstr);

	if ((af = ll_addr_type2af(ce_req->remote_rtp_address_type)) < 0) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: ctx=%u with unexpected address type %u\n",
		     ce_req->context_id, ce_req->remote_rtp_address_type);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 1);
	}

	ue = hnb_find_ue_by_id(hnb, ce_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: UE not found! ctx=%u rem_addr=%s\n",
		     ce_req->context_id, rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 2);
	}
	if (!ue->conn_cs.active) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: CS chan not active! rem_addr=%s\n",
		      rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 3);
	}

	/* Create the socket: */
	if ((rc = hnb_ue_voicecall_setup(ue, &rem_osa, &loc_osa)) < 0) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: Failed to set up audio socket rem_addr=%s\n",
		      rem_addrstr);
		return _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 4);
	}

	/* Convert resulting local address back to LLSK format: */
	if (osa2_ll_addr(&loc_osa, &loc_uaddr,  &loc_port) != ce_req->remote_rtp_address_type) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_ESTABLISH.req: Failed to provide proper local address rem_addr=%s\n",
		      rem_addrstr);
		rc = _send_conn_establish_cnf_failed(hnb, ce_req->context_id, 4);
		goto release_sock;
	}

	/* Submit successful confirmation */
	LOGUE(ue, DLLSK, LOGL_INFO, "Tx AUDIO-CONN_ESTABLISH.cnf: error_code=0 rem_addr=%s loc_addr=%s\n",
	      rem_addrstr, osmo_sockaddr_to_str(&loc_osa));
	audio_prim = hnb_audio_makeprim_conn_establish_cnf(ce_req->context_id, 0, loc_port,
							   ce_req->remote_rtp_address_type, &loc_uaddr);
	if ((rc = osmo_prim_srv_send(hnb->llsk, audio_prim->hdr.msg)) < 0) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Failed sending AUDIO-CONN_ESTABLISH.cnf error_code=0\n");
		goto release_sock;
	}

	return rc;
release_sock:
	hnb_ue_voicecall_release(ue);
	return rc;
}

static int llsk_rx_audio_conn_release_req(struct hnb *hnb, struct hnb_audio_conn_release_req_param *rel_req)
{
	struct hnb_ue *ue;

	LOGP(DLLSK, LOGL_DEBUG, "Rx AUDIO-CONN_RELEASE.req ctx=%u\n", rel_req->context_id);

	ue = hnb_find_ue_by_id(hnb, rel_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_RELEASE.req: UE not found! ctx=%u\n",
		     rel_req->context_id);
		return -EINVAL;
	}
	/* Release RTP socket: */
	return hnb_ue_voicecall_release(ue);
}

static int llsk_rx_audio_conn_data_req(struct hnb *hnb, struct hnb_audio_conn_data_req_param *data_req)
{
	struct hnb_ue *ue;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx AUDIO-CONN_DATA.req ctx=%u data_len=%u\n",
	     data_req->context_id, data_req->data_len);

	ue = hnb_find_ue_by_id(hnb, data_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_DATA.req: UE not found! ctx=%u data_len=%u\n",
		     data_req->context_id, data_req->data_len);
		return -EINVAL;
	}

	/* TODO: transmit data_req->data through RTP/Iu-UP socket */
	rc = osmo_rtp_send_frame_ext(ue->conn_cs.rtp.socket, data_req->data,
				     data_req->data_len, GSM_RTP_DURATION, false);
	if (rc < 0) {
		LOGUE(ue, DLLSK, LOGL_ERROR, "Rx AUDIO-CONN_DATA.req: UE not found! ctx=%u data_len=%u\n",
		     data_req->context_id, data_req->data_len);
	}
	return rc;
}

int llsk_rx_audio(struct hnb *hnb, struct osmo_prim_hdr *oph)
{
	size_t prim_size = llsk_audio_prim_size(oph->primitive, oph->operation);

	if (msgb_length(oph->msg) < prim_size) {
		LOGP(DLLSK, LOGL_ERROR, "Rx AUDIO-%s.%s with length %u < %zu\n",
		     get_value_string(hnb_audio_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg), prim_size);
		return -EINVAL;
	}

	switch (oph->operation) {
	case PRIM_OP_REQUEST:
		switch (oph->primitive) {
		case HNB_AUDIO_PRIM_CONN_ESTABLISH:
			return llsk_rx_audio_conn_establish_req(hnb, (struct hnb_audio_conn_establish_req_param *)msgb_data(oph->msg));
		case HNB_AUDIO_PRIM_CONN_RELEASE:
			return llsk_rx_audio_conn_release_req(hnb, (struct hnb_audio_conn_release_req_param *)msgb_data(oph->msg));
		case HNB_AUDIO_PRIM_CONN_DATA:
			return llsk_rx_audio_conn_data_req(hnb, (struct hnb_audio_conn_data_req_param *)msgb_data(oph->msg));
		default:
			LOGP(DLLSK, LOGL_ERROR, "Rx llsk-audio unknown primitive %u (len=%u)\n",
			     oph->primitive, msgb_length(oph->msg));
			return -EINVAL;
		}
		break;

	case PRIM_OP_RESPONSE:
	case PRIM_OP_INDICATION:
	case PRIM_OP_CONFIRM:
	default:
		LOGP(DLLSK, LOGL_ERROR, "Rx llsk-audio unexpected primitive operation %s::%s (len=%u)\n",
		     get_value_string(hnb_audio_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg));
		return -EINVAL;
	}
}