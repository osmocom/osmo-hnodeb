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
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <inttypes.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include <osmocom/rua/rua_msg_factory.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/llsk.h>
#include <osmocom/hnodeb/hnb_prim.h>
#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/ranap.h>

static size_t llsk_iuh_prim_size_tbl[4][_HNB_IUH_PRIM_MAX] = {
	[PRIM_OP_REQUEST] = {
		[HNB_IUH_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_iuh_conn_establish_req_param),
		[HNB_IUH_PRIM_CONN_RELEASE] = sizeof(struct hnb_iuh_conn_release_req_param),
		[HNB_IUH_PRIM_CONN_DATA] = sizeof(struct hnb_iuh_conn_data_req_param),
		[HNB_IUH_PRIM_UNITDATA] = sizeof(struct hnb_iuh_unitdata_req_param),
	},
	[PRIM_OP_RESPONSE] = {},
	[PRIM_OP_INDICATION] = {
		[HNB_IUH_PRIM_CONFIGURE] = sizeof(struct hnb_iuh_configure_ind_param),
		[HNB_IUH_PRIM_CONN_DATA] = sizeof(struct hnb_iuh_conn_data_ind_param),
		[HNB_IUH_PRIM_UNITDATA] = sizeof(struct hnb_iuh_unitdata_ind_param),
	},
	[PRIM_OP_CONFIRM] = {
		[HNB_IUH_PRIM_CONN_ESTABLISH] = sizeof(struct hnb_iuh_conn_establish_cnf_param),
	},
};
static inline size_t llsk_iuh_prim_size(enum hnb_iuh_prim_type ptype, enum osmo_prim_operation op)
{
	size_t val = llsk_iuh_prim_size_tbl[op][ptype];
	if (val == 0) {
		LOGP(DLLSK, LOGL_FATAL, "Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
		osmo_panic("Expected prim_size != 0 for ptype=%u op=%u\n", ptype, op);
	}
	return val;
}

const struct value_string hnb_iuh_prim_type_names[] = {
	OSMO_VALUE_STRING(HNB_IUH_PRIM_CONFIGURE),
	OSMO_VALUE_STRING(HNB_IUH_PRIM_CONN_ESTABLISH),
	OSMO_VALUE_STRING(HNB_IUH_PRIM_CONN_RELEASE),
	OSMO_VALUE_STRING(HNB_IUH_PRIM_CONN_DATA),
	{ 0, NULL }
};


struct hnb_iuh_prim *hnb_iuh_prim_alloc(enum hnb_iuh_prim_type ptype, enum osmo_prim_operation op, size_t extra_len)
{
	struct osmo_prim_hdr *oph;
	size_t len = llsk_iuh_prim_size(ptype, op);

	oph = osmo_prim_msgb_alloc(HNB_PRIM_SAPI_IUH, ptype, op, sizeof(*oph) + len + extra_len);
	if (!oph)
		return NULL;
	msgb_put(oph->msg, len);

	return (struct hnb_iuh_prim *)oph;
}

struct hnb_iuh_prim *hnb_iuh_makeprim_configure_ind(uint16_t mcc, uint16_t mnc,
						   uint16_t cell_identity,
						   uint16_t lac, uint8_t rac,
						   uint16_t sac, uint16_t rnc_id)
{
	struct hnb_iuh_prim *iuh_prim;

	iuh_prim = hnb_iuh_prim_alloc(HNB_IUH_PRIM_CONFIGURE, PRIM_OP_INDICATION, 0);
	iuh_prim->u.configure_ind.mcc = mcc;
	iuh_prim->u.configure_ind.mnc = mnc;
	iuh_prim->u.configure_ind.cell_identity = cell_identity;
	iuh_prim->u.configure_ind.lac = lac;
	iuh_prim->u.configure_ind.rac = rac;
	iuh_prim->u.configure_ind.sac = sac;
	iuh_prim->u.configure_ind.rnc_id = rnc_id;

	return iuh_prim;
}

int llsk_iuh_tx_configure_ind(struct hnb *hnb)
{
	struct hnb_iuh_prim *iuh_prim;
	int rc;

	LOGP(DLLSK, LOGL_INFO, "Tx IUH-CONFIGURE.ind\n");
	/* We are already registered, so configure the lower layers right now */
	iuh_prim = hnb_iuh_makeprim_configure_ind(hnb->plmn.mcc, hnb->plmn.mnc,
						  hnb->cell_identity, hnb->lac,
						  hnb->rac, hnb->sac, hnb->rnc_id);
	if ((rc = osmo_prim_srv_send(hnb->llsk.srv, iuh_prim->hdr.msg)) < 0)
		LOGP(DLLSK, LOGL_ERROR, "Failed sending IUH-CONFIGURE.ind\n");
	return rc;
}

struct hnb_iuh_prim *hnb_iuh_makeprim_conn_establish_cnf(uint32_t context_id, uint8_t domain,
						 uint8_t cause)
{
	struct hnb_iuh_prim *iuh_prim;

	iuh_prim = hnb_iuh_prim_alloc(HNB_IUH_PRIM_CONN_ESTABLISH, PRIM_OP_CONFIRM, 0);
	iuh_prim->u.conn_establish_cnf.context_id = context_id;
	iuh_prim->u.conn_establish_cnf.domain = domain;
	iuh_prim->u.conn_establish_cnf.cause = cause;

	return iuh_prim;
}

struct hnb_iuh_prim *hnb_iuh_makeprim_conn_data_ind(uint32_t context_id,
					    uint8_t domain,
					    const uint8_t *data,
					    uint32_t data_len)
{
	struct hnb_iuh_prim *iuh_prim;

	iuh_prim = hnb_iuh_prim_alloc(HNB_IUH_PRIM_CONN_DATA, PRIM_OP_INDICATION, data_len);
	iuh_prim->u.conn_data_ind.context_id = context_id;
	iuh_prim->u.conn_data_ind.domain = domain;
	iuh_prim->u.conn_data_ind.data_len = data_len;
	if (data_len) {
		msgb_put(iuh_prim->hdr.msg, data_len);
		memcpy(iuh_prim->u.conn_data_ind.data, data, data_len);
	}

	return iuh_prim;
}

struct hnb_iuh_prim *hnb_iuh_makeprim_unitdata_ind(const uint8_t *data, uint32_t data_len)
{
	struct hnb_iuh_prim *iuh_prim;

	iuh_prim = hnb_iuh_prim_alloc(HNB_IUH_PRIM_UNITDATA, PRIM_OP_INDICATION, data_len);
	iuh_prim->u.unitdata_ind.data_len = data_len;
	if (data_len) {
		msgb_put(iuh_prim->hdr.msg, data_len);
		memcpy(iuh_prim->u.unitdata_ind.data, data, data_len);
	}

	return iuh_prim;
}

static int llsk_rx_iuh_conn_establish_req(struct hnb *hnb, struct hnb_iuh_conn_establish_req_param *ce_req)
{
	struct hnb_ue *ue;
	int rc = 0;

	LOGP(DLLSK, LOGL_INFO, "Rx IUH-CONN_ESTABLISH.req ctx=%u is_ps=%u est_cause=%u data_len=%u\n",
	     ce_req->context_id, ce_req->domain, ce_req->est_cause, ce_req->data_len);

	if (!hnb->registered) {
		LOGP(DLLSK, LOGL_NOTICE, "Ignoring Rx IUH-CONN_ESTABLISH.req: HNB not registered to HNBGW!\n");
		/* TODO: NACK it to lower layers */
		return -EINVAL;
	}

	ue = hnb_find_ue_by_id(hnb, ce_req->context_id);
	if (!ue) {
		ue = hnb_ue_alloc(hnb, ce_req->context_id);
		if (ce_req->domain) {
			ue->conn_ps.active = true;
			ue->conn_ps.conn_est_cnf_pending = true; /* Set to false once we receive first DT from HNBGW and send CONN_EST.cnf */

		} else {
			ue->conn_cs.active = true;
			ue->conn_cs.conn_est_cnf_pending = true; /* Set to false once we receive first DT from HNBGW and send CONN_EST.cnf */
		}
	}
	if (ce_req->data_len) {
		struct msgb *rua_msg;
		struct msgb *ranap_msg = hnb_ranap_msgb_alloc();
		LOGP(DRUA, LOGL_DEBUG, "Tx RUA CONNECT ctx=%u is_ps=%u data_len=%u\n",
		     ce_req->context_id, ce_req->domain, ce_req->data_len);
		memcpy(msgb_put(ranap_msg, ce_req->data_len), ce_req->data, ce_req->data_len);
		rua_msg = rua_new_conn(ce_req->domain, ce_req->context_id, ranap_msg);
		hnb_iuh_send(hnb, rua_msg);
	}

	return rc;
}

static int llsk_rx_iuh_conn_release_req(struct hnb *hnb, struct hnb_iuh_conn_release_req_param *rel_req)
{
	struct hnb_ue *ue;
	struct msgb *rua_msg;
	struct msgb *ranap_msg;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx IUH-CONN_RELEASE.req ctx=%u is_ps=%u data_len=%u\n",
	     rel_req->context_id, rel_req->domain, rel_req->data_len);

	if (!hnb->registered) {
		LOGP(DLLSK, LOGL_NOTICE, "Rx IUH-CONN_RELEASE.req: Ignoring, HNB not registered to HNBGW!\n");
		return -EINVAL;
	}

	ue = hnb_find_ue_by_id(hnb, rel_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx IUH-CONN_RELEASE.req: conn unknown! ctx=%u is_ps=%u data_len=%u\n",
		     rel_req->context_id, rel_req->domain, rel_req->data_len);
		return -EINVAL;
	}
	hnb_ue_reset_chan(ue, !!rel_req->domain);
	if (!ue->conn_cs.active && !ue->conn_ps.active) {
		hnb_ue_free(ue);
		ue = NULL;
	}

	LOGP(DRUA, LOGL_DEBUG, "Tx RUA DISC ctx=%u is_ps=%u data_len=%u\n",
	     rel_req->context_id, rel_req->domain, rel_req->data_len);
	ranap_msg = hnb_ranap_msgb_alloc();
	if (rel_req->data_len)
		memcpy(msgb_put(ranap_msg, rel_req->data_len), rel_req->data, rel_req->data_len);

	rua_msg = rua_new_disc(rel_req->domain, rel_req->context_id, ranap_msg);
	hnb_iuh_send(hnb, rua_msg);
	return rc;
}

static int llsk_rx_iuh_conn_data_req(struct hnb *hnb, struct hnb_iuh_conn_data_req_param *data_req)
{
	struct hnb_ue *ue;
	struct msgb *rua_msg;
	struct msgb *ranap_msg;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx IUH-CONN_DATA.req ctx=%u is_ps=%u data_len=%u\n",
	     data_req->context_id, data_req->domain, data_req->data_len);

	if (!hnb->registered) {
		LOGP(DLLSK, LOGL_NOTICE, "Rx IUH-CONN_DATA.req: Ignoring, HNB not registered to HNBGW!\n");
		/* TODO: NACK it to lower layers */
		return -EINVAL;
	}

	ue = hnb_find_ue_by_id(hnb, data_req->context_id);
	if (!ue) {
		LOGP(DLLSK, LOGL_ERROR, "Rx IUH-CONN_DATA.req: conn unknown! ctx=%u is_ps=%u data_len=%u\n",
		     data_req->context_id, data_req->domain, data_req->data_len);
		/* TODO: NACK it to lower layers */
		return -EINVAL;
	}

	LOGP(DRUA, LOGL_DEBUG, "Tx RUA DT ctx=%u is_ps=%u data_len=%u\n",
	     data_req->context_id, data_req->domain, data_req->data_len);
	ranap_msg = hnb_ranap_msgb_alloc();
	if (data_req->data_len)
		memcpy(msgb_put(ranap_msg, data_req->data_len), data_req->data, data_req->data_len);

	rua_msg = rua_new_dt(data_req->domain, data_req->context_id, ranap_msg);
	hnb_iuh_send(hnb, rua_msg);
	return rc;
}

static int llsk_rx_iuh_unitdata_req(struct hnb *hnb, struct hnb_iuh_unitdata_req_param *ud_req)
{
	struct msgb *rua_msg;
	struct msgb *ranap_msg;
	int rc = 0;

	LOGP(DLLSK, LOGL_DEBUG, "Rx IUH-UNITDATA.req data_len=%u\n", ud_req->data_len);

	if (!hnb->registered) {
		LOGP(DLLSK, LOGL_NOTICE, "Rx IUH-UNITDATA.req: Ignoring, HNB not registered to HNBGW!\n");
		return -EINVAL;
	}

	LOGP(DRUA, LOGL_DEBUG, "Tx RUA UDT data_len=%u\n", ud_req->data_len);

	ranap_msg = hnb_ranap_msgb_alloc();
	if (ud_req->data_len)
		memcpy(msgb_put(ranap_msg, ud_req->data_len), ud_req->data, ud_req->data_len);

	rua_msg = rua_new_udt(ranap_msg);
	hnb_iuh_send(hnb, rua_msg);
	return rc;
}

int llsk_rx_iuh(struct hnb *hnb, struct osmo_prim_hdr *oph)
{
	size_t prim_size = llsk_iuh_prim_size(oph->primitive, oph->operation);

	if (msgb_length(oph->msg) < prim_size) {
		LOGP(DLLSK, LOGL_ERROR, "Rx IUH-%s.%s with length %u < %zu\n",
		     get_value_string(hnb_iuh_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
			msgb_length(oph->msg), prim_size);
		return -EINVAL;
	}

	switch (oph->operation) {
	case PRIM_OP_REQUEST:
		switch (oph->primitive) {
		case HNB_IUH_PRIM_CONN_ESTABLISH:
			return llsk_rx_iuh_conn_establish_req(hnb, (struct hnb_iuh_conn_establish_req_param *)msgb_data(oph->msg));
		case HNB_IUH_PRIM_CONN_RELEASE:
			return llsk_rx_iuh_conn_release_req(hnb, (struct hnb_iuh_conn_release_req_param *)msgb_data(oph->msg));
		case HNB_IUH_PRIM_CONN_DATA:
			return llsk_rx_iuh_conn_data_req(hnb, (struct hnb_iuh_conn_data_req_param *)msgb_data(oph->msg));
		case HNB_IUH_PRIM_UNITDATA:
			return llsk_rx_iuh_unitdata_req(hnb, (struct hnb_iuh_unitdata_req_param *)msgb_data(oph->msg));
		default:
			LOGP(DLLSK, LOGL_ERROR, "Rx llsk-iuh unknown primitive %u (len=%u)\n",
			     oph->primitive, msgb_length(oph->msg));
			return -EINVAL;
		}
		break;

	case PRIM_OP_RESPONSE:
	case PRIM_OP_INDICATION:
	case PRIM_OP_CONFIRM:
	default:
		LOGP(DLLSK, LOGL_ERROR, "Rx llsk-iuh unexpected primitive operation %s::%s (len=%u)\n",
		     get_value_string(hnb_iuh_prim_type_names, oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation),
		     msgb_length(oph->msg));
		return -EINVAL;
	}
}
