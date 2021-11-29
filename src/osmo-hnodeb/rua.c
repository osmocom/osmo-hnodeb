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

#include <errno.h>

#include <asn1c/ANY.h>
#include <asn1c/asn1helpers.h>

#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/rua/rua_msg_factory.h>

#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/hnodeb.h>


struct msgb *hnb_rua_msgb_alloc(void)
{
	return msgb_alloc(1000, "rua_tx");
}

static void hnb_rua_dt_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_DirectTransferIEs_t ies;
	int rc;
	struct hnb_ue *ue;
	struct hnb_iuh_prim *iuh_prim;
	uint32_t context_id;
	bool is_ps;
	uint8_t *ranap_buf;
	size_t ranap_buf_len;
	bool *conn_est_cnf_pending;

	rc = rua_decode_directtransferies(&ies, in);
	if (rc < 0) {
		LOGP(DRUA, LOGL_INFO, "failed to decode RUA DT IEs\n");
		return;
	}

	context_id = asn1bitstr_to_u24(&ies.context_ID);
	is_ps = (ies.cN_DomainIndicator == RUA_CN_DomainIndicator_ps_domain);
	ranap_buf = ies.ranaP_Message.buf;
	ranap_buf_len = ies.ranaP_Message.size;

	LOGP(DRUA, LOGL_DEBUG, "Rx RUA DT context_id=%u is_ps=%u ranap_len=%zu\n",
	     context_id, is_ps, ranap_buf_len);

	if (!(ue = hnb_find_ue_by_id(hnb, context_id))) {
		LOGP(DRUA, LOGL_ERROR, "Rx RUA DT: Failed finding ue context_id=%u is_ps=%u\n",
		     context_id, is_ps);
		goto free_ret;
	}

	conn_est_cnf_pending = is_ps ? &ue->conn_ps.conn_est_cnf_pending :
				       &ue->conn_cs.conn_est_cnf_pending;
	if (*conn_est_cnf_pending) {
		*conn_est_cnf_pending = false;
		LOGP(DLLSK, LOGL_INFO, "Tx IUH-CONN_ESTABLISH.cnf context_id=%u is_ps=%u\n",
		     context_id, is_ps);
		iuh_prim = hnb_iuh_makeprim_conn_establish_cnf(context_id, is_ps, 0);
		if ((rc = osmo_prim_srv_send(hnb->llsk, iuh_prim->hdr.msg)) < 0) {
			LOGP(DRUA, LOGL_ERROR, "Failed sending IUH-CONN_ESTABLISH.cnf context_id=%u is_ps=%u\n",
			     context_id, is_ps);
			goto free_ret;
		}
	}

	LOGP(DLLSK, LOGL_DEBUG, "Tx IUH-CONN_DATA.ind context_id=%u is_ps=%u ranap_len=%zu\n",
	     context_id, is_ps, ranap_buf_len);
	iuh_prim = hnb_iuh_makeprim_conn_data_ind(context_id, is_ps, ranap_buf, ranap_buf_len);
	if ((rc = osmo_prim_srv_send(hnb->llsk, iuh_prim->hdr.msg)) < 0) {
		LOGP(DRUA, LOGL_ERROR, "Failed sending IUH-CONN_DATA.ind context_id=%u is_ps=%u ranap_len=%zu\n",
		     context_id, is_ps, ranap_buf_len);
		goto free_ret;
	}

free_ret:
	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_directtransferies(&ies);
}

static void hnb_rua_cl_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_ConnectionlessTransferIEs_t ies;
	int rc;
	struct hnb_iuh_prim *iuh_prim;
	uint8_t *ranap_buf;
	size_t ranap_buf_len;

	rc = rua_decode_connectionlesstransferies(&ies, in);
	if (rc < 0) {
		LOGP(DRUA, LOGL_INFO, "failed to decode RUA CL IEs\n");
		return;
	}
	ranap_buf = ies.ranaP_Message.buf;
	ranap_buf_len = ies.ranaP_Message.size;

	LOGP(DRUA, LOGL_DEBUG, "Rx RUA UDT ranap_len=%zu\n", ranap_buf_len);

	LOGP(DLLSK, LOGL_DEBUG, "Tx IUH-UNITDATA.ind ranap_len=%zu\n", ranap_buf_len);
	iuh_prim = hnb_iuh_makeprim_unitdata_ind(ranap_buf, ranap_buf_len);
	if ((rc = osmo_prim_srv_send(hnb->llsk, iuh_prim->hdr.msg)) < 0) {
		LOGP(DRUA, LOGL_ERROR, "Failed sending IUH-CONN_DATA.ind ranap_len=%zu\n",
		     ranap_buf_len);
		goto free_ret;
	}

free_ret:
	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_connectionlesstransferies(&ies);
}


static int hnb_rua_rx_initiating(struct hnb *hnb, RUA_InitiatingMessage_t *init)
{
	switch (init->procedureCode) {
	case RUA_ProcedureCode_id_ConnectionlessTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx Initiating ConnectionlessTransfer\n");
		hnb_rua_cl_handle(hnb, &init->value);
		break;
	case RUA_ProcedureCode_id_DirectTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx Initiating DirectTransfer\n");
		hnb_rua_dt_handle(hnb, &init->value);
	default:
		LOGP(DRUA, LOGL_INFO, "RUA rx unknown Initiating message\n");
		break;
	}
	return 0;
}

static int hnb_rua_rx_successful(struct hnb *hnb, RUA_SuccessfulOutcome_t *success)
{
	switch (success->procedureCode) {
	case RUA_ProcedureCode_id_ConnectionlessTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome ConnectionlessTransfer\n");
		hnb_rua_cl_handle(hnb, &success->value);
		break;
	case RUA_ProcedureCode_id_Connect:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome Connect\n");
		break;
	case RUA_ProcedureCode_id_DirectTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome DirectTransfer\n");
		hnb_rua_dt_handle(hnb, &success->value);
		break;
	case RUA_ProcedureCode_id_Disconnect:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome Disconnect\n");
		break;
	case RUA_ProcedureCode_id_ErrorIndication:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome ErrorIndication\n");
		break;
	case RUA_ProcedureCode_id_privateMessage:
		LOGP(DRUA, LOGL_INFO, "RUA rx SuccessfulOutcome privateMessage\n");
		break;
	default:
		LOGP(DRUA, LOGL_INFO, "RUA rx unknown SuccessfulOutcome message\n");
		break;
	}
	return 0;
}

int hnb_rua_rx(struct hnb *hnb, struct msgb *msg)
{
	RUA_RUA_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_RUA_RUA_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DMAIN, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -EINVAL;
	}

	switch (pdu->present) {
	case RUA_RUA_PDU_PR_successfulOutcome:
		return hnb_rua_rx_successful(hnb, &pdu->choice.successfulOutcome);
	case RUA_RUA_PDU_PR_initiatingMessage:
		return hnb_rua_rx_initiating(hnb, &pdu->choice.initiatingMessage);
	case RUA_RUA_PDU_PR_NOTHING:
		LOGP(DRUA, LOGL_INFO, "RUA_RUA_PDU_PR_NOTHING\n");
		break;
	case RUA_RUA_PDU_PR_unsuccessfulOutcome:
		LOGP(DRUA, LOGL_INFO, "RUA_RUA_PDU_PR_unsuccessfulOutcome\n");
		break;
	default:
		LOGP(DRUA, LOGL_INFO, "Unexpected RUA message received\n");
		break;
	}

	return 0;
}
