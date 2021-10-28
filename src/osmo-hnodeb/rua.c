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

#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/rua/rua_msg_factory.h>

#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>

int hnb_tx_dt(struct hnb *hnb, struct msgb *txm)
{
	struct hnb_chan *chan;
	struct msgb *rua;

	chan = hnb->cs.chan;
	if (!chan) {
		LOGP(DRUA, LOGL_INFO, "hnb_nas_tx_tmsi_realloc_compl(): No CS channel established yet.\n");
		return -1;
	}

	rua = rua_new_dt(chan->is_ps, chan->conn_id, txm);
	hnb_iuh_send(hnb, rua);
	return 0;
}

static void hnb_rua_dt_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_DirectTransferIEs_t ies;
	int rc;

	rc = rua_decode_directtransferies(&ies, in);
	if (rc < 0) {
		LOGP(DRUA, LOGL_INFO, "failed to decode RUA DT IEs\n");
		return;
	}

	rc = ranap_cn_rx_co(hnb_rua_dt_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_directtransferies(&ies);
}

static void hnb_rua_cl_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_ConnectionlessTransferIEs_t ies;
	int rc;

	rc = rua_decode_connectionlesstransferies(&ies, in);
	if (rc < 0) {
		LOGP(DRUA, LOGL_INFO, "failed to decode RUA CL IEs\n");
		return;
	}

	rc = ranap_cn_rx_cl(hnb_rua_cl_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_connectionlesstransferies(&ies);
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
		LOGP(DRUA, LOGL_INFO, "RUA_RUA_PDU_PR_successfulOutcome\n");
		break;
	case RUA_RUA_PDU_PR_initiatingMessage:
		LOGP(DRUA, LOGL_INFO, "RUA_RUA_PDU_PR_initiatingMessage\n");
		break;
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

	switch (pdu->choice.successfulOutcome.procedureCode) {
	case RUA_ProcedureCode_id_ConnectionlessTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx Connectionless Transfer\n");
		hnb_rua_cl_handle(hnb, &pdu->choice.successfulOutcome.value);
		break;
	case RUA_ProcedureCode_id_Connect:
		LOGP(DRUA, LOGL_INFO, "RUA rx Connect\n");
		break;
	case RUA_ProcedureCode_id_DirectTransfer:
		LOGP(DRUA, LOGL_INFO, "RUA rx DirectTransfer\n");
		hnb_rua_dt_handle(hnb, &pdu->choice.successfulOutcome.value);
		break;
	case RUA_ProcedureCode_id_Disconnect:
		LOGP(DRUA, LOGL_INFO, "RUA rx Disconnect\n");
		break;
	case RUA_ProcedureCode_id_ErrorIndication:
		LOGP(DRUA, LOGL_INFO, "RUA rx ErrorIndication\n");
		break;
	case RUA_ProcedureCode_id_privateMessage:
		LOGP(DRUA, LOGL_INFO, "RUA rx privateMessage\n");
		break;
	default:
		LOGP(DRUA, LOGL_INFO, "RUA rx unknown message\n");
		break;
	}

	return 0;
}
