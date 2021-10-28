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

#include <osmocom/core/msgb.h>
#include <osmocom/netif/stream.h>

#include <osmocom/hnbap/hnbap_common.h>
#include <osmocom/hnbap/hnbap_ies_defs.h>

#include <osmocom/ranap/iu_helpers.h> /* ranap_bcd_decode() */

#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/hnodeb.h>

static int hnb_rx_hnb_register_acc(struct hnb *hnb, ANY_t *in)
{
	int rc;
	HNBAP_HNBRegisterAcceptIEs_t accept;

	rc = hnbap_decode_hnbregisteraccepties(&accept, in);
	if (rc < 0) {
	}

	hnb->rnc_id = accept.rnc_id;
	LOGP(DHNBAP, LOGL_INFO, "HNB Register accept with RNC ID %u\n", hnb->rnc_id);

	hnbap_free_hnbregisteraccepties(&accept);
	return 0;
}

static int hnb_rx_ue_register_acc(struct hnb *hnb, ANY_t *in)
{
	int rc;
	uint32_t ctx_id;
	HNBAP_UERegisterAcceptIEs_t accept;
	char imsi[16];

	rc = hnbap_decode_ueregisteraccepties(&accept, in);
	if (rc < 0) {
		return rc;
	}

	if (accept.uE_Identity.present != HNBAP_UE_Identity_PR_iMSI) {
		LOGP(DHNBAP, LOGL_ERROR, "Wrong type in UE register accept\n");
		return -1;
	}

	ctx_id = asn1bitstr_to_u24(&accept.context_ID);

	ranap_bcd_decode(imsi, sizeof(imsi), accept.uE_Identity.choice.iMSI.buf,
			accept.uE_Identity.choice.iMSI.size);
	LOGP(DHNBAP, LOGL_INFO, "UE Register accept for IMSI %s, context %u\n", imsi, ctx_id);

	hnb->ctx_id = ctx_id;
	hnbap_free_ueregisteraccepties(&accept);

	return 0;
}

int hnb_hnbap_rx(struct hnb *hnb, struct msgb *msg)
{
	HNBAP_HNBAP_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_HNBAP_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DMAIN, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -EINVAL;
	}

	if (pdu->present != HNBAP_HNBAP_PDU_PR_successfulOutcome) {
		LOGP(DHNBAP, LOGL_ERROR, "Unexpected HNBAP message received\n");
	}

	switch (pdu->choice.successfulOutcome.procedureCode) {
	case HNBAP_ProcedureCode_id_HNBRegister:
		/* Get HNB id and send UE Register request */
		rc = hnb_rx_hnb_register_acc(hnb, &pdu->choice.successfulOutcome.value);
		break;
	case HNBAP_ProcedureCode_id_UERegister:
		rc = hnb_rx_ue_register_acc(hnb, &pdu->choice.successfulOutcome.value);
		break;
	default:
		rc = -ENOSPC;
		break;
	}

	return rc;
}

int hnb_ue_register_tx(struct hnb *hnb, const char *imsi_str)
{
	struct msgb *msg;
	int rc, imsi_len;

	uint8_t imsi_buf[16];

	HNBAP_UERegisterRequest_t request_out;
	HNBAP_UERegisterRequestIEs_t request;
	memset(&request, 0, sizeof(request));

	request.uE_Identity.present = HNBAP_UE_Identity_PR_iMSI;

	imsi_len = ranap_imsi_encode(imsi_buf, sizeof(imsi_buf), imsi_str);
	OCTET_STRING_fromBuf(&request.uE_Identity.choice.iMSI, (const char*)imsi_buf, imsi_len);

	request.registration_Cause = HNBAP_Registration_Cause_normal;
	request.uE_Capabilities.access_stratum_release_indicator = HNBAP_Access_stratum_release_indicator_rel_6;
	request.uE_Capabilities.csg_capability = HNBAP_CSG_Capability_not_csg_capable;

	memset(&request_out, 0, sizeof(request_out));
	rc = hnbap_encode_ueregisterrequesties(&request_out, &request);
	OSMO_ASSERT(rc == 0);

	msg = hnbap_generate_initiating_message(HNBAP_ProcedureCode_id_UERegister,
						HNBAP_Criticality_reject,
						&asn_DEF_HNBAP_UERegisterRequest,
						&request_out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_UERegisterRequest, &request_out);

	msgb_sctp_ppid(msg) = IUH_PPI_HNBAP;

	return hnb_iuh_send(hnb, msg);
}

void hnb_send_register_req(struct hnb *hnb)
{
	HNBAP_HNBRegisterRequest_t request_out;
	struct msgb *msg;
	int rc;
	uint16_t lac, sac;
	uint8_t rac;
	uint32_t cid;
	uint8_t plmn[] = {0x09, 0xf1, 0x99};
	char identity[50] = "ATestHNB@";

	HNBAP_HNBRegisterRequestIEs_t request;
	memset(&request, 0, sizeof(request));

	lac = 0xc0fe;
	sac = 0xabab;
	rac = 0x42;
	cid = 0xadceaab;

	asn1_u16_to_str(&request.lac, &lac, lac);
	asn1_u16_to_str(&request.sac, &sac, sac);
	asn1_u8_to_str(&request.rac, &rac, rac);
	asn1_u28_to_bitstring(&request.cellIdentity, &cid, cid);

	request.hnB_Identity.hNB_Identity_Info.buf = (uint8_t*) identity;
	request.hnB_Identity.hNB_Identity_Info.size = strlen(identity);

	request.plmNidentity.buf = plmn;
	request.plmNidentity.size = 3;



	memset(&request_out, 0, sizeof(request_out));
	rc = hnbap_encode_hnbregisterrequesties(&request_out, &request);
	if (rc < 0) {
		LOGP(DHNBAP, LOGL_ERROR, "Could not encode HNB register request IEs\n");
	}

	msg = hnbap_generate_initiating_message(HNBAP_ProcedureCode_id_HNBRegister,
						HNBAP_Criticality_reject,
						&asn_DEF_HNBAP_HNBRegisterRequest,
						&request_out);


	msgb_sctp_ppid(msg) = IUH_PPI_HNBAP;

	hnb_iuh_send(hnb, msg);
}

void hnb_send_deregister_req(struct hnb *hnb)
{
	struct msgb *msg;
	int rc;

	HNBAP_HNBDe_RegisterIEs_t request;
	memset(&request, 0, sizeof(request));

	request.cause.present = HNBAP_Cause_PR_misc;
	request.cause.choice.misc = HNBAP_CauseMisc_o_and_m_intervention;

	HNBAP_HNBDe_Register_t request_out;
	memset(&request_out, 0, sizeof(request_out));
	rc = hnbap_encode_hnbde_registeries(&request_out, &request);
	if (rc < 0) {
		LOGP(DHNBAP, LOGL_ERROR, "Could not encode HNB deregister request IEs\n");
	}

	msg = hnbap_generate_initiating_message(HNBAP_ProcedureCode_id_HNBDe_Register,
						HNBAP_Criticality_reject,
						&asn_DEF_HNBAP_HNBDe_Register,
						&request_out);

	msgb_sctp_ppid(msg) = IUH_PPI_HNBAP;

	hnb_iuh_send(hnb, msg);
}
