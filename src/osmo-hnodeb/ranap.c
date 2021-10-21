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
#include <osmocom/core/msgb.h>

#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/hnodeb/ranap.h>

static const char *printstr(OCTET_STRING_t *s)
{
	return osmo_hexdump((const unsigned char*)s->buf, s->size);
}

#define PP(octet_string_t) \
	printf(#octet_string_t " = %s\n",\
	       printstr(&octet_string_t))

void hnb_rua_dt_handle_ranap(struct hnb *hnb,
				  struct ranap_message_s *ranap_msg)
{
	int len;
	uint8_t *data;
	RANAP_PermittedIntegrityProtectionAlgorithms_t *algs;
	RANAP_IntegrityProtectionAlgorithm_t *first_alg;

	printf("rx ranap_msg->procedureCode %d\n",
	       ranap_msg->procedureCode);

	switch (ranap_msg->procedureCode) {
	case RANAP_ProcedureCode_id_DirectTransfer:
		printf("rx DirectTransfer: presence = %hx\n",
		       ranap_msg->msg.directTransferIEs.presenceMask);
		PP(ranap_msg->msg.directTransferIEs.nas_pdu);

		len = ranap_msg->msg.directTransferIEs.nas_pdu.size;
		data = ranap_msg->msg.directTransferIEs.nas_pdu.buf;

		hnb_nas_rx_dtap(hnb, data, len);
		return;

	case RANAP_ProcedureCode_id_SecurityModeControl:
		printf("rx SecurityModeControl: presence = %hx\n",
		       ranap_msg->msg.securityModeCommandIEs.presenceMask);

		/* Just pick the first available IP alg, don't care about
		 * encryption (yet?) */
		algs = &ranap_msg->msg.securityModeCommandIEs.integrityProtectionInformation.permittedAlgorithms;
		if (algs->list.count < 1) {
			printf("Security Mode Command: No permitted algorithms.\n");
			return;
		}
		first_alg = *algs->list.array;

		hnb_rx_secmode_cmd(hnb, *first_alg);
		return;

	case RANAP_ProcedureCode_id_Iu_Release:
		hnb_rx_iu_release(hnb);
		return;
	}
}

void hnb_rua_cl_handle_ranap(struct hnb *hnb,
				  struct ranap_message_s *ranap_msg)
{
	char imsi[16];

	printf("rx ranap_msg->procedureCode %d\n",
	       ranap_msg->procedureCode);

	switch (ranap_msg->procedureCode) {
	case RANAP_ProcedureCode_id_Paging:
		if (ranap_msg->msg.pagingIEs.permanentNAS_UE_ID.present == RANAP_PermanentNAS_UE_ID_PR_iMSI) {
			ranap_bcd_decode(imsi, sizeof(imsi),
					 ranap_msg->msg.pagingIEs.permanentNAS_UE_ID.choice.iMSI.buf,
					 ranap_msg->msg.pagingIEs.permanentNAS_UE_ID.choice.iMSI.size);
		} else imsi[0] = '\0';

		printf("rx Paging: presence=%hx  domain=%ld  IMSI=%s\n",
		       ranap_msg->msg.pagingIEs.presenceMask,
		       ranap_msg->msg.pagingIEs.cN_DomainIndicator,
		       imsi
		       );

		hnb_rx_paging(hnb, imsi);
		return;
	}
}
