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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/crypt/auth.h>

#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/nas.h>
#include <osmocom/hnodeb/hnodeb.h>

static struct msgb *gen_nas_id_resp()
{
	uint8_t id_resp[] = {
		GSM48_PDISC_MM,
		GSM48_MT_MM_ID_RESP,
		/* IMEISV */
		0x09, /* len */
		0x03, /* first digit (0000) + even (0) + id IMEISV (011) */
		0x31, 0x91, 0x06, 0x00, 0x28, 0x47, 0x11, /* digits */
		0xf2, /* filler (1111) + last digit (0010) */
	};

	return ranap_new_msg_dt(0, id_resp, sizeof(id_resp));
}

static struct msgb *gen_nas_tmsi_realloc_compl()
{
	uint8_t id_resp[] = {
		GSM48_PDISC_MM,
		GSM48_MT_MM_TMSI_REALL_COMPL,
	};

	return ranap_new_msg_dt(0, id_resp, sizeof(id_resp));
}

static struct msgb *gen_nas_auth_resp(uint8_t *sres)
{
	uint8_t id_resp[] = {
		GSM48_PDISC_MM,
		0x80 | GSM48_MT_MM_AUTH_RESP, /* simulate sequence nr 2 */
		0x61, 0xb5, 0x69, 0xf5 /* hardcoded SRES */
	};

	memcpy(id_resp + 2, sres, 4);

	return ranap_new_msg_dt(0, id_resp, sizeof(id_resp));
}

static struct tlv_parsed *parse_mm(struct gsm48_hdr *gh, int len)
{
	static struct tlv_parsed tp;
	int parse_res;

	len -= (const char *)&gh->data[0] - (const char *)gh;

	OSMO_ASSERT(gsm48_hdr_pdisc(gh) == GSM48_PDISC_MM);

	parse_res = tlv_parse(&tp, &gsm48_mm_att_tlvdef, &gh->data[0], len, 0, 0);
	if (parse_res <= 0) {
		uint8_t msg_type = gsm48_hdr_msg_type(gh);
		printf("Error parsing MM message 0x%hhx: %d\n", msg_type, parse_res);
		return NULL;
	}

	return &tp;
}

int hnb_nas_rx_lu_accept(struct gsm48_hdr *gh, int len, int *sent_tmsi)
{
	printf(" :D Location Update Accept :D\n");
	struct gsm48_loc_area_id *lai;

	lai = (struct gsm48_loc_area_id *)&gh->data[0];

	struct osmo_location_area_id laid;
	gsm48_decode_lai2(lai, &laid);
	printf("LU: mcc %s  mnc %s  lac %hd\n",
	       osmo_mcc_name(laid.plmn.mcc), osmo_mnc_name(laid.plmn.mnc, laid.plmn.mnc_3_digits),
	       laid.lac);

	struct tlv_parsed tp;
	int parse_res;

	len -= (const char *)&gh->data[0] - (const char *)gh;
	parse_res = tlv_parse(&tp, &gsm48_mm_att_tlvdef, &gh->data[0], len, 0, 0);
	if (parse_res <= 0) {
		printf("Error parsing Location Update Accept message: %d\n", parse_res);
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM48_IE_MOBILE_ID)) {
		uint8_t type = TLVP_VAL(&tp, GSM48_IE_NAME_SHORT)[0] & 0x0f;
		if (type == GSM_MI_TYPE_TMSI)
			*sent_tmsi = 1;
		else *sent_tmsi = 0;
	}
	return 0;
}

void hnb_nas_rx_mm_info(struct gsm48_hdr *gh, int len)
{
	printf(" :) MM Info :)\n");
	struct tlv_parsed *tp = parse_mm(gh, len);
	if (!tp)
		return;

	if (TLVP_PRESENT(tp, GSM48_IE_NAME_SHORT)) {
		char name[128] = {0};
		gsm_7bit_decode_n(name, 127,
				  TLVP_VAL(tp, GSM48_IE_NAME_SHORT)+1,
				  (TLVP_LEN(tp, GSM48_IE_NAME_SHORT)-1)*8/7);
		printf("Info: Short Network Name: %s\n", name);
	}

	if (TLVP_PRESENT(tp, GSM48_IE_NAME_LONG)) {
		char name[128] = {0};
		gsm_7bit_decode_n(name, 127,
				  TLVP_VAL(tp, GSM48_IE_NAME_LONG)+1,
				  (TLVP_LEN(tp, GSM48_IE_NAME_LONG)-1)*8/7);
		printf("Info: Long Network Name: %s\n", name);
	}
}

static int hnb_nas_rx_auth_req(struct hnb *hnb, struct gsm48_hdr *gh,
				    int len)
{
	struct gsm48_auth_req *ar;

	len -= (const char *)&gh->data[0] - (const char *)gh;

	if (len < sizeof(*ar)) {
		printf("GSM48 Auth Req does not fit.\n");
		return -1;
	}

	printf(" :) Authentication Request :)\n");

	ar = (struct gsm48_auth_req*) &gh->data[0];
	int seq = ar->key_seq;

	/* Generate SRES from *HARDCODED* Ki for Iuh testing */
	struct osmo_auth_vector vec;
	/* Ki 000102030405060708090a0b0c0d0e0f */
	struct osmo_sub_auth_data auth = {
		.type	= OSMO_AUTH_TYPE_GSM,
		.algo	= OSMO_AUTH_ALG_COMP128v1,
		.u.gsm.ki = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f
		},
	};

	memset(&vec, 0, sizeof(vec));
	osmo_auth_gen_vec(&vec, &auth, ar->rand);

	printf("seq %d rand %s",
	       seq, osmo_hexdump(ar->rand, sizeof(ar->rand)));
	printf(" --> sres %s\n",
	       osmo_hexdump(vec.sres, 4));

	return hnb_tx_dt(hnb, gen_nas_auth_resp(vec.sres));
}

static int hnb_nas_rx_mm(struct hnb *hnb, struct gsm48_hdr *gh, int len)
{
	struct hnb_chan *chan;

	chan = hnb->cs.chan;
	if (!chan) {
		printf("hnb_nas_rx_mm(): No CS channel established yet.\n");
		return -1;
	}

	OSMO_ASSERT(!chan->is_ps);

	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	int sent_tmsi;

	switch (msg_type) {
	case GSM48_MT_MM_ID_REQ:
		return hnb_tx_dt(hnb, gen_nas_id_resp());

	case GSM48_MT_MM_LOC_UPD_ACCEPT:
		if (hnb_nas_rx_lu_accept(gh, len, &sent_tmsi))
			return -1;
		if (sent_tmsi)
			return hnb_tx_dt(hnb, gen_nas_tmsi_realloc_compl());
		else
			return 0;

	case GSM48_MT_MM_LOC_UPD_REJECT:
		printf("Received Location Update Reject\n");
		return 0;

	case GSM48_MT_MM_INFO:
		hnb_nas_rx_mm_info(gh, len);
		hnb_tx_iu_release_req(hnb);
		return 0;

	case GSM48_MT_MM_AUTH_REQ:
		return hnb_nas_rx_auth_req(hnb, gh, len);

	default:
		printf("04.08 message type not handled by hnb-test: 0x%x\n",
		       msg_type);
		return 0;
	}

}

void hnb_nas_rx_dtap(struct hnb *hnb, void *data, int len)
{
	int rc;
	printf("got %d bytes: %s\n", len, osmo_hexdump(data, len));

	// nas_pdu == '05 08 12' ==> IMEI Identity request
	//            '05 04 0d' ==> LU reject

	struct gsm48_hdr *gh = data;
	if (len < sizeof(*gh)) {
		printf("hnb_nas_rx_dtap(): NAS PDU is too short: %d. Ignoring.\n",
		       len);
		return;
	}
	uint8_t pdisc = gsm48_hdr_pdisc(gh);

	switch (pdisc) {
	case GSM48_PDISC_MM:
		rc = hnb_nas_rx_mm(hnb, gh, len);
		if (rc != 0)
			printf("Error receiving MM message: %d\n", rc);
		return;
	default:
		printf("04.08 discriminator not handled by hnb-test: %d\n",
		       pdisc);
		return;
	}
}
