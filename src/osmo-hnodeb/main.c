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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/netif/stream.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/command.h>

#include <osmocom/crypt/auth.h>

#include <osmocom/rua/rua_msg_factory.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/rua/RUA_RUA-PDU.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/ranap/RANAP_ProcedureCode.h>
#include <osmocom/ranap/RANAP_Criticality.h>
#include <osmocom/ranap/RANAP_DirectTransfer.h>
#include <osmocom/ranap/ranap_common.h>

#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/vty.h>
#include <osmocom/hnodeb/hnodeb.h>

void *tall_hnb_ctx;

struct hnb g_hnb = {
	.gw_addr = "127.0.0.1",
	.gw_port = IUH_DEFAULT_SCTP_PORT,
};

struct msgb *rua_new_udt(struct msgb *inmsg);

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

static int hnb_tx_dt(struct hnb *hnb, struct msgb *txm)
{
	struct hnb_chan *chan;
	struct msgb *rua;

	chan = hnb->cs.chan;
	if (!chan) {
		printf("hnb_nas_tx_tmsi_realloc_compl(): No CS channel established yet.\n");
		return -1;
	}

	rua = rua_new_dt(chan->is_ps, chan->conn_id, txm);
	osmo_wqueue_enqueue(&g_hnb.wqueue, rua);
	return 0;
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

void hnb_tx_iu_release_req(struct hnb *hnb)
{
	RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_radioNetwork,
		.choice.transmissionNetwork = RANAP_CauseRadioNetwork_release_due_to_UE_generated_signalling_connection_release,
	};
	hnb_tx_dt(hnb, ranap_new_msg_iu_rel_req(&cause));
}

void hnb_tx_iu_release_compl(struct hnb *hnb)
{
	hnb_tx_dt(hnb, ranap_new_msg_iu_rel_compl());
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

void hnb_rx_secmode_cmd(struct hnb *hnb, long ip_alg)
{
	printf(" :) Security Mode Command :)\n");
	/* not caring about encryption yet, just pass 0 for No Encryption. */
	hnb_tx_dt(hnb, ranap_new_msg_sec_mod_compl(ip_alg, 0));
}

void hnb_rx_iu_release(struct hnb *hnb)
{
	hnb_tx_iu_release_compl(hnb);
}

void hnb_rx_paging(struct hnb *hnb, const char *imsi)
{
	printf(" :) Paging Request for %s :)\n", imsi);
	/* TODO reply */
}

extern void direct_transfer_nas_pdu_print(ANY_t *in);

static int hnb_read_cb(struct osmo_fd *fd)
{
	struct hnb *hnb = fd->data;
	struct sctp_sndrcvinfo sinfo;
	struct msgb *msg = msgb_alloc(IUH_MSGB_SIZE, "Iuh rx");
	int flags = 0;
	int rc;

	if (!msg)
		return -ENOMEM;

	rc = sctp_recvmsg(fd->fd, msgb_data(msg), msgb_tailroom(msg),
			  NULL, NULL, &sinfo, &flags);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error during sctp_recvmsg()\n");
		/* FIXME: clean up after disappeared HNB */
		close(fd->fd);
		osmo_fd_unregister(fd);
		return rc;
	} else if (rc == 0) {
		LOGP(DMAIN, LOGL_INFO, "Connection to HNB closed\n");
		close(fd->fd);
		osmo_fd_unregister(fd);
		fd->fd = -1;

		return -1;
	} else {
		msgb_put(msg, rc);
	}

	if (flags & MSG_NOTIFICATION) {
		LOGP(DMAIN, LOGL_DEBUG, "Ignoring SCTP notification\n");
		msgb_free(msg);
		return 0;
	}

	sinfo.sinfo_ppid = ntohl(sinfo.sinfo_ppid);

	switch (sinfo.sinfo_ppid) {
	case IUH_PPI_HNBAP:
		printf("HNBAP message received\n");
		rc = hnb_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		printf("RUA message received\n");
		rc = hnb_rua_rx(hnb, msg);
		break;
	case IUH_PPI_SABP:
	case IUH_PPI_RNA:
	case IUH_PPI_PUA:
		LOGP(DMAIN, LOGL_ERROR, "Unimplemented SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "Unknown SCTP PPID=%u received\n",
		     sinfo.sinfo_ppid);
		rc = 0;
		break;
	}

	msgb_free(msg);
	return rc;
}

static int hnb_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	/* struct hnb *ctx = fd->data; */
	struct sctp_sndrcvinfo sinfo = {
		.sinfo_ppid = htonl(msgb_sctp_ppid(msg)),
		.sinfo_stream = 0,
	};
	int rc;

	printf("Sending: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	rc = sctp_send(fd->fd, msgb_data(msg), msgb_length(msg),
			&sinfo, 0);
	/* we don't need to msgb_free(), write_queue does this for us */
	return rc;
}

static struct vty_app_info vty_info = {
	.name		= "OsmohNodeB",
	.version	= "0",
};

static int sctp_sock_init(int fd)
{
	struct sctp_event_subscribe event;
	int rc;

	/* subscribe for all events */
	memset((uint8_t *)&event, 1, sizeof(event));
	rc = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			&event, sizeof(event));

	return rc;
}


struct msgb *gen_initue_lu(int is_ps, uint32_t conn_id, const char *imsi)
{
	uint8_t lu[] = { GSM48_PDISC_MM, GSM48_MT_MM_LOC_UPD_REQUEST,
		         0x70, 0x62, 0xf2, 0x30, 0xff, 0xf3, 0x57,
		/*	 len, IMSI/type, IMSI-------------------------------- */
			 0x08, 0x29, 0x26, 0x24, 0x10, 0x32, 0x54, 0x76, 0x98,
			 0x33, 0x03, 0x57, 0x18 , 0xb2 };
	uint8_t plmn_id[] = { 0x09, 0x01, 0x99 };
	RANAP_GlobalRNC_ID_t rnc_id = {
		.rNC_ID = 23,
		.pLMNidentity.buf = plmn_id,
		.pLMNidentity.size = sizeof(plmn_id),
	};

	/* FIXME: patch imsi */
	/* Note: the Mobile Identitiy IE's IMSI data has the identity type and
	 * an even/odd indicator bit encoded in the first octet. So the first
	 * octet looks like this:
	 *
	 *   8  7  6  5 | 4        | 3 2 1
	 *   IMSI-digit | even/odd | type
	 *
	 * followed by the remaining IMSI digits.
	 * If digit count is even (bit 4 == 0), that first high-nibble is 0xf.
	 * (derived from Iu pcap Location Update Request msg and TS 25.413)
	 *
	 * TODO I'm only 90% sure about this
	 */

	return ranap_new_msg_initial_ue(conn_id, is_ps, &rnc_id, lu, sizeof(lu));
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int idx = 0, c;
		static const struct option long_options[] = {
			{ "ues", 1, 0, 'u' },
			{ "gw-addr", 1, 0, 'g' },
			{ 0, 0, 0, 0 },
		};

		c = getopt_long(argc, argv, "u:g:", long_options, &idx);

		if (c == -1)
			break;

		switch (c) {
		case 'u':
			g_hnb.ues = atoi(optarg);
			break;
		case 'g':
			g_hnb.gw_addr = optarg;
			break;
		}
	}
}

int main(int argc, char **argv)
{
	int rc;

	tall_hnb_ctx = talloc_named_const(NULL, 0, "hnb_context");

	msgb_talloc_ctx_init(tall_hnb_ctx, 0);
	talloc_asn1_ctx = talloc_named_const(tall_hnb_ctx, 0, "asn1_context");

	rc = osmo_init_logging2(tall_hnb_ctx, &hnb_log_info);
	if (rc < 0)
		exit(1);

	ranap_set_log_area(DRANAP);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	vty_init(&vty_info);
	hnb_vty_init();

	rc = telnet_init_dynif(NULL, NULL, vty_get_bind_addr(), 2324);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	handle_options(argc, argv);

	osmo_wqueue_init(&g_hnb.wqueue, 16);
	g_hnb.wqueue.bfd.data = &g_hnb;
	g_hnb.wqueue.read_cb = hnb_read_cb;
	g_hnb.wqueue.write_cb = hnb_write_cb;

	rc = osmo_sock_init_ofd(&g_hnb.wqueue.bfd, AF_INET, SOCK_STREAM,
			   IPPROTO_SCTP, g_hnb.gw_addr,
			   g_hnb.gw_port, OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		perror("Error connecting to Iuh port");
		exit(1);
	}
	sctp_sock_init(g_hnb.wqueue.bfd.fd);

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
