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
#pragma once

#include <asn1c/asn1helpers.h>

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>

enum {
	DMAIN,
	DHNBAP,
	DRUA,
	DRANAP,
};
extern const struct log_info hnb_log_info;

/* 25.467 Section 7.1 */
#define IUH_DEFAULT_SCTP_PORT	29169
#define RNA_DEFAULT_SCTP_PORT	25471

#define IUH_PPI_RUA		19
#define IUH_PPI_HNBAP		20
#define IUH_PPI_SABP		31
#define IUH_PPI_RNA		42
#define IUH_PPI_PUA		55

#define IUH_MSGB_SIZE	2048

struct umts_cell_id {
	uint16_t mcc;	/*!< Mobile Country Code */
	uint16_t mnc;	/*!< Mobile Network Code */
	uint16_t lac;	/*!< Locaton Area Code */
	uint16_t rac;	/*!< Routing Area Code */
	uint16_t sac;	/*!< Service Area Code */
	uint32_t cid;	/*!< Cell ID */
};

struct ue_context {
	/*! Entry in the HNB-global list of UE */
	struct llist_head list;
	/*! Unique Context ID for this UE */
	uint32_t context_id;
	char imsi[16+1];
};

struct hnb_chan {
	int is_ps;
	uint32_t conn_id;
	char *imsi;
};

struct hnb {
	const char *gw_addr;
	uint16_t gw_port;
	/*! SCTP listen socket for incoming connections */
	struct osmo_fd conn_fd;

	/*! SCTP socket + write queue for Iuh to this specific HNB */
	struct osmo_wqueue wqueue;
	/*! copied from HNB-Identity-Info IE */
	char identity_info[256];
	/*! copied from Cell Identity IE */
	struct umts_cell_id id;

	/*! SCTP stream ID for HNBAP */
	uint16_t hnbap_stream;
	/*! SCTP stream ID for RUA */
	uint16_t rua_stream;

	uint16_t rnc_id;

	uint32_t ctx_id;

	int ues;

	struct {
		struct hnb_chan *chan;
	} cs;
};

void hnb_rx_iu_release(struct hnb *hnb);
void hnb_rx_paging(struct hnb *hnb, const char *imsi);
void hnb_nas_rx_dtap(struct hnb *hnb, void *data, int len);
void hnb_rx_secmode_cmd(struct hnb *hnb, long ip_alg);

struct msgb *gen_initue_lu(int is_ps, uint32_t conn_id, const char *imsi);

extern void *tall_hnb_ctx;
extern struct hnb g_hnb;
