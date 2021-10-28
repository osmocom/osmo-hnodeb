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
	DNAS,
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

struct hnb_chan {
	int is_ps;
	uint32_t conn_id;
	char *imsi;
};

struct hnb {
	struct {
		char *local_addr;
		uint16_t local_port;
		char *remote_addr;
		uint16_t remote_port;
		/*! SCTP socket + write queue for Iuh to this specific HNB */
		struct osmo_wqueue wqueue;
	} iuh;

	uint16_t rnc_id;

	uint32_t ctx_id;

	struct {
		struct hnb_chan *chan;
	} cs;
};
struct hnb *hnb_alloc(void *tall_ctx);
int hnb_connect(struct hnb *hnb);

int hnb_iuh_send(struct hnb *hnb, struct msgb *msg);

extern void *tall_hnb_ctx;
extern struct hnb *g_hnb;
