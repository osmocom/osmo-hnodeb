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
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/netif/stream.h>

enum {
	DMAIN,
	DHNBAP,
	DRUA,
	DRANAP,
	DSCTP,
	DNAS,
};
extern const struct log_info hnb_log_info;

struct hnb_chan {
	int is_ps;
	uint32_t conn_id;
	char *imsi;
};

struct hnb {
	char *identity; /* HNB-Identity */
	struct osmo_plmn_id plmn;
	uint16_t cell_identity;
	uint16_t lac;
	uint8_t rac;
	uint16_t sac;
	struct {
		char *local_addr;
		uint16_t local_port;
		char *remote_addr;
		uint16_t remote_port;
		struct osmo_stream_cli *client;
	} iuh;

	uint16_t rnc_id;

	uint32_t ctx_id;

	struct osmo_fsm_inst *shutdown_fi; /* FSM instance to manage shutdown procedure during process exit */
	bool shutdown_fi_exit_proc; /* exit process when shutdown_fsm is finished? */

	struct {
		struct hnb_chan *chan;
	} cs;
};

struct hnb *hnb_alloc(void *tall_ctx);
void hnb_free(struct hnb *hnb);

extern void *tall_hnb_ctx;
extern struct hnb *g_hnb;
