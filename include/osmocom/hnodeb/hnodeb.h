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

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <asn1c/asn1helpers.h>

#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/netif/stream.h>

#include <gtp.h>
#include <pdp.h>

#include <osmocom/hnodeb/llsk.h>

enum {
	DMAIN,
	DHNBAP,
	DRUA,
	DRANAP,
	DSCTP,
	DLLSK,
	DRTP,
	DGTP,
};
extern const struct log_info hnb_log_info;

struct hnb;

struct hnb_ue {
	struct llist_head list; /* Item in struct hnb->ue_list */
	struct hnb *hnb; /* backpointer */
	uint32_t conn_id;
	char imsi[OSMO_IMSI_BUF_SIZE];
	struct hnb_ue_cs_ctx {
		bool active; /* Is this chan in use? */
		bool conn_est_cnf_pending; /* Did we send CONN_ESTABLISH_CNF to lower layers? */
		struct {
			struct osmo_rtp_socket *socket;
		} rtp;
	} conn_cs;
	struct hnb_ue_ps_ctx {
		bool active; /* Is this chan in use? */
		bool conn_est_cnf_pending; /* Did we send CONN_ESTABLISH_CNF to lower layers? */
		uint32_t local_tei;
		uint32_t remote_tei;
		struct pdp_t *pdp_lib;
	} conn_ps;
};
struct hnb_ue *hnb_ue_alloc(struct hnb *hnb, uint32_t conn_id);
void hnb_ue_free(struct hnb_ue *ue);
void hnb_ue_reset_chan(struct hnb_ue *ue, bool is_ps);


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

	/* Lower Layer UD socket */
	struct osmo_prim_srv_link *llsk_link;
	struct osmo_prim_srv *llsk;
	uint8_t llsk_valid_sapi_mask;
	struct osmo_timer_list llsk_defer_configure_ind_timer;

	struct {
		unsigned int jitter_buf_ms;
		bool jitter_adaptive;

		uint16_t port_range_start;
		uint16_t port_range_end;
		uint16_t port_range_next;
		int ip_dscp;
		int priority;
	} rtp;

	struct gtp {
		char *cfg_local_addr;
		struct osmo_sockaddr local_addr;
		struct gsn_t *gsn;
		struct osmo_fd fd1u;
	} gtp;

	uint16_t rnc_id;
	bool registered; /* Set to true once HnbRegisterAccept was received from Iuh. rnc_id is valid iif registered==true */

	uint32_t ctx_id;

	struct osmo_fsm_inst *shutdown_fi; /* FSM instance to manage shutdown procedure during process exit */
	bool shutdown_fi_exit_proc; /* exit process when shutdown_fsm is finished? */

	struct llist_head ue_list; /* list of struct hnb_ue */
};

struct hnb *hnb_alloc(void *tall_ctx);
void hnb_free(struct hnb *hnb);
struct hnb_ue *hnb_find_ue_by_id(const struct hnb *hnb, uint32_t conn_id);
struct hnb_ue *hnb_find_ue_by_tei(const struct hnb *hnb, uint32_t tei, bool is_remote);
struct hnb_ue *hnb_find_ue_by_imsi(const struct hnb *hnb, char *imsi);

extern void *tall_hnb_ctx;
extern struct hnb *g_hnb;

#define LOGUE(ue, ss, lvl, fmt, args...) LOGP(ss, lvl, "UE(%" PRIu32 ") " fmt, (ue)->conn_id, ## args)
