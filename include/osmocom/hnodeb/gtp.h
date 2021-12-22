/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/socket.h>
#include <osmocom/core/linuxlist.h>

struct hnb;
struct hnb_ue;

int hnb_gtp_bind(struct hnb *hnb);
void hnb_gtp_unbind(struct hnb *hnb);

struct gtp_conn {
	struct llist_head list; /* Item in struct hnb->ue_list */
	struct hnb_ue *ue; /* backpointer */
	uint32_t id;
	struct osmo_sockaddr loc_addr;
	struct osmo_sockaddr rem_addr;
	uint32_t loc_tei;
	uint32_t rem_tei;
	uint16_t seq_nr;
};

struct gtp_conn *gtp_conn_alloc(struct hnb_ue *ue);
void gtp_conn_free(struct gtp_conn *conn);

int gtp_conn_setup(struct gtp_conn *conn, const struct osmo_sockaddr *rem_addr, uint32_t rem_tei);
int gtp_conn_tx(struct gtp_conn *conn, const uint8_t *gtpu_payload, unsigned gtpu_payload_len);
