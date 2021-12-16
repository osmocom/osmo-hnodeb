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

#include <stdint.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/hnodeb/hnb_prim.h>

struct hnb;
struct hnb_ue;

struct rtp_conn {
	struct llist_head list; /* Item in struct hnb->ue_list */
	struct hnb_ue *ue; /* backpointer */
	uint32_t id;
	struct osmo_rtp_socket *socket;
	struct osmo_sockaddr loc_addr;
	struct osmo_sockaddr rem_addr;
	struct osmo_iuup_instance *iui;
};

struct rtp_conn *rtp_conn_alloc(struct hnb_ue *ue);
void rtp_conn_free(struct rtp_conn *conn);

int rtp_conn_setup(struct rtp_conn *conn, const struct osmo_sockaddr *rem_addr, const struct hnb_audio_conn_establish_req_param *ce_req);
int rtp_conn_tx_data(struct rtp_conn *conn, uint8_t frame_nr, uint8_t fqc, uint8_t rfci, const uint8_t *data, unsigned int data_len);
