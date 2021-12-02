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

struct hnb;
struct hnb_ue;

int hnb_gtp_bind(struct hnb *hnb);
void hnb_gtp_unbind(struct hnb *hnb);

int hnb_ue_gtp_bind(struct hnb_ue *ue, const struct osmo_sockaddr *rem_addr, uint32_t rem_tei,
		     struct osmo_sockaddr *loc_addr, uint32_t *loc_tei);
int hnb_ue_gtp_unbind(struct hnb_ue *ue);
int hnb_ue_gtp_tx(struct hnb_ue *ue, void *gtpu_payload, unsigned gtpu_payload_len);
