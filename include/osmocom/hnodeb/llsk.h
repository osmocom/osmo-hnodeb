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

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/netif/prim.h>
#include <osmocom/hnodeb/hnb_prim.h>

struct hnb;
struct hnb_ue;

int hnb_llsk_alloc(struct hnb *hnb);
bool hnb_llsk_connected(const struct hnb *hnb);
bool hnb_llsk_can_be_configured(struct hnb *hnb);

int ll_addr_type2af(enum u_addr_type t);
int ll_addr2osa(enum u_addr_type t, const union u_addr *uaddr, uint16_t port, struct osmo_sockaddr *osa);
enum u_addr_type osa2_ll_addr(const struct osmo_sockaddr *osa, union u_addr *uaddr, uint16_t *port);



extern const struct value_string hnb_iuh_prim_type_names[];
int llsk_rx_iuh(struct hnb *hnb, struct osmo_prim_hdr *oph);
int llsk_iuh_tx_configure_ind(struct hnb *hnb);
struct hnb_iuh_prim *hnb_iuh_makeprim_conn_establish_cnf(uint32_t context_id, uint8_t domain,
							 uint8_t cause);
struct hnb_iuh_prim *hnb_iuh_makeprim_conn_data_ind(uint32_t context_id,
						    uint8_t domain,
						    const uint8_t *data,
						    uint32_t data_len);
struct hnb_iuh_prim *hnb_iuh_makeprim_unitdata_ind(const uint8_t *data, uint32_t data_len);


extern const struct value_string hnb_audio_prim_type_names[];
int llsk_rx_audio(struct hnb *hnb, struct osmo_prim_hdr *oph);
int llsk_audio_tx_conn_data_ind(struct hnb_ue *ue, const uint8_t *payload, uint32_t len);
