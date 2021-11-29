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
#include <osmocom/netif/prim.h>
#include <osmocom/hnodeb/hnb_prim.h>

struct hnb;

int hnb_llsk_alloc(struct hnb *hnb);
bool hnb_llsk_connected(const struct hnb *hnb);
bool hnb_llsk_can_be_configured(struct hnb *hnb);


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
