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

struct hnb;
struct ranap_message_s;
#include <osmocom/hnodeb/hnodeb.h>

void hnb_rx_iu_release(struct hnb *hnb);
void hnb_rx_paging(struct hnb *hnb, const char *imsi);
void hnb_rx_secmode_cmd(struct hnb *hnb, long ip_alg);

void hnb_rua_dt_handle_ranap(struct hnb *hnb, struct ranap_message_s *ranap_msg);
void hnb_rua_cl_handle_ranap(struct hnb *hnb, struct ranap_message_s *ranap_msg);
void hnb_tx_iu_release_req(struct hnb *hnb);
struct msgb *gen_initue_lu(const struct hnb *hnb, int is_ps, uint32_t conn_id, const char *imsi);
