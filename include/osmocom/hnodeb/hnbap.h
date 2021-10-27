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

#include <asn1c/ANY.h>

struct hnb;
struct msg;

int hnb_hnbap_rx(struct hnb *hnb, struct msgb *msg);

int hnb_ue_register_tx(struct hnb *hnb, const char *imsi_str);
void hnb_send_register_req(struct hnb *hnb);
void hnb_send_deregister_req(struct hnb *hnb);
