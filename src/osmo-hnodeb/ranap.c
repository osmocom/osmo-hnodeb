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
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>

struct msgb *hnb_ranap_msgb_alloc(void)
{
	return msgb_alloc(1000, "ranap_tx");
}
