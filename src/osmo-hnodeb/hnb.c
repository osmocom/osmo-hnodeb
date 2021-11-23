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

#include "config.h"

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/netif/stream.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/hnb_shutdown_fsm.h>


struct hnb *hnb_alloc(void *tall_ctx)
{
	struct hnb *hnb;

	hnb = talloc_zero(tall_ctx, struct hnb);
	if (!hnb)
		return NULL;

	hnb->identity = talloc_strdup(hnb, "OsmoHNodeB");
	hnb->plmn = (struct osmo_plmn_id){
		.mcc = 1,
		.mnc = 1,
	};

	hnb->shutdown_fi = osmo_fsm_inst_alloc(&hnb_shutdown_fsm, hnb, hnb,
					       LOGL_INFO, NULL);

	hnb_iuh_alloc(hnb);

	return hnb;
}

void hnb_free(struct hnb *hnb)
{
	if (hnb->shutdown_fi) {
		osmo_fsm_inst_free(hnb->shutdown_fi);
		hnb->shutdown_fi = NULL;
	}
	hnb_iuh_free(hnb);
	talloc_free(hnb);
}
