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

#include <errno.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/netif/stream.h>
#include <osmocom/netif/prim.h>

#include <osmocom/trau/osmo_ortp.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/hnb_shutdown_fsm.h>
#include <osmocom/hnodeb/hnb_prim.h>
#include <osmocom/hnodeb/rtp.h>


struct hnb *hnb_alloc(void *tall_ctx)
{
	struct hnb *hnb;

	hnb = talloc_zero(tall_ctx, struct hnb);
	if (!hnb)
		return NULL;

	INIT_LLIST_HEAD(&hnb->ue_list);

	hnb->identity = talloc_strdup(hnb, "OsmoHNodeB");
	hnb->plmn = (struct osmo_plmn_id){
		.mcc = 1,
		.mnc = 1,
	};

	hnb->rtp.jitter_adaptive = false;
	hnb->rtp.port_range_start = 16384;
	hnb->rtp.port_range_end = 17407;
	hnb->rtp.port_range_next = hnb->rtp.port_range_start;
	hnb->rtp.ip_dscp = -1;
	hnb->rtp.priority = -1;

	hnb->shutdown_fi = osmo_fsm_inst_alloc(&hnb_shutdown_fsm, hnb, hnb,
					       LOGL_INFO, NULL);

	hnb_llsk_alloc(hnb);

	hnb_iuh_alloc(hnb);

	return hnb;
}

void hnb_free(struct hnb *hnb)
{
	struct hnb_ue *ue, *ue_tmp;

	llist_for_each_entry_safe(ue, ue_tmp, &hnb->ue_list, list)
		hnb_ue_free(ue);

	if (hnb->shutdown_fi) {
		osmo_fsm_inst_free(hnb->shutdown_fi);
		hnb->shutdown_fi = NULL;
	}
	hnb_iuh_free(hnb);

	osmo_timer_del(&hnb->llsk_defer_configure_ind_timer);
	osmo_prim_srv_link_free(hnb->llsk_link);
	hnb->llsk_link = NULL;

	talloc_free(hnb);
}

struct hnb_ue *hnb_ue_alloc(struct hnb *hnb, uint32_t conn_id)
{
	struct hnb_ue *ue;

	ue = talloc_zero(hnb, struct hnb_ue);
	if (!ue)
		return NULL;

	ue->hnb = hnb;
	ue->conn_id = conn_id;

	llist_add(&ue->list, &hnb->ue_list);

	return ue;
}

void hnb_ue_free(struct hnb_ue *ue)
{
	hnb_ue_reset_chan(ue, true);
	hnb_ue_reset_chan(ue, false);
	llist_del(&ue->list);
	talloc_free(ue);
}

void hnb_ue_reset_chan(struct hnb_ue *ue, bool is_ps)
{
	if (is_ps) {
		ue->conn_ps = (struct hnb_ue_ps_ctx){0};
	} else {
		hnb_ue_voicecall_release(ue);
		ue->conn_cs = (struct hnb_ue_cs_ctx){0};
	}
}

struct hnb_ue *hnb_find_ue_by_id(const struct hnb *hnb, uint32_t conn_id)
{
	struct hnb_ue *ue;

	llist_for_each_entry(ue, &hnb->ue_list, list) {
		if (ue->conn_id != conn_id)
			continue;
		return ue;
	}
	return NULL;
}
struct hnb_ue *hnb_find_ue_by_imsi(const struct hnb *hnb, char *imsi)
{
	struct hnb_ue *ue;

	if (!imsi || imsi[0] == '\0')
		return NULL;

	llist_for_each_entry(ue, &hnb->ue_list, list) {
		if (ue->imsi[0] == '\0')
			continue;
		if (strncmp(&ue->imsi[0], imsi, ARRAY_SIZE(ue->imsi)) != 0)
			continue;
		return ue;
	}
	return NULL;
}
