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
#include <asn1c/ANY.h>

#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/ranap/ranap_common_cn.h>

#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>


void hnb_rua_dt_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_DirectTransferIEs_t ies;
	int rc;

	rc = rua_decode_directtransferies(&ies, in);
	if (rc < 0) {
		printf("failed to decode RUA DT IEs\n");
		return;
	}

	rc = ranap_cn_rx_co(hnb_rua_dt_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_directtransferies(&ies);
}

void hnb_rua_cl_handle(struct hnb *hnb, ANY_t *in)
{
	RUA_ConnectionlessTransferIEs_t ies;
	int rc;

	rc = rua_decode_connectionlesstransferies(&ies, in);
	if (rc < 0) {
		printf("failed to decode RUA CL IEs\n");
		return;
	}

	rc = ranap_cn_rx_cl(hnb_rua_cl_handle_ranap, hnb, ies.ranaP_Message.buf, ies.ranaP_Message.size);

	/* FIXME: what to do with the asn1c-allocated memory */
	rua_free_connectionlesstransferies(&ies);
}
