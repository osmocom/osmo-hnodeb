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

#include <errno.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <osmocom/core/prim.h>
#include <osmocom/core/logging.h>

#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/llsk.h>
#include <osmocom/hnodeb/hnb_prim.h>
#include <osmocom/hnodeb/hnb_shutdown_fsm.h>

int ll_addr_type2af(enum u_addr_type t)
{
	switch (t) {
	case HNB_PRIM_ADDR_TYPE_IPV4:
		return AF_INET;
	case HNB_PRIM_ADDR_TYPE_IPV6:
		return AF_INET6;
	default:
		LOGP(DLLSK, LOGL_ERROR, "Rx unknown address type %u\n", (unsigned)t);
		return -1;
	}
}

int ll_addr2osa(enum u_addr_type t, const union u_addr *uaddr, uint16_t port, struct osmo_sockaddr *osa)
{
	int af = ll_addr_type2af(t);

	osa->u.sa.sa_family = af;

	switch (af) {
	case AF_INET6:
		memcpy(&osa->u.sin6.sin6_addr, &uaddr->v6, sizeof(osa->u.sin6.sin6_addr));
		osa->u.sin6.sin6_port = htons(port);
		break;
	case AF_INET:
		memcpy(&osa->u.sin.sin_addr, &uaddr->v4, sizeof(osa->u.sin.sin_addr));
		osa->u.sin.sin_port = htons(port);
		break;
	default:
		return -1;
	}
	return 0;
}

enum u_addr_type osa2_ll_addr(const struct osmo_sockaddr *osa, union u_addr *uaddr, uint16_t *port)
{
	switch (osa->u.sa.sa_family) {
	case AF_INET6:
		memcpy(&uaddr->v6, &osa->u.sin6.sin6_addr, sizeof(osa->u.sin6.sin6_addr));
		if (port)
			*port = ntohs(osa->u.sin6.sin6_port);
		return HNB_PRIM_ADDR_TYPE_IPV6;
	case AF_INET:
		memcpy(&uaddr->v4, &osa->u.sin.sin_addr, sizeof(osa->u.sin.sin_addr));
		if (port)
			*port = ntohs(osa->u.sin.sin_port);
		return HNB_PRIM_ADDR_TYPE_IPV4;
	default:
		return HNB_PRIM_ADDR_TYPE_UNSPEC;
	}
}

static int llsk_opened_cb(struct osmo_prim_srv *srv)
{
	struct hnb *hnb = (struct hnb *)osmo_prim_srv_get_priv(srv);
	osmo_prim_srv_set_name(srv, "llsk");

	if (hnb->llsk.srv) {
		LOGP(DLLSK, LOGL_ERROR, "New connection opened while one is already active, dropping it\n");
		osmo_prim_srv_close(srv);
		return 0;
	}
	LOGP(DLLSK, LOGL_NOTICE, "LLSK conn is UP\n");
	hnb->llsk.srv = srv;
	return 0;
}

static int llsk_closed_cb(struct osmo_prim_srv *srv)
{
	struct hnb *hnb = (struct hnb *)osmo_prim_srv_get_priv(srv);

	if (!hnb->llsk.srv) {
		LOGP(DLLSK, LOGL_ERROR, "closed_cb received but we have no active llsk conn!\n");
		return 0;
	}
	/* If a later conn different than active one is dropped (because we closed it): */
	if (hnb->llsk.srv != srv)
		return 0;
	LOGP(DLLSK, LOGL_NOTICE, "LLSK conn is DOWN\n");

	hnb->llsk.srv = NULL;
	hnb->llsk.valid_sapi_mask = 0x0;
	osmo_timer_del(&hnb->llsk.defer_configure_ind_timer);
	hnb_shutdown(hnb, "LLSK conn dropped", false);
	return 0;
}

bool hnb_llsk_connected(const struct hnb *hnb)
{
	return !!hnb->llsk.srv;
}

bool hnb_llsk_can_be_configured(struct hnb *hnb)
{
	if (!hnb->registered)
		return false;
	if (!hnb->llsk.srv)
		return false;

	if (hnb->llsk.valid_sapi_mask & (1 << HNB_PRIM_SAPI_IUH) &&
	    hnb->llsk.valid_sapi_mask & (1 << HNB_PRIM_SAPI_AUDIO) &&
	    hnb->llsk.valid_sapi_mask & (1 << HNB_PRIM_SAPI_GTP))
		return true;
	return false;
}

static void llsk_defer_configure_ind_timer_cb(void *data)
{
	struct hnb *hnb = (struct hnb *)data;
	llsk_iuh_tx_configure_ind(hnb);
}

static int llsk_rx_sapi_version_cb(struct osmo_prim_srv *prim_srv, uint32_t sapi, uint16_t rem_version)
{
	struct hnb *hnb = (struct hnb *)osmo_prim_srv_get_priv(prim_srv);
	if (sapi > sizeof(hnb->llsk.valid_sapi_mask)*8 - 1)
		return -1;

	switch (sapi) {
	case HNB_PRIM_SAPI_IUH:
		if (rem_version < LLSK_SAPI_IUH_VERSION_MIN)
			return -1;
		if (rem_version > LLSK_SAPI_IUH_VERSION_MAX)
			return LLSK_SAPI_IUH_VERSION_MAX;
		hnb->llsk.sapi_version_iuh = rem_version;
		break;
	case HNB_PRIM_SAPI_GTP:
		if (rem_version < LLSK_SAPI_GTP_VERSION_MIN)
			return -1;
		if (rem_version > LLSK_SAPI_GTP_VERSION_MAX)
			return LLSK_SAPI_GTP_VERSION_MAX;
		hnb->llsk.sapi_version_gtp = rem_version;
		break;
	case HNB_PRIM_SAPI_AUDIO:
		if (rem_version < LLSK_SAPI_AUDIO_VERSION_MIN)
			return -1;
		if (rem_version > LLSK_SAPI_AUDIO_VERSION_MAX)
			return LLSK_SAPI_AUDIO_VERSION_MAX;
		if (llsk_audio_sapi_version_confirmed(rem_version) < 0)
			return -1;
		hnb->llsk.sapi_version_audio = rem_version;
		break;
	default:
		return -1;
	}

	hnb->llsk.valid_sapi_mask |= (1 << sapi);

	/* Defer CONFIGURE.req after we have confirmed the versions */
	if (hnb_llsk_can_be_configured(hnb))
		osmo_timer_schedule(&hnb->llsk.defer_configure_ind_timer, 0, 0);

	return rem_version;
}

static int llsk_rx_cb(struct osmo_prim_srv *srv, struct osmo_prim_hdr *oph)
{
	struct hnb *hnb = (struct hnb *)osmo_prim_srv_get_priv(srv);
	LOGP(DLLSK, LOGL_DEBUG, "llsk_rx_cb() SAP=%u (%u bytes): %s\n", oph->sap,
	     msgb_length(oph->msg), osmo_hexdump(msgb_data(oph->msg), msgb_length(oph->msg)));

	switch (oph->sap) {
	case HNB_PRIM_SAPI_IUH:
		return llsk_rx_iuh(hnb, oph);
	case HNB_PRIM_SAPI_GTP:
		return llsk_rx_gtp(hnb, oph);
	case HNB_PRIM_SAPI_AUDIO:
		return llsk_rx_audio(hnb, oph);
	default:
		LOGP(DLLSK, LOGL_ERROR, "Rx msg for unknown SAPI %u (len=%u)\n",
		     oph->sap, msgb_length(oph->msg));
		return -EINVAL;
	}
}

int hnb_llsk_alloc(struct hnb *hnb)
{
	hnb->llsk.link = osmo_prim_srv_link_alloc(hnb);
	osmo_prim_srv_link_set_priv(hnb->llsk.link, hnb);
	osmo_prim_srv_link_set_name(hnb->llsk.link, "llsk-link");
	osmo_prim_srv_link_set_log_category(hnb->llsk.link, DLLSK);
	osmo_prim_srv_link_set_addr(hnb->llsk.link, HNB_PRIM_UD_SOCK_DEFAULT);
	osmo_prim_srv_link_set_opened_conn_cb(hnb->llsk.link, llsk_opened_cb);
	osmo_prim_srv_link_set_closed_conn_cb(hnb->llsk.link, llsk_closed_cb);
	osmo_prim_srv_link_set_rx_sapi_version_cb(hnb->llsk.link, llsk_rx_sapi_version_cb);
	osmo_prim_srv_link_set_rx_cb(hnb->llsk.link, llsk_rx_cb);
	osmo_timer_setup(&hnb->llsk.defer_configure_ind_timer, llsk_defer_configure_ind_timer_cb, hnb);
	return 0;
}

void hnb_llsk_free(struct hnb *hnb)
{
	osmo_timer_del(&hnb->llsk.defer_configure_ind_timer);
	osmo_prim_srv_link_free(hnb->llsk.link);
	hnb->llsk.link = NULL;
}

int hnb_llsk_start_listen(struct hnb *hnb)
{
	return osmo_prim_srv_link_open(g_hnb->llsk.link);
}
