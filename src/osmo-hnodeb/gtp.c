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

#include <osmocom/hnodeb/gtp.h>
#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/llsk.h>

#include <gtp.h>
#include <pdp.h>

/* Get osa of locally bound GTP-U socket */
int sk_get_bound_addr(int fd, struct osmo_sockaddr *osa)
{
	int rc;
	socklen_t alen = sizeof(*osa);

	rc = getsockname(fd, (struct sockaddr *)&osa->u.sa, &alen);
	if (rc < 0)
		return rc;

	return 0;
}

/* Called whenever we receive a DATA packet */
static int hnb_gtp_cb_data_ind(struct pdp_t *lib, void *packet, unsigned int len)
{
	struct hnb_gtp_prim *gtp_prim;
	struct hnb_ue *ue = lib->priv;
	struct hnb *hnb = ue->hnb;
	int rc;

	if (!ue || !ue->conn_ps.active) {
		LOGUE(ue, DGTP, LOGL_NOTICE, "Tx GTP-CONN_DATA.ind data=%p len=%u but UE conn_ps is not active!\n",
		      packet, len);
		return -EINVAL;
	}

	LOGUE(ue, DGTP, LOGL_DEBUG, "Tx GTP-CONN_DATA.ind data=%p len=%u\n", packet, len);
	gtp_prim = hnb_gtp_makeprim_conn_data_ind(ue->conn_id, ue->conn_ps.local_tei, packet, len);
	if ((rc = osmo_prim_srv_send(hnb->llsk, gtp_prim->hdr.msg)) < 0) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Failed Tx GTP-CONN_DATA.ind data=%p len=%u\n",
		      packet, len);
	}
	return rc;
}

/* libgtp select loop integration */
static int hnb_gtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct hnb *hnb = fd->data;
	int rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	switch (fd->priv_nr) {
	case 0:
		rc = gtp_decaps1u(hnb->gtp.gsn);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

int hnb_gtp_bind(struct hnb *hnb)
{
	int rc;
	struct gsn_t *gsn;
	struct in_addr inaddr;

	rc = inet_pton(AF_INET, hnb->gtp.cfg_local_addr, &inaddr);
	if (rc <= 0)
		return -EINVAL;

	/* TODO: add new mode GTP_MODE_GTPU_ONLY to set up gtpu side only (and ignore statedir) */
	rc = gtp_new(&gsn, "/tmp", &inaddr, GTP_MODE_SGSN);
	if (rc < 0) {
		LOGP(DGTP, LOGL_ERROR, "Failed to set up GTP socket: %s\n", strerror(-rc));
		return rc;
	}

	rc = sk_get_bound_addr(gsn->fd1u, &hnb->gtp.local_addr);
	if (rc < 0) {
		LOGP(DGTP, LOGL_ERROR, "Failed to get GTP-U socket bound address: %s\n", strerror(-rc));
		goto free_ret;
	}

	osmo_fd_setup(&hnb->gtp.fd1u, gsn->fd1u, OSMO_FD_READ, hnb_gtp_fd_cb, hnb, 0);
	if ((rc = osmo_fd_register(&hnb->gtp.fd1u)) < 0)
		goto free_ret;

	gtp_set_cb_data_ind(gsn, hnb_gtp_cb_data_ind);

	hnb->gtp.gsn = gsn;
	return 0;

free_ret:
	gtp_free(gsn);
	hnb->gtp.fd1u.fd = -1;
	return rc;
}

void hnb_gtp_unbind(struct hnb *hnb)
{
	osmo_fd_unregister(&hnb->gtp.fd1u);
	gtp_free(hnb->gtp.gsn);
	hnb->gtp.gsn = NULL;
	hnb->gtp.fd1u.fd = -1;
}

int hnb_ue_gtp_bind(struct hnb_ue *ue, const struct osmo_sockaddr *rem_addr, uint32_t rem_tei,
		     struct osmo_sockaddr *loc_addr, uint32_t *loc_tei)
{
	int rc;
	struct hnb *hnb = ue->hnb;
	struct pdp_t *pdp;
	struct in_addr rem_in;

	LOGUE(ue, DGTP, LOGL_INFO, "Creating PDP context\n");


	if (rem_addr->u.sa.sa_family != AF_INET) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Failed creating PDP context: unsupported proto family %u\n",
		      rem_addr->u.sa.sa_family);
		return -ENOTSUP;
	}

	rem_in = rem_addr->u.sin.sin_addr;

	rc = gtp_pdp_newpdp(hnb->gtp.gsn, &pdp, ue->conn_id, 0 /* TODO: NSAPI? */, NULL);
	if (rc < 0) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Failed creating PDP context: %s\n", strerror(-rc));
		return rc;
	}
	pdp->priv = ue;
	ue->conn_ps.pdp_lib = pdp;

	pdp->teid_gn = rem_tei;
	pdp->version = 1;
	pdp->hisaddr0 =	rem_in;
	pdp->hisaddr1 = rem_in;

	pdp->gsnru.l = sizeof(rem_in);
	memcpy(pdp->gsnru.v, &rem_in, sizeof(rem_in));


	pdp->gsnlu.l = sizeof(hnb->gtp.local_addr.u.sin.sin_addr);
	memcpy(pdp->gsnlu.v, &hnb->gtp.local_addr.u.sin.sin_addr,
	       sizeof(hnb->gtp.local_addr.u.sin.sin_addr));

	*loc_addr = hnb->gtp.local_addr;
	//loc_addr->u.sin.sin_family = AF_INET;
	//loc_addr->u.sin.sin_addr = hnb->gtp.gsn->gsnu;
	//loc_addr->u.sin.sin_port = GTP1U_PORT;
	*loc_tei = pdp->teid_own;
	return 0;
}

int hnb_ue_gtp_tx(struct hnb_ue *ue, void *gtpu_payload, unsigned gtpu_payload_len)
{
	int rc;
	struct hnb *hnb = ue->hnb;

	if (!hnb->gtp.gsn) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Tx: GTP socket not bound\n");
		return -EINVAL;
	}

	if (!ue || !ue->conn_ps.pdp_lib) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Tx: UE PDP Ctx not available\n");
		return -EINVAL;
	}

	rc = gtp_data_req(hnb->gtp.gsn, ue->conn_ps.pdp_lib, gtpu_payload, gtpu_payload_len);
	return rc;
}

int hnb_ue_gtp_unbind(struct hnb_ue *ue)
{
	if (!ue->conn_ps.pdp_lib)
		return -EINVAL;

	pdp_freepdp(ue->conn_ps.pdp_lib);
	ue->conn_ps.pdp_lib = NULL;
	return 0;
}
