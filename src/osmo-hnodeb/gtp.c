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
#include <osmocom/core/endian.h>

/* 3GPP TS 29.281 */
struct gtp1u_hdr {	/* 3GPP TS 29.281 */
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t pn:1, /* N-PDU Number flag */
		s:1, /* Sequence number flag */
		e:1, /* Extension header flag */
		spare:1,
		pt:1, /* Protocol Type: GTP=1, GTP'=0 */
		version:3; /* Version: 1 */
#elif OSMO_IS_BIG_ENDIAN
	uint8_t version:3, pt:1, spare:1, e:1, s:1, pn:1;
#endif
	uint8_t msg_type;
	uint16_t length;
	uint32_t tei;		/* 05 - 08 Tunnel Endpoint ID */
	uint8_t data[0];
} __attribute__((packed));

static uint32_t next_gtp_conn_id = 1;

struct gtp_conn *gtp_conn_alloc(struct hnb_ue *ue)
{
	struct gtp_conn *conn;

	conn = talloc_zero(ue, struct gtp_conn);
	if (!conn)
		return NULL;

	conn->ue = ue;

	llist_add(&conn->list, &ue->conn_ps.conn_list);

	return conn;
}

void gtp_conn_free(struct gtp_conn *conn)
{
	if (!conn)
		return;

	llist_del(&conn->list);
	talloc_free(conn);
}

int gtp_conn_setup(struct gtp_conn *conn, const struct osmo_sockaddr *rem_addr, uint32_t rem_tei)
{
	struct hnb_ue *ue = conn->ue;
	struct hnb *hnb = ue->hnb;

	LOGUE(ue, DGTP, LOGL_INFO, "Creating PDP context\n");


	if (rem_addr->u.sa.sa_family != AF_INET) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Failed creating PDP context: unsupported proto family %u\n",
		      rem_addr->u.sa.sa_family);
		return -ENOTSUP;
	}

	conn->id = next_gtp_conn_id++; /* TODO: validate next one is not already taken due to wrap-around */

	conn->loc_addr = hnb->gtp.local_addr;
	conn->rem_addr = *rem_addr;
	conn->rem_tei = rem_tei;
	conn->loc_tei = conn->id; /* We use conn ID as local TEI */
	return 0;
}

int gtp_conn_tx(struct gtp_conn *conn, const uint8_t *gtpu_payload, unsigned gtpu_payload_len)
{
	int rc;
	struct hnb_ue *ue;
	struct hnb *hnb;
	struct msgb *msg;
	struct gtp1u_hdr *hdr;
	struct osmo_sockaddr *sa;
	const uint8_t opt_hdr_len = 4;
	unsigned msg_len = sizeof(*hdr) + opt_hdr_len + gtpu_payload_len;

	if (!conn) {
		LOGP(DGTP, LOGL_ERROR, "Tx: GTP-U conn not available\n");
		return -EINVAL;
	}

	ue = conn->ue;
	hnb = ue->hnb;

	if (hnb->gtp.wq1u.bfd.fd == -1) {
		LOGP(DGTP, LOGL_ERROR, "Tx: GTP-U socket not available\n");
		return -EINVAL;
	}

	if (gtpu_payload_len == 0) {
		LOGP(DGTP, LOGL_ERROR, "Tx: GTP-U len=0\n");
		return -EINVAL;
	}

	msg = msgb_alloc_c(hnb, sizeof(*sa) + msg_len, "gtp-ul");

	sa = (struct osmo_sockaddr *)msgb_put(msg, sizeof(*sa));
	*sa = conn->rem_addr;

	hdr = (struct gtp1u_hdr *)msgb_put(msg,  msg_len);
	hdr->pn = 0;
	hdr->s = 1;
	hdr->e = 0;
	hdr->spare = 0;
	hdr->pt = 1;
	hdr->version = 1;
	hdr->msg_type = 0xff;
	osmo_store16be(gtpu_payload_len + opt_hdr_len, &hdr->length);
	osmo_store32be(conn->rem_tei, &hdr->tei);
	osmo_store16be(conn->seq_nr, &hdr->data[0]);
	conn->seq_nr++;
	/* byes 2 and 3 are set to 0 */
	memcpy(&hdr->data[opt_hdr_len], gtpu_payload, gtpu_payload_len);

	rc = osmo_wqueue_enqueue(&hnb->gtp.wq1u, msg);
	if (rc < 0)
		msgb_free(msg);

	return rc;
}

/* Called whenever we receive a DATA packet */
static int hnb_gtp_rx_gtp(struct hnb *hnb, struct msgb *msg, const struct osmo_sockaddr *from)
{
	struct gtp_conn *conn;
	struct hnb_ue *ue;
	struct gtp1u_hdr *hdr;
	uint32_t tei;
	struct hnb_gtp_prim *gtp_prim;
	int rc;

	hdr = (struct gtp1u_hdr *)msgb_data(msg);
	tei = osmo_load32be(&hdr->tei);

	/* The local TEI is the GTP conn_id: */
	conn = hnb_find_gtp_conn_by_id(hnb, tei);
	if (!conn) {
		LOGP(DGTP, LOGL_NOTICE, "Tx GTP-CONN_DATA.ind len=%u with no conn!\n",
		     msgb_l3len(msg));
		rc = -EINVAL;
		goto free_ret;
	}
	ue = conn->ue;

	if (osmo_sockaddr_cmp(from, &conn->rem_addr)) {
		LOGUE(ue, DGTP, LOGL_NOTICE, "Rx DL GTP-U loc_tei=0x%08x from unexpected addr=%s!\n",
		      tei, osmo_sockaddr_to_str(from));
		rc = -EINVAL;
		goto free_ret;
	}
	ue = conn->ue;

	if (!ue->conn_ps.active) {
		LOGUE(ue, DGTP, LOGL_NOTICE, "Tx GTP-CONN_DATA.ind len=%u but UE conn_ps is not active!\n",
		      msgb_l3len(msg));
		rc = -EINVAL;
		goto free_ret;
	}
	hnb = ue->hnb;

	LOGUE(ue, DGTP, LOGL_DEBUG, "Tx GTP-CONN_DATA.ind len=%u\n", msgb_l3len(msg));
	gtp_prim = hnb_gtp_makeprim_conn_data_ind(conn->id, msgb_l3(msg), msgb_l3len(msg));
	if ((rc = osmo_prim_srv_send(hnb->llsk, gtp_prim->hdr.msg)) < 0) {
		LOGUE(ue, DGTP, LOGL_ERROR, "Failed Tx GTP-CONN_DATA.ind len=%u\n",
		      msgb_l3len(msg));
	}
free_ret:
	msgb_free(msg);
	return rc;
}

static int hnb_gtp_wq_read_cb(struct osmo_fd *fd)
{
	struct hnb *hnb = (struct hnb *)fd->data;
	struct msgb *msg;
	struct gtp1u_hdr *hdr;
	int rc;
	struct osmo_sockaddr peer;
	socklen_t peerlen = sizeof(peer.u.sas);
	unsigned int opt_hdr_len;
	uint16_t pl_len;

	msg = msgb_alloc_c(hnb, 4096, "gtp-dl");

	rc = recvfrom(hnb->gtp.wq1u.bfd.fd, msgb_data(msg), msg->data_len, 0,
		      &peer.u.sa, &peerlen);
	if (rc <= 0) {
		LOGP(DGTP, LOGL_ERROR, "recvfrom() failed: rc = %d error = %s\n",
		     rc, rc ? strerror(errno) : "No error");
		goto free_ret;
	}
	msgb_put(msg, rc);

	/* Do some sanity checks: */
	if (msgb_length(msg) < sizeof(*hdr)) {
		LOGP(DGTP, LOGL_ERROR, "Rx GTP-U packet with size %u < %zu (header)\n",
		     msgb_length(msg), sizeof(*hdr));
		rc = -EINVAL;
		goto free_ret;
	}

	hdr = (struct gtp1u_hdr *)msgb_data(msg);
	pl_len = osmo_load16be(&hdr->length);

	/* Do some sanity checks: */
	if (hdr->version != 1) {
		LOGP(DGTP, LOGL_ERROR, "Rx GTP-U version %u != 1\n", hdr->version);
		rc = -ENOTSUP;
		goto free_ret;
	}

	if (hdr->e == 1) {
		LOGP(DGTP, LOGL_ERROR, "Rx GTP-U with Extension Header not supported\n");
		rc = -ENOTSUP;
		goto free_ret;
	}

	if (hdr->s || hdr->pn || hdr->e)
		opt_hdr_len = 4;
	if (hdr->pn)
		opt_hdr_len = 0;

	if (msgb_length(msg) < sizeof(*hdr) + opt_hdr_len) {
		LOGP(DGTP, LOGL_ERROR, "Rx GTP-U packet with size %u < %zu (header + opt)\n",
		     msgb_length(msg), sizeof(*hdr) + opt_hdr_len);
		rc = -EINVAL;
		goto free_ret;
	}

	msg->l3h = msgb_data(msg) + sizeof(*hdr) + opt_hdr_len;

	if (pl_len < opt_hdr_len || msgb_l3len(msg) != (pl_len - opt_hdr_len)) {
		LOGP(DGTP, LOGL_ERROR, "Rx GTP-U packet with payload size %u != %u (header)\n",
		     msgb_length(msg), pl_len - opt_hdr_len);
		rc = -EINVAL;
		goto free_ret;
	}

	return hnb_gtp_rx_gtp(hnb, msg, &peer);
free_ret:
	msgb_free(msg);
	return rc;
}

static int hnb_gtp_wq_write_cb(struct osmo_fd *fd, struct msgb *msg)
{
	struct hnb *hnb = (struct hnb *)fd->data;
	struct osmo_sockaddr *rem_addr;
	int rc;

	rem_addr = (struct osmo_sockaddr *)msgb_data(msg);
	msgb_pull(msg, sizeof(*rem_addr));

	rc = sendto(hnb->gtp.wq1u.bfd.fd, msgb_data(msg), msgb_length(msg), 0,
		    &rem_addr->u.sa, sizeof(*rem_addr));
	if (rc < 0) {
		int err = errno;
		LOGP(DGTP, LOGL_ERROR, "GTP1-U sendto(len=%d, to=%s) failed: Error = %s\n",
		     msgb_length(msg), osmo_sockaddr_to_str(rem_addr), strerror(err));
	}
	return rc;
}

/* Get osa of locally bound GTP-U socket */
static int sk_get_bound_addr(int fd, struct osmo_sockaddr *osa)
{
	int rc;
	socklen_t alen = sizeof(*osa);

	rc = getsockname(fd, (struct sockaddr *)&osa->u.sa, &alen);
	if (rc < 0)
		return rc;

	return 0;
}

int hnb_gtp_bind(struct hnb *hnb)
{
	int rc;

	OSMO_ASSERT(hnb->gtp.wq1u.bfd.fd == -1);

	hnb->gtp.wq1u.read_cb = hnb_gtp_wq_read_cb;
	hnb->gtp.wq1u.write_cb = hnb_gtp_wq_write_cb;

	rc = osmo_sock_init2_ofd(&hnb->gtp.wq1u.bfd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
			     hnb->gtp.cfg_local_addr, 2152, NULL, 0, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		LOGP(DGTP, LOGL_ERROR, "Failed to set up GTP socket: %s\n", strerror(-rc));
		return rc;
	}

	rc = sk_get_bound_addr(hnb->gtp.wq1u.bfd.fd, &hnb->gtp.local_addr);
	if (rc < 0) {
		LOGP(DGTP, LOGL_ERROR, "Failed to get GTP-U socket bound address: %s\n", strerror(-rc));
		goto free_ret;
	}
	return 0;

free_ret:
	if (hnb->gtp.wq1u.bfd.fd != -1) {
		close(hnb->gtp.wq1u.bfd.fd);
		hnb->gtp.wq1u.bfd.fd = -1;
	}
	return rc;
}

void hnb_gtp_unbind(struct hnb *hnb)
{
	if (hnb->gtp.wq1u.bfd.fd != -1) {
		osmo_wqueue_clear(&hnb->gtp.wq1u);
		osmo_fd_unregister(&hnb->gtp.wq1u.bfd);
		close(hnb->gtp.wq1u.bfd.fd);
		hnb->gtp.wq1u.bfd.fd = -1;
	}
}
