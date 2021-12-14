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
/* This header includes information relative to protocol and message structure
 * spoken between osmo-hnodeb, facing the HNBGW and other RAN/CN nodes, and a
 * Lower Layer program (aka the TRX), implementing the RLC/MAC/RRC towards the
 * UE in the Uu interface. This protocol is usually referenced as HNBLLIF. The
 * protocol is primitive based and follows the concepts described in ITU-T
 * X.210, with osmo-hnodeb taking the "service provider" role and the TRX taking
 * the "user" role in this case.
 */

#pragma once

#include <inttypes.h>
#include <unistd.h>
#include <stdint.h>

#include <osmocom/core/prim.h>

#define HNB_PRIM_API_VERSION 0
#define HNB_PRIM_UD_SOCK_DEFAULT "/tmp/hnb_prim_sock"

#define HNB_PRIM_SAPI_IUH 1
#define HNB_PRIM_SAPI_GTP 2
#define HNB_PRIM_SAPI_AUDIO 3

enum u_addr_type {
	HNB_PRIM_ADDR_TYPE_UNSPEC,
	HNB_PRIM_ADDR_TYPE_IPV4,
	HNB_PRIM_ADDR_TYPE_IPV6
};
union u_addr {
	struct in_addr v4;
	struct in6_addr v6;
} __attribute__ ((packed));

/*! \brief HNB_IUH primitives */
enum hnb_iuh_prim_type {
	HNB_IUH_PRIM_CONFIGURE,
	HNB_IUH_PRIM_CONN_ESTABLISH,
	HNB_IUH_PRIM_CONN_RELEASE,
	HNB_IUH_PRIM_CONN_DATA,
	HNB_IUH_PRIM_UNITDATA,
	_HNB_IUH_PRIM_MAX
};

/* HNB_IUH_PRIM_CONFIGURE.ind, DL */
struct hnb_iuh_configure_ind_param {
	uint16_t mcc;
	uint16_t mnc;
	uint16_t cell_identity;
	uint16_t lac;
	uint8_t rac;
	uint8_t reserved;
	uint16_t sac;
	uint16_t rnc_id;
} __attribute__ ((packed));

/* HNB_HNB_IUH_PRIM_CONN_ESTABLISH.ind, DL */
struct hnb_iuh_conn_establish_ind_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t cause;
	uint8_t csg_membership_status;
	uint8_t spare1;
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_HNB_IUH_PRIM_CONN_ESTABLISH.req, UL */
struct hnb_iuh_conn_establish_req_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t est_cause;
	/* TODO: Check if we can copy it as an encoded buffer RRC <-> RUA
	 * RRC: 3GPP TS 25.331 10.3.1.6 Intra Domain NAS Node Selector
	 * RUA:  3GPP TS 25.468 9.2.4  */
	uint16_t reserved; //uint16_t nas_node_selector_bitlen;
	//uint8_t nas_node_selector[128]; /* TODO: check whether we can decrease this buffer size */
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_HNB_IUH_PRIM_CONN_ESTABLISH.cnf, DL */
struct hnb_iuh_conn_establish_cnf_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t cause; /* 0 = success, !0 = failure */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_CONN_RELEASE.req, DL */
struct hnb_iuh_conn_release_req_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t spare1;
	uint8_t cause_type; /* 3GPP TS 25.468 9.2.7 Cause */
	uint8_t cause; /* 3GPP TS 25.468 9.2.7 Cause */
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_CONN_RELEASE.ind, UL */
struct hnb_iuh_conn_release_ind_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t spare1;
	uint8_t cause_type;
	uint8_t cause;
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_CONN_DATA.req, DL */
struct hnb_iuh_conn_data_req_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t spare1;
	uint16_t spare2;
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_CONN_DATA.ind, UL */
struct hnb_iuh_conn_data_ind_param {
	uint32_t context_id;
	uint8_t domain;
	uint8_t spare1;
	uint16_t spare2;
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_UNITDATA.req, UL */
struct hnb_iuh_unitdata_req_param {
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

/* HNB_IUH_PRIM_UNITDATA.ind, DL */
struct hnb_iuh_unitdata_ind_param {
	uint32_t data_len; /* RANAP message length in bytes */
	uint8_t data[0]; /* RANAP message */
} __attribute__ ((packed));

struct hnb_iuh_prim {
	struct osmo_prim_hdr hdr;
	union {
		struct hnb_iuh_configure_ind_param configure_ind;
		struct hnb_iuh_conn_establish_req_param conn_establish_req;
		struct hnb_iuh_conn_establish_ind_param conn_establish_ind;
		struct hnb_iuh_conn_establish_cnf_param conn_establish_cnf;
		struct hnb_iuh_conn_release_req_param conn_release_req;
		struct hnb_iuh_conn_release_ind_param conn_release_ind;
		struct hnb_iuh_conn_data_req_param conn_data_req;
		struct hnb_iuh_conn_data_ind_param conn_data_ind;
		struct hnb_iuh_unitdata_req_param unitdata_req;
		struct hnb_iuh_unitdata_ind_param unitdata_ind;
	} u;
} __attribute__ ((packed));

/****************************
 * AUDIO
 ***************************/
/*! \brief HNB_AUDIO primitives */
enum hnb_audio_prim_type {
	HNB_AUDIO_PRIM_CONN_ESTABLISH,
	HNB_AUDIO_PRIM_CONN_RELEASE,
	HNB_AUDIO_PRIM_CONN_DATA,
	_HNB_AUDIO_PRIM_MAX
};

/* HNB_AUDIO_PRIM_CONN_ESTABLISH, UL */
struct hnb_audio_conn_establish_req_param {
	uint32_t context_id;
	uint16_t remote_rtp_port;
	uint8_t spare1;
	uint8_t remote_rtp_address_type;  /* enum u_addr_type */
	union u_addr remote_rtp_addr;
} __attribute__ ((packed));

/* HNB_AUDIO_PRIM_CONN_ESTABLISH, DL */
struct hnb_audio_conn_establish_cnf_param {
	uint32_t context_id;
	uint32_t audio_conn_id;
	uint16_t local_rtp_port;
	uint8_t error_code; /* 0 = success, !0 = failure */
	uint8_t local_rtp_address_type; /* enum u_addr_type */
	union u_addr local_rtp_addr;
} __attribute__ ((packed));

/* HNB_AUDIO_PRIM_CONN_RELEASE, UL */
struct hnb_audio_conn_release_req_param {
	uint32_t audio_conn_id;
} __attribute__ ((packed));

/* HNB_AUDIO_PRIM_CONN_DATA, UL */
struct hnb_audio_conn_data_req_param {
	uint32_t audio_conn_id;
	uint32_t data_len; /* RTP payload length in bytes */
	uint8_t data[0]; /* RTP payload (aka IP packet) */
} __attribute__ ((packed));

/* HNB_AUDIO_PRIM_CONN_DATA, DL */
struct hnb_audio_conn_data_ind_param {
	uint32_t audio_conn_id;
	uint32_t data_len; /* RTP payload length in bytes */
	uint8_t data[0]; /* RTP payload (aka IP packet) */
} __attribute__ ((packed));

struct hnb_audio_prim {
	struct osmo_prim_hdr hdr;
	union {
		struct hnb_audio_conn_establish_req_param conn_establish_req;
		struct hnb_audio_conn_establish_cnf_param conn_establish_cnf;
		struct hnb_audio_conn_release_req_param conn_release_req;
		struct hnb_audio_conn_data_req_param conn_data_req;
		struct hnb_audio_conn_data_ind_param conn_data_ind;
	} u;
} __attribute__ ((packed));

/****************************
 * GTP
 ***************************/
/*! \brief HNB_GTP primitives */
enum hnb_gtp_prim_type {
	HNB_GTP_PRIM_CONN_ESTABLISH,
	HNB_GTP_PRIM_CONN_RELEASE,
	HNB_GTP_PRIM_CONN_DATA,
	_HNB_GTP_PRIM_MAX
};

/* HNB_GTP_PRIM_CONN_ESTABLISH, UL */
struct hnb_gtp_conn_establish_req_param {
	uint32_t context_id;
	uint32_t remote_tei;
	uint8_t spare1;
	uint8_t remote_gtpu_address_type;
	union u_addr remote_gtpu_addr;
} __attribute__ ((packed));

/* HNB_GTP_PRIM_CONN_ESTABLISH, DL */
struct hnb_gtp_conn_establish_cnf_param {
	uint32_t context_id;
	uint32_t gtp_conn_id;
	uint32_t local_tei;
	uint8_t error_code; /* 0 = success, !0 = failure */
	uint8_t local_gtpu_address_type;   /* enum u_addr_type */
	union u_addr local_gtpu_addr;
} __attribute__ ((packed));

/* HNB_GTP_PRIM_CONN_RELEASE, UL */
struct hnb_gtp_conn_release_req_param {
	uint32_t gtp_conn_id;
} __attribute__ ((packed));

/* HNB_GTP_PRIM_CONN_DATA, DL */
struct hnb_gtp_conn_data_ind_param {
	uint32_t gtp_conn_id;
	uint32_t data_len; /* GTP-U payload length in bytes */
	uint8_t data[0]; /* GTP-U payload (aka IP packet) */
} __attribute__ ((packed));

/* HNB_GTP_PRIM_CONN_DATA, UL */
struct hnb_gtp_conn_data_req_param {
	uint32_t gtp_conn_id;
	uint32_t data_len; /* GTP-U payload length in bytes */
	uint8_t data[0]; /* GTP-U payload (aka IP packet) */
} __attribute__ ((packed));

struct hnb_gtp_prim {
	struct osmo_prim_hdr hdr;
	union {
		struct hnb_gtp_conn_establish_req_param conn_establish_req;
		struct hnb_gtp_conn_establish_cnf_param conn_establish_cnf;
		struct hnb_gtp_conn_release_req_param conn_release_req;
		struct hnb_gtp_conn_data_req_param conn_data_req;
		struct hnb_gtp_conn_data_ind_param conn_data_ind;
	} u;
} __attribute__ ((packed));
