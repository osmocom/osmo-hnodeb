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

#include <unistd.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/command.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/rua/rua_msg_factory.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnodeb/iuh.h>
#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/vty.h>
#include <osmocom/hnodeb/hnodeb.h>

int hnb_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case IUH_NODE:
		vty->node = HNODEB_NODE;
		vty->index = g_hnb;
		break;
	case LLSK_NODE:
		vty->node = HNODEB_NODE;
		vty->index = g_hnb;
		break;
	case GTP_NODE:
		vty->node = HNODEB_NODE;
		vty->index = g_hnb;
		break;
	case HNODEB_NODE:
		vty->node = CONFIG_NODE;
		vty->index = g_hnb;
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		break;
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}

	return vty->node;
}

static struct cmd_node hnodeb_node = {
	HNODEB_NODE,
	"%s(config-hnodeb)# ",
	1,
};

#define HNODEB_STR "Configure the HNodeB\n"
#define CODE_CMD_STR "Code commands\n"

DEFUN(cfg_hnodeb,
      cfg_hnodeb_cmd,
      "hnodeb", HNODEB_STR)
{
	OSMO_ASSERT(g_hnb);
	vty->index = g_hnb;
	vty->node = HNODEB_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_identity,
	      cfg_hnodeb_identity_cmd,
	      0,
	      "identity TEXT",
	      "Set the HNB-identity of this HnodeB\n" "HNB-Identity\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	osmo_talloc_replace_string(g_hnb, &hnb->identity, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_ncc,
	      cfg_hnodeb_ncc_cmd,
	      0,
	      "network country code <1-999>",
	      "Set the GSM network country code\n"
	      "Country commands\n"
	      CODE_CMD_STR
	      "Network Country Code to use\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	uint16_t mcc;

	if (osmo_mcc_from_str(argv[0], &mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	hnb->plmn.mcc = mcc;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_mnc,
	      cfg_hnodeb_mnc_cmd,
	      0,
	      "mobile network code <0-999>",
	      "Set the GSM mobile network code\n"
	      "Network Commands\n"
	      CODE_CMD_STR
	      "Mobile Network Code to use\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	hnb->plmn.mnc = mnc;
	hnb->plmn.mnc_3_digits = mnc_3_digits;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_ci,
	      cfg_hnodeb_ci_cmd,
	      0,
	      "cell_identity <0-65535>",
	      "Set the Cell identity of this HnodeB\n" "Cell Identity\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	hnb->cell_identity = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_lac,
	      cfg_hnodeb_lac_cmd,
	      0,
	      "location_area_code <0-65535>",
	      "Set the Location Area Code (LAC) of this HnodeB\n" "LAC\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	int lac = atoi(argv[0]);

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}
	hnb->lac = lac;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_rac,
	      cfg_hnodeb_rac_cmd,
	      0,
	      "routing_area_code <0-255>",
	      "Set the Routing Area Code (RAC) of this HnodeB\n" "RAC\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	hnb->rac = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_hnodeb_sac,
	      cfg_hnodeb_sac_cmd,
	      0,
	      "service_area_code <0-65535>",
	      "Set the Service Area Code (SAC) of this HnodeB\n" "SAC\n")
{
	struct hnb *hnb = (struct hnb *)vty->index;
	hnb->sac = atoi(argv[0]);
	return CMD_SUCCESS;
}

static struct cmd_node iuh_node = {
	IUH_NODE,
	"%s(config-iuh)# ",
	1,
};

DEFUN(cfg_hnodeb_iuh,
      cfg_hnodeb_iuh_cmd,
      "iuh", "Configure Iuh options\n")
{
	OSMO_ASSERT(g_hnb);
	vty->index = g_hnb;
	vty->node = IUH_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_iuh_local_ip, cfg_hnodeb_iuh_local_ip_cmd,
      "local-ip " VTY_IPV46_CMD,
      "Bind Iuh connection on local IP address\n"
      "Local interface IPv4 address\n"
      "Local interface IPv6 address\n")
{
	osmo_talloc_replace_string(g_hnb, &g_hnb->iuh.local_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_iuh_local_port, cfg_hnodeb_iuh_local_port_cmd,
      "local-port <1-65535>",
      "Bind Iuh connection on local SCTP port\n"
      "Local interface port\n")
{
	g_hnb->iuh.local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_iuh_remote_ip, cfg_hnodeb_iuh_remote_ip_cmd,
      "remote-ip " VTY_IPV46_CMD,
      "Connect to HNBGW over Iuh on remote IP address\n"
      "Remote interface IPv4 address\n"
      "Remote interface IPv6 address\n")
{
	osmo_talloc_replace_string(g_hnb, &g_hnb->iuh.remote_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_iuh_remote_port, cfg_hnodeb_iuh_remote_port_cmd,
      "remote-port <1-65535>",
      "Connect to HNBGW over Iuh on remote SCTP port\n"
      "Remote interface port (default: "OSMO_STRINGIFY_VAL(IUH_DEFAULT_SCTP_PORT) ")\n")
{
	g_hnb->iuh.remote_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

static struct cmd_node llsk_node = {
	LLSK_NODE,
	"%s(config-ll-socket)# ",
	1,
};

#define LLSK_STR "Configure the Lower Layer Unix Domain Socket\n"

DEFUN(cfg_hnodeb_llsk,
      cfg_hnodeb_llsk_cmd,
      "ll-socket", LLSK_STR)
{
	OSMO_ASSERT(g_hnb);
	vty->index = g_hnb;
	vty->node = LLSK_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_llsk_path, cfg_hnodeb_llsk_path_cmd,
      "path PATH",
      "Configure the Lower Layer Unix Domain Socket path\n"
      "UNIX socket path\n")
{
	osmo_prim_srv_link_set_addr(g_hnb->llsk.link, argv[0]);

	/* FIXME: re-open the interface? */
	return CMD_SUCCESS;
}

static struct cmd_node gtp_node = {
	GTP_NODE,
	"%s(config-gtp)# ",
	1,
};

#define GTP_STR "Configure the GPRS Tunnelling Protocol parameters\n"

DEFUN(cfg_hnodeb_gtp,
      cfg_hnodeb_gtp_cmd,
      "gtp", GTP_STR)
{
	OSMO_ASSERT(g_hnb);
	vty->index = g_hnb;
	vty->node = GTP_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_hnodeb_gtp_local_ip, cfg_hnodeb_gtp_local_ip_cmd,
      "local-ip " VTY_IPV4_CMD,
      "Configure the GTP-U bind address\n"
      "GTP-U local IPv4 address\n")
{
	osmo_talloc_replace_string(g_hnb, &g_hnb->gtp.cfg_local_addr, argv[0]);
	return CMD_SUCCESS;
}

static int config_write_hnodeb(struct vty *vty)
{
	vty_out(vty, "hnodeb%s", VTY_NEWLINE);
	vty_out(vty, " identity %s%s", g_hnb->identity, VTY_NEWLINE);
	vty_out(vty, " network country code %s%s", osmo_mcc_name(g_hnb->plmn.mcc), VTY_NEWLINE);
	vty_out(vty, " mobile network code %s%s",
		osmo_mnc_name(g_hnb->plmn.mnc, g_hnb->plmn.mnc_3_digits), VTY_NEWLINE);
	vty_out(vty, " cell_identity %u%s", g_hnb->cell_identity, VTY_NEWLINE);
	vty_out(vty, " location_area_code %u%s", g_hnb->lac, VTY_NEWLINE);
	vty_out(vty, " routing_area_code %u%s", g_hnb->rac, VTY_NEWLINE);
	vty_out(vty, " service_area_code %u%s", g_hnb->sac, VTY_NEWLINE);
	vty_out(vty, " iuh%s", VTY_NEWLINE);
	if (g_hnb->iuh.local_addr)
		vty_out(vty, "  local-ip %s%s", g_hnb->iuh.local_addr, VTY_NEWLINE);
	if (g_hnb->iuh.local_port)
		vty_out(vty, "  local-port %u%s", g_hnb->iuh.local_port, VTY_NEWLINE);
	vty_out(vty, "  remote-ip %s%s", g_hnb->iuh.remote_addr, VTY_NEWLINE);
	vty_out(vty, "  remote-port %u%s", g_hnb->iuh.remote_port, VTY_NEWLINE);
	vty_out(vty, " ll-socket%s", VTY_NEWLINE);
	vty_out(vty, "  path %s%s", osmo_prim_srv_link_get_addr(g_hnb->llsk.link), VTY_NEWLINE);
	vty_out(vty, " gtp%s", VTY_NEWLINE);
	vty_out(vty, "  local-ip %s%s", g_hnb->gtp.cfg_local_addr, VTY_NEWLINE);
	return CMD_SUCCESS;
}

#define RANAP_STR	"RANAP related commands\n"
#define CSPS_STR	"Circuit Switched\n" "Packet Switched\n"


DEFUN(asn_dbg, asn_dbg_cmd,
      "asn-debug (1|0)",
      "Enable or disable libasn1c debugging\n"
      "Enable libasn1c debugging\n"
      "Disable libasn1c debugging\n")
{
	asn_debug = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(ranap_reset, ranap_reset_cmd,
	"ranap reset (cs|ps)", RANAP_STR "Send RANAP RESET\n" CSPS_STR)
{
	int is_ps = 0;
	struct msgb *msg, *rua;

	RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice.transmissionNetwork = RANAP_CauseTransmissionNetwork_signalling_transport_resource_failure,
	};

	if (!strcmp(argv[0], "ps"))
		is_ps = 1;

	msg = ranap_new_msg_reset(is_ps, &cause);
	rua = rua_new_udt(msg);
	//msgb_free(msg);
	hnb_iuh_send(g_hnb, rua);

	return CMD_SUCCESS;
}

void hnb_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_hnodeb_cmd);
	install_node(&hnodeb_node, config_write_hnodeb);
	install_element(HNODEB_NODE, &cfg_hnodeb_identity_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_ncc_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_mnc_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_ci_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_lac_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_rac_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_sac_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_iuh_cmd);
	install_node(&iuh_node, NULL);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_local_ip_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_local_port_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_remote_ip_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_remote_port_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_llsk_cmd);
	install_node(&llsk_node, NULL);
	install_element(LLSK_NODE, &cfg_hnodeb_llsk_path_cmd);
	install_element(HNODEB_NODE, &cfg_hnodeb_gtp_cmd);
	install_node(&gtp_node, NULL);
	install_element(GTP_NODE, &cfg_hnodeb_gtp_local_ip_cmd);

	install_element_ve(&asn_dbg_cmd);
	install_element_ve(&ranap_reset_cmd);
}
