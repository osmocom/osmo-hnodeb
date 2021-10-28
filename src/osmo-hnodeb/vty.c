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

#include <osmocom/rua/rua_msg_factory.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_msg_factory.h>

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

DEFUN(cfg_hnodeb,
      cfg_hnodeb_cmd,
      "hnodeb", HNODEB_STR)
{
	OSMO_ASSERT(g_hnb);
	vty->index = g_hnb;
	vty->node = HNODEB_NODE;

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


static int config_write_hnodeb(struct vty *vty)
{
	vty_out(vty, "hnodeb%s", VTY_NEWLINE);
	vty_out(vty, " iuh%s", VTY_NEWLINE);
	if (g_hnb->iuh.local_addr)
		vty_out(vty, "  local-ip %s%s", g_hnb->iuh.local_addr, VTY_NEWLINE);
	if (g_hnb->iuh.local_port)
		vty_out(vty, "  local-port %u%s", g_hnb->iuh.local_port, VTY_NEWLINE);
	vty_out(vty, "  remote-ip %s%s", g_hnb->iuh.remote_addr, VTY_NEWLINE);
	vty_out(vty, "  remote-port %u%s", g_hnb->iuh.remote_port, VTY_NEWLINE);
	return CMD_SUCCESS;
}


static struct cmd_node chan_node = {
	CHAN_NODE,
	"%s(chan)> ",
	1,
};

#define HNBAP_STR	"HNBAP related commands\n"
#define HNB_STR		"HomeNodeB commands\n"
#define UE_STR		"User Equipment commands\n"
#define RANAP_STR	"RANAP related commands\n"
#define CSPS_STR	"Circuit Switched\n" "Packet Switched\n"

DEFUN(hnb_register, hnb_register_cmd,
	"hnbap hnb register", HNBAP_STR HNB_STR "Send HNB-REGISTER REQUEST")
{
	hnb_send_register_req(g_hnb);

	return CMD_SUCCESS;
}

DEFUN(hnb_deregister, hnb_deregister_cmd,
	"hnbap hnb deregister", HNBAP_STR HNB_STR "Send HNB-DEREGISTER REQUEST")
{
	hnb_send_deregister_req(g_hnb);

	return CMD_SUCCESS;
}

DEFUN(ue_register, ue_register_cmd,
	"hnbap ue register IMSI", HNBAP_STR UE_STR "Send UE-REGISTER REQUEST")
{
	hnb_ue_register_tx(g_hnb, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(asn_dbg, asn_dbg_cmd,
	"asn-debug (1|0)", "Enable or disable libasn1c debugging")
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
	osmo_wqueue_enqueue(&g_hnb->wqueue, rua);

	return CMD_SUCCESS;
}

DEFUN(chan, chan_cmd,
	"channel (cs|ps) lu imsi IMSI",
	"Open a new Signalling Connection\n"
	"To Circuit-Switched CN\n"
	"To Packet-Switched CN\n"
	"Performing a Location Update\n"
	)
{
	struct hnb_chan *chan;
	struct msgb *msg, *rua;
	static uint16_t conn_id = 42;

	chan = talloc_zero(tall_hnb_ctx, struct hnb_chan);
	if (!strcmp(argv[0], "ps"))
		chan->is_ps = 1;
	chan->imsi = talloc_strdup(chan, argv[1]);
	chan->conn_id = conn_id;
	conn_id++;

	msg = gen_initue_lu(chan->is_ps, chan->conn_id, chan->imsi);
	rua = rua_new_conn(chan->is_ps, chan->conn_id, msg);

	osmo_wqueue_enqueue(&g_hnb->wqueue, rua);

	vty->index = chan;
	vty->node = CHAN_NODE;

	if (!chan->is_ps)
		g_hnb->cs.chan = chan;


	return CMD_SUCCESS;
}

void hnb_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_hnodeb_cmd);
	install_node(&hnodeb_node, config_write_hnodeb);
	install_element(HNODEB_NODE, &cfg_hnodeb_iuh_cmd);
	install_node(&iuh_node, NULL);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_local_ip_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_local_port_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_remote_ip_cmd);
	install_element(IUH_NODE, &cfg_hnodeb_iuh_remote_port_cmd);

	install_element_ve(&asn_dbg_cmd);
	install_element_ve(&hnb_register_cmd);
	install_element_ve(&hnb_deregister_cmd);
	install_element_ve(&ue_register_cmd);
	install_element_ve(&ranap_reset_cmd);
	install_element_ve(&chan_cmd);

	install_node(&chan_node, NULL);
}
