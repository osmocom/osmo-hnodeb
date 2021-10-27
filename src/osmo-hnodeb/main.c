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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/command.h>

#include <osmocom/ranap/ranap_common.h> /* ranap_set_log_area() */

#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/vty.h>
#include <osmocom/hnodeb/hnodeb.h>

void *tall_hnb_ctx;
struct hnb *g_hnb;

static struct vty_app_info vty_info = {
	.name		= "OsmohNodeB",
	.version	= "0",
};

static void handle_options(int argc, char **argv)
{
	while (1) {
		int idx = 0, c;
		static const struct option long_options[] = {
			{ "ues", 1, 0, 'u' },
			{ "gw-addr", 1, 0, 'g' },
			{ 0, 0, 0, 0 },
		};

		c = getopt_long(argc, argv, "u:g:", long_options, &idx);

		if (c == -1)
			break;

		switch (c) {
		case 'u':
			g_hnb->ues = atoi(optarg);
			break;
		case 'g':
			g_hnb->gw_addr = optarg;
			break;
		}
	}
}

int main(int argc, char **argv)
{
	int rc;

	tall_hnb_ctx = talloc_named_const(NULL, 0, "hnb_context");

	msgb_talloc_ctx_init(tall_hnb_ctx, 0);
	talloc_asn1_ctx = talloc_named_const(tall_hnb_ctx, 0, "asn1_context");

	rc = osmo_init_logging2(tall_hnb_ctx, &hnb_log_info);
	if (rc < 0)
		exit(1);

	ranap_set_log_area(DRANAP);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	g_hnb = hnb_alloc(tall_hnb_ctx);

	vty_init(&vty_info);
	hnb_vty_init();

	rc = telnet_init_dynif(NULL, NULL, vty_get_bind_addr(), 2324);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	handle_options(argc, argv);

	rc = hnb_connect(g_hnb);
	if (rc < 0) {
		perror("Error connecting to Iuh port");
		exit(1);
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
