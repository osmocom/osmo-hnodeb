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
#include <osmocom/vty/misc.h>
#include <osmocom/vty/cpu_sched_vty.h>
#include <osmocom/vty/ports.h>

#include <osmocom/trau/osmo_ortp.h>

#include <osmocom/ranap/ranap_common.h> /* ranap_set_log_area() */

#include <osmocom/hnodeb/hnbap.h>
#include <osmocom/hnodeb/rua.h>
#include <osmocom/hnodeb/ranap.h>
#include <osmocom/hnodeb/vty.h>
#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/iuh.h>

static const char * const osmohnodeb_copyright =
	"OsmoHNodeB - Osmocom 3G Home NodeB implementation\r\n"
	"Copyright (C) 2015 by Daniel Willmann <dwillmann@sysmocom.de\r\n"
	"Copyright (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Based on initial work (hnb-test) by Daniel Willmann\r\n"
	"Contributions by Pau Espin Pedrol\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

void *tall_hnb_ctx;
struct hnb *g_hnb;

static struct {
	const char *database_name;
	const char *config_file;
	int daemonize;
	const char *mncc_sock_path;
} hnb_cmdline_config = {
	.database_name = NULL,
	.config_file = "osmo-hnodeb.cfg",
};

static struct vty_app_info vty_info = {
	.name		= "OsmoHNodeB",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= hnb_vty_go_parent,
};

static void print_usage()
{
	printf("Usage: osmo-hnodeb\n");
}

static void print_help()
{
	printf("Some useful options:\n");
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DCC:DMM:DRR:  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -V --version               Print the version of OsmoHNodeB.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");

	printf("\nVTY reference generation:\n");
	printf("     --vty-ref-mode MODE     VTY reference generation mode (e.g. 'expert').\n");
	printf("     --vty-ref-xml           Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int idx = 0, c;
		static int long_option = 0;
		static const struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{"log-level", 1, 0, 'e'},
			{"vty-ref-mode", 1, &long_option, 1},
			{"vty-ref-xml", 0, &long_option, 2},
			{ 0, 0, 0, 0 },
		};

		c = getopt_long(argc, argv, "hd:Dc:sTVe:", long_options, &idx);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			hnb_cmdline_config.daemonize = 1;
			break;
		case 'c':
			hnb_cmdline_config.config_file = optarg;
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}
}

static void signal_handler(int signum)
{
	fprintf(stdout, "signal %u received\n", signum);

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		/* If SIGTERM was already sent before, just terminate immediately. */
		if (osmo_select_shutdown_requested())
			exit(-1);
		osmo_select_shutdown_request();
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_hnb_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_hnb_ctx, stderr);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	int rc;
	void *tall_rtp_ctx;

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	tall_hnb_ctx = talloc_named_const(NULL, 0, "hnb_context");

	msgb_talloc_ctx_init(tall_hnb_ctx, 0);
	talloc_asn1_ctx = talloc_named_const(tall_hnb_ctx, 0, "asn1_context");

	rc = osmo_init_logging2(tall_hnb_ctx, &hnb_log_info);
	if (rc < 0)
		exit(1);

	ranap_set_log_area(DRANAP);

	vty_info.copyright = osmohnodeb_copyright;
	vty_info.tall_ctx = tall_hnb_ctx;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_cpu_sched_vty_init(tall_hnb_ctx);

	/* allocate a talloc pool for ORTP to ensure it doesn't have to go back
	 * to the libc malloc all the time */
	tall_rtp_ctx = talloc_pool(tall_hnb_ctx, 262144);
	osmo_rtp_init(tall_rtp_ctx);

	g_hnb = hnb_alloc(tall_hnb_ctx);
	hnb_vty_init();

	handle_options(argc, argv);


	rc = vty_read_config_file(hnb_cmdline_config.config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			hnb_cmdline_config.config_file);
		exit(1);
	}

	rc = telnet_init_dynif(tall_hnb_ctx, g_hnb, vty_get_bind_addr(), OSMO_VTY_PORT_HNODEB);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	/* Start listening on lower layer unix domain socket: */
	rc = osmo_prim_srv_link_open(g_hnb->llsk_link);
	if (rc < 0) {
		perror("Error opening lower layer socket");
		exit(1);
	}

	rc = hnb_iuh_connect(g_hnb);
	if (rc < 0) {
		perror("Error connecting to Iuh port");
		exit(1);
	}

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (hnb_cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			return 6;
		}
	}

	while (!osmo_select_shutdown_done()) {
		osmo_select_main_ctx(0);
	}

	log_fini();

	/**
	 * Report the heap state of root context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(tall_hnb_ctx, stderr);
	talloc_free(tall_hnb_ctx);

	/* FIXME: VTY code still uses NULL-context */
	talloc_free(tall_vty_ctx);

	/**
	 * Report the heap state of NULL context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	/* not reached */
	exit(0);
}
