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
#include <osmocom/core/logging.h>

#include <osmocom/hnodeb/hnodeb.h>

static const struct log_info_cat log_cat[] = {
	[DMAIN] = {
		.name = "DMAIN", .loglevel = LOGL_INFO, .enabled = 1,
		.color = "",
		.description = "Main program",
	},
	[DHNBAP] = {
		.name = "DHNBAP", .loglevel = LOGL_DEBUG, .enabled = 1,
		.color = "",
		.description = "Home Node B Application Part",
	},
	[DRANAP] = {
		.name = "RANAP", .loglevel = LOGL_DEBUG, .enabled = 1,
		.color = "",
		.description = "RAN Application Part",
	},
	[DRUA] = {
		.name = "RUA", .loglevel = LOGL_DEBUG, .enabled = 1,
		.color = "",
		.description = "RANAP User Adaptation",
	},
};

const struct log_info hnb_log_info = {
	.cat = log_cat,
	.num_cat = ARRAY_SIZE(log_cat),
};
