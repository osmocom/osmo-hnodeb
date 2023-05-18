/* hNodeB shutdown FSM */

/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <stdbool.h>

#include <osmocom/core/fsm.h>

enum hnb_shutdown_fsm_states {
	HNB_SHUTDOWN_ST_NONE,
	HNB_SHUTDOWN_ST_EXIT,
};

enum hnb_shutdown_fsm_events {
	HNB_SHUTDOWN_EV_START,
};

extern struct osmo_fsm hnb_shutdown_fsm;

struct hnb;
void hnb_shutdown(struct hnb *hnb, const char *reason, bool exit_proc);
bool hnb_shutdown_in_progress(const struct hnb *hnb);
