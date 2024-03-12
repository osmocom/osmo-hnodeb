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

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/hnodeb/hnb_shutdown_fsm.h>
#include <osmocom/hnodeb/hnodeb.h>
#include <osmocom/hnodeb/iuh.h>
#define X(s) (1 << (s))

#define hnb_shutdown_fsm_state_chg(fi, NEXT_STATE) \
	osmo_fsm_inst_state_chg(fi, NEXT_STATE, 0, 0)

static void st_none_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnb *hnb = (struct hnb *)fi->priv;

	/* Reset state: */
	hnb->registered = false;
	hnb->rnc_id = 0;

	hnb_iuh_connect(hnb); /* Start reconnect once we are done with shutdown and we didn't exit process */
}

static void st_none(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnb *hnb = (struct hnb *)fi->priv;
	switch (event) {
	case HNB_SHUTDOWN_EV_START:
		/* TODO: here we may want to communicate to lower layers over UDsocket that we are shutting down...
		 * TODO: Also, if Iuh link is still up, maybe send a Hnb deregister req towards HNBGW
		 * TODO: also signal the hnb object somehow that we are starting to shut down?
		 */
		if (osmo_stream_cli_is_connected(hnb->iuh.client))
			osmo_stream_cli_close(hnb->iuh.client);

		hnb_shutdown_fsm_state_chg(fi, HNB_SHUTDOWN_ST_EXIT);
		break;
	}
}

static void st_exit_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnb *hnb = (struct hnb *)fi->priv;
	/* TODO: here we may want to signal the hnb object somehow that we have completed the shut down? */

	if (hnb->shutdown_fi_exit_proc) {
		LOGPFSML(fi, LOGL_NOTICE, "Shutdown process completed successfully, exiting process\n");
		exit(0);
	}
	hnb_shutdown_fsm_state_chg(fi, HNB_SHUTDOWN_ST_NONE);
}

static struct osmo_fsm_state hnb_shutdown_fsm_states[] = {
	[HNB_SHUTDOWN_ST_NONE] = {
		.in_event_mask =
			X(HNB_SHUTDOWN_EV_START),
		.out_state_mask =
			X(HNB_SHUTDOWN_ST_EXIT),
		.name = "NONE",
		.onenter = st_none_on_enter,
		.action = st_none,
	},
	[HNB_SHUTDOWN_ST_EXIT] = {
		.name = "EXIT",
		.out_state_mask =
			X(HNB_SHUTDOWN_ST_NONE),
		.onenter = st_exit_on_enter,
	}
};

const struct value_string hnb_shutdown_fsm_event_names[] = {
	OSMO_VALUE_STRING(HNB_SHUTDOWN_EV_START),
	{ 0, NULL }
};

int hnb_shutdown_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->state) {
	default:
		OSMO_ASSERT(false);
	}
	return 0;
}

struct osmo_fsm hnb_shutdown_fsm = {
	.name = "HNB_SHUTDOWN",
	.states = hnb_shutdown_fsm_states,
	.num_states = ARRAY_SIZE(hnb_shutdown_fsm_states),
	.event_names = hnb_shutdown_fsm_event_names,
	.log_subsys = DMAIN,
	.timer_cb = hnb_shutdown_fsm_timer_cb,
};

static __attribute__((constructor)) void hnb_shutdown_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&hnb_shutdown_fsm) == 0);
}

bool hnb_shutdown_in_progress(const struct hnb *hnb)
{
	const struct osmo_fsm_inst *fi = hnb->shutdown_fi;
	return fi->state != HNB_SHUTDOWN_ST_NONE;
}

void hnb_shutdown(struct hnb *hnb, const char *reason, bool exit_proc)
{
	struct osmo_fsm_inst *fi = hnb->shutdown_fi;
	if (hnb_shutdown_in_progress(hnb)) {
		LOGPFSML(fi, LOGL_NOTICE, "hNodeB is already being shutdown.\n");
		if (exit_proc)
			hnb->shutdown_fi_exit_proc = true;
		return;
	}
	hnb->shutdown_fi_exit_proc = exit_proc;
	LOGPFSML(fi, LOGL_NOTICE, "Shutting down hNodeB, exit %u, reason: %s\n",
		 exit_proc, reason);
	osmo_fsm_inst_dispatch(fi, HNB_SHUTDOWN_EV_START, NULL);
}
