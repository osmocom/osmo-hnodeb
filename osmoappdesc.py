#!/usr/bin/env python3

# (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

app_configs = {
    "osmo-hnodeb": ["doc/examples/osmo-hnodeb/osmo-hnodeb.cfg"]
}

apps = [(4273, "src/osmo-hnodeb/osmo-hnodeb", "OsmoHNodeB", "osmo-hnodeb")
        ]

vty_command = ["./src/osmo-hnodeb/osmo-hnodeb", "-c",
               "doc/examples/osmo-hnodeb/osmo-hnodeb.cfg"]

vty_app = apps[0]
