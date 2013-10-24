#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

import fte.relay

class listener(fte.relay.listener):

    def onNewIncomingConnection(self, socket):
        return socket

    def onNewOutgoingConnection(self, socket):
        outgoing_regex = fte.conf.getValue('runtime.state.upstream_language')
        incoming_regex = fte.conf.getValue('runtime.state.downstream_language')
        socket = fte.wrap_socket(socket, outgoing_regex, incoming_regex)
        return socket
    