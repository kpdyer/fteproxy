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

import fte.conf
import fte.relay


class listener(fte.relay.listener):

    def onNewIncomingConnection(self, socket):
        """On an incoming data stream we wrap it with ``fte.wrap_socket``, with no parameters.
        By default we want the regular expressions to be negotiated in-band, specified by the client.
        """

        socket = fte.wrap_socket(socket)

        return socket
