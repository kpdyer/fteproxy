#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

import fte.relay


class listener(fte.relay.listener):

    def onNewOutgoingConnection(self, socket):
        """On an outgoing data stream we wrap it with ``fte.wrap_socket``, with
        the languages specified in the ``runtime.state.upstream_language`` and
        ``runtime.state.downstream_language`` configuration parameters.
        """

        outgoing_language = fte.conf.getValue(
            'runtime.state.upstream_language')
        incoming_language = fte.conf.getValue(
            'runtime.state.downstream_language')

        outgoing_regex = fte.defs.getRegex(outgoing_language)
        outgoing_fixed_slice = fte.defs.getFixedSlice(outgoing_language)

        incoming_regex = fte.defs.getRegex(incoming_language)
        incoming_fixed_slice = fte.defs.getFixedSlice(incoming_language)

        socket = fte.wrap_socket(socket,
                                 outgoing_regex, outgoing_fixed_slice,
                                 incoming_regex, incoming_fixed_slice)

        return socket
