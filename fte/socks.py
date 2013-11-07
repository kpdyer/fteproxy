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

import multiprocessing

import twisted.protocols.socks

SOCKS_LOG = "socks.log"


class SocksProxyv4(multiprocessing.Process):

    def __init__(self, proxyIP, proxyPort):
        multiprocessing.Process.__init__(self)
        
        self._proxyIP = proxyIP
        self._proxyPort = proxyPort
        self._event = multiprocessing.Event()

    def run(self):
        factory = twisted.protocols.socks.SOCKSv4Factory("socks.log")
        twisted.internet.reactor.listenTCP(
            self._proxyPort, factory, interface=self._proxyIP)

        l = twisted.internet.task.LoopingCall(self.shouldStop)
        l.start(0.1)

        twisted.internet.reactor.run()

    def shouldStop(self):
        if self._event.is_set():
            twisted.internet.reactor.stop()

    def stop(self):
        self._event.set()