#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Low-level parts of pyptlib that are only useful to clients.
"""

from pyptlib.config import Config, get_env

class ClientConfig(Config):
    """
    A client-side pyptlib configuration.
    """

    @classmethod
    def fromEnv(cls):
        """
        Build a ClientConfig from environment variables.

        :raises: :class:`pyptlib.config.EnvError` if environment was incomplete or corrupted.
        """
        return cls(
            stateLocation = get_env('TOR_PT_STATE_LOCATION'),
            managedTransportVer = get_env('TOR_PT_MANAGED_TRANSPORT_VER').split(','),
            transports = get_env('TOR_PT_CLIENT_TRANSPORTS').split(','),
            )
