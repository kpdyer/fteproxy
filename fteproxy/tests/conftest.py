#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest configuration and fixtures for fteproxy tests.
"""

import pytest

import fteproxy
import fteproxy.conf


#: A fixed key for tests that exercise the record layer directly, where the
#: value does not matter but both ends must agree. Real connections derive
#: their keys per direction from the handshake; nothing in the package ships a
#: default key any more.
TEST_KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def restore_fteproxy_logger():
    """Undo any logging setup a test performed.

    ``fteproxy.cli.configure_logging`` attaches a handler and stops the
    package logger propagating to the root, which is right for a CLI process
    and wrong for the rest of the session: ``caplog`` reads records off the
    root logger, so a leaked configuration would silently blind every later
    test that asserts on a log message.
    """
    logger = fteproxy.logger
    handlers = list(logger.handlers)
    level = logger.level
    propagate = logger.propagate
    yield
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate


@pytest.fixture
def sample_key():
    """A 32-byte key for tests that need one but not a real handshake."""
    return TEST_KEY
