#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest configuration and fixtures for fteproxy tests.
"""

import pytest

import fteproxy
import fteproxy.conf


@pytest.fixture(autouse=True)
def setup_test_mode():
    """Automatically set runtime mode for all tests."""
    fteproxy.conf.setValue('runtime.mode', 'client')
    yield
    # Reset after test if needed
    fteproxy.conf.setValue('runtime.mode', None)


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
    """Provide a sample encryption key for testing."""
    return b'\xff' * 16 + b'\x00' * 16
