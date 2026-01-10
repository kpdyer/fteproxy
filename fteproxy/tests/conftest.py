#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest configuration and fixtures for fteproxy tests.
"""

import pytest
import fteproxy.conf


@pytest.fixture(autouse=True)
def setup_test_mode():
    """Automatically set runtime mode for all tests."""
    fteproxy.conf.setValue('runtime.mode', 'client')
    yield
    # Reset after test if needed
    fteproxy.conf.setValue('runtime.mode', None)


@pytest.fixture
def sample_key():
    """Provide a sample encryption key for testing."""
    return b'\xff' * 16 + b'\x00' * 16
