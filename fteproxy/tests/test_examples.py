#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests that run all examples to verify they work correctly.

These tests ensure that:
1. Self-contained examples run without errors
2. Client/server examples work together
3. All examples properly demonstrate FTE functionality
"""

import os
import sys
import time
import subprocess

import pytest


# Get the examples directory
EXAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'examples'
)


def run_example(script_path, timeout=30):
    """Run a Python example script and return (success, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=os.path.dirname(script_path)
    )
    return result.returncode == 0, result.stdout, result.stderr


class TestSelfContainedExamples:
    """Test examples that run standalone without needing a server."""

    def test_simple_encoder(self):
        """Test programmatic/simple_encoder.py"""
        script = os.path.join(EXAMPLES_DIR, 'programmatic', 'simple_encoder.py')
        success, stdout, stderr = run_example(script)
        assert success, f"simple_encoder.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "Roundtrip successful: True" in stdout

    def test_format_demo(self):
        """Test programmatic/format_demo.py"""
        script = os.path.join(EXAMPLES_DIR, 'programmatic', 'format_demo.py')
        success, stdout, stderr = run_example(script)
        assert success, f"format_demo.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "[OK]" in stdout

    def test_custom_format(self):
        """Test programmatic/custom_format.py"""
        script = os.path.join(EXAMPLES_DIR, 'programmatic', 'custom_format.py')
        success, stdout, stderr = run_example(script)
        assert success, f"custom_format.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "[OK]" in stdout or "successfully" in stdout.lower()

    def test_comparison_demo(self):
        """Test formats/comparison_demo.py"""
        script = os.path.join(EXAMPLES_DIR, 'formats', 'comparison_demo.py')
        success, stdout, stderr = run_example(script)
        assert success, f"comparison_demo.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "FORMAT COMPARISON" in stdout

    def test_words_demo(self):
        """Test formats/words_demo.py"""
        script = os.path.join(EXAMPLES_DIR, 'formats', 'words_demo.py')
        success, stdout, stderr = run_example(script)
        assert success, f"words_demo.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "[OK]" in stdout

    def test_http_demo(self):
        """Test formats/http_demo.py"""
        script = os.path.join(EXAMPLES_DIR, 'formats', 'http_demo.py')
        success, stdout, stderr = run_example(script)
        assert success, f"http_demo.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "HTTP" in stdout


class TestClientServerExamples:
    """Test examples that require both client and server."""

    @pytest.fixture
    def chat_server(self):
        """Start the chat server."""
        script = os.path.join(EXAMPLES_DIR, 'chat', 'server.py')
        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(script)
        )
        
        # Give the server time to start listening
        # Note: We can't use wait_for_port because it would consume the server's
        # single connection slot (since this server only accepts one client)
        time.sleep(3)
        
        # Check if server is still running
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Chat server failed to start:\nstdout: {stdout.decode() if stdout else ''}\nstderr: {stderr.decode() if stderr else ''}")
        
        yield proc
        
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    @pytest.fixture
    def echo_server(self):
        """Start the echo server."""
        script = os.path.join(EXAMPLES_DIR, 'programmatic', 'echo_server.py')
        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(script)
        )
        
        # Give the server time to start listening
        time.sleep(3)
        
        # Check if server is still running
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=5)
            pytest.fail(f"Echo server failed to start:\nstdout: {stdout.decode() if stdout else ''}\nstderr: {stderr.decode() if stderr else ''}")
        
        yield proc
        
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def test_chat_example(self, chat_server):
        """Test the chat client/server example."""
        client_script = os.path.join(EXAMPLES_DIR, 'chat', 'client.py')
        
        # Run the client
        result = subprocess.run(
            [sys.executable, client_script],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(client_script)
        )
        
        # If failed, also get server output for debugging
        if result.returncode != 0:
            chat_server.terminate()
            server_stdout, server_stderr = chat_server.communicate(timeout=5)
            pytest.fail(f"Chat client failed:\nClient stdout: {result.stdout}\nClient stderr: {result.stderr}\nServer stdout: {server_stdout.decode() if server_stdout else ''}\nServer stderr: {server_stderr.decode() if server_stderr else ''}")
        
        assert "Chat ended" in result.stdout or "[Round 10/10]" in result.stdout

    def test_echo_example(self, echo_server):
        """Test the echo client/server example."""
        client_script = os.path.join(EXAMPLES_DIR, 'programmatic', 'echo_client.py')
        
        # Run the client
        result = subprocess.run(
            [sys.executable, client_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(client_script)
        )
        
        assert result.returncode == 0, \
            f"Echo client failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Echo successful" in result.stdout or "received" in result.stdout.lower()


class TestFileTransferExample:
    """Test the file transfer example."""

    def test_file_transfer(self):
        """Test programmatic/file_transfer.py"""
        script = os.path.join(EXAMPLES_DIR, 'programmatic', 'file_transfer.py')
        success, stdout, stderr = run_example(script, timeout=60)
        assert success, f"file_transfer.py failed:\nstdout: {stdout}\nstderr: {stderr}"
        assert "success" in stdout.lower() or "[OK]" in stdout
