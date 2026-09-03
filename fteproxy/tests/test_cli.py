#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the command line: parsing, applying to conf, and exit statuses.

These call :func:`fteproxy.cli.main` in process, so they assert on the status
the process would exit with rather than on a subprocess return code.
``test_system.py`` covers the subprocess path.
"""

import logging

import pytest

import fteproxy
import fteproxy.cli
import fteproxy.conf
import fteproxy.defs


@pytest.fixture(autouse=True)
def restore_conf():
    """Snapshot and restore the global configuration around each test.

    ``apply_args_to_conf`` writes process-global state; without this a test
    that sets a non-default release or key would leak into the next one.
    """
    saved = dict(fteproxy.conf.conf)
    saved_defs = fteproxy.defs._definitions
    yield
    fteproxy.conf.conf.clear()
    fteproxy.conf.conf.update(saved)
    fteproxy.defs._definitions = saved_defs


def parse(argv):
    return fteproxy.cli.build_parser().parse_args(argv)


class TestParser:
    """The parse step alone: no configuration is written."""

    def test_ports_are_integers(self):
        args = parse(['--mode', 'client', '--client_port', '1234',
                      '--server_port', '5678', '--proxy_port', '9012'])
        assert args.client_port == 1234
        assert args.server_port == 5678
        assert args.proxy_port == 9012

    def test_non_integer_port_is_a_usage_error(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['--mode', 'client', '--client_port', 'http'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_mode_has_no_default(self):
        """A bare run must be a usage error, not a client that was never
        configured. The old default hid the no-argument crash."""
        assert parse([]).mode is None

    def test_invalid_mode_is_a_usage_error(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['--mode', 'invalid'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_parsing_does_not_write_conf(self):
        before = fteproxy.conf.getValue('runtime.client.port')
        parse(['--mode', 'client', '--client_port', str(before + 1)])
        assert fteproxy.conf.getValue('runtime.client.port') == before

    def test_quiet_and_verbose_are_mutually_exclusive(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['--mode', 'client', '-q', '-v'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_key_and_key_file_are_mutually_exclusive(self, tmp_path):
        key_file = tmp_path / 'k'
        key_file.write_text('a' * 64)
        with pytest.raises(SystemExit) as excinfo:
            parse(['--mode', 'server', '--key', 'a' * 64,
                   '--key-file', str(key_file)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_formats_subcommand_is_recognised(self):
        assert parse(['formats']).command == 'formats'
        assert parse(['--mode', 'client']).command is None

    def test_release_before_the_subcommand_is_kept(self):
        """The subcommand's own --release defaults to SUPPRESS so it does not
        clobber a value given ahead of it."""
        assert parse(['--release', '20131224', 'formats']).release == '20131224'
        assert parse(['formats', '--release', '20131224']).release == '20131224'


class TestApplyArgsToConf:
    """Every value reaches conf, whether typed or defaulted."""

    def test_defaults_reach_conf(self):
        args = parse(['--mode', 'client'])
        # Poison conf after parsing: applying must put the default back. The
        # old setConfValue action ran only for values the user typed, so a
        # default never reached conf at all.
        fteproxy.conf.setValue('runtime.client.port', 1)
        fteproxy.conf.setValue('runtime.mode', None)
        fteproxy.cli.apply_args_to_conf(args)
        assert fteproxy.conf.getValue('runtime.mode') == 'client'
        assert fteproxy.conf.getValue('runtime.client.port') == args.client_port

    def test_typed_values_reach_conf(self):
        fteproxy.cli.apply_args_to_conf(parse([
            '--mode', 'server',
            '--client_ip', '10.0.0.1', '--client_port', '1111',
            '--server_ip', '10.0.0.2', '--server_port', '2222',
            '--proxy_ip', '10.0.0.3', '--proxy_port', '3333',
            '--upstream-format', 'ssh-request',
            '--downstream-format', 'ssh-response',
            '--record-layer-mode', 'format',
        ]))
        get = fteproxy.conf.getValue
        assert get('runtime.mode') == 'server'
        assert get('runtime.client.ip') == '10.0.0.1'
        assert get('runtime.client.port') == 1111
        assert get('runtime.server.ip') == '10.0.0.2'
        assert get('runtime.server.port') == 2222
        assert get('runtime.proxy.ip') == '10.0.0.3'
        assert get('runtime.proxy.port') == 3333
        assert get('runtime.state.upstream_language') == 'ssh-request'
        assert get('runtime.state.downstream_language') == 'ssh-response'
        assert get('runtime.fteproxy.record_layer.mode') == 'format'

    def test_key_reaches_conf_as_bytes(self):
        fteproxy.cli.apply_args_to_conf(
            parse(['--mode', 'client', '--key', '0123456789abcdef' * 4]))
        key = fteproxy.conf.getValue('runtime.fteproxy.encrypter.key')
        assert key == bytes.fromhex('0123456789abcdef' * 4)

    def test_key_file_reaches_conf(self, tmp_path):
        key_file = tmp_path / 'fteproxy.key'
        key_file.write_text('0123456789abcdef' * 4 + '\n')
        fteproxy.cli.apply_args_to_conf(
            parse(['--mode', 'client', '--key-file', str(key_file)]))
        assert fteproxy.conf.getValue('runtime.fteproxy.encrypter.key') == \
            bytes.fromhex('0123456789abcdef' * 4)

    def test_changing_the_release_drops_the_definitions_cache(self):
        fteproxy.defs.load_definitions()
        assert fteproxy.defs._definitions is not None
        fteproxy.cli.apply_args_to_conf(
            parse(['--mode', 'client', '--release', '20131224']))
        assert fteproxy.defs._definitions is None
        assert fteproxy.conf.getValue('fteproxy.defs.release') == '20131224'


class TestKeyValidation:
    """Key errors are usage errors and never quote the key material."""

    def test_short_key_rejected(self):
        with pytest.raises(fteproxy.cli.UsageError) as excinfo:
            fteproxy.cli.parse_hex_key('abcdef')
        assert 'abcdef' not in str(excinfo.value)

    def test_non_hex_key_rejected(self):
        with pytest.raises(fteproxy.cli.UsageError):
            fteproxy.cli.parse_hex_key('z' * 64)

    def test_trailing_newline_accepted(self):
        assert fteproxy.cli.parse_hex_key('ab' * 32 + '\n') == b'\xab' * 32

    def test_missing_key_file_rejected(self, tmp_path):
        with pytest.raises(fteproxy.cli.UsageError):
            fteproxy.cli.read_key_file(str(tmp_path / 'nope.key'))

    def test_bad_key_file_is_exit_2(self, tmp_path):
        key_file = tmp_path / 'short.key'
        key_file.write_text('abcdef')
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['--mode', 'server', '--key-file', str(key_file)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE


class TestStartupChecks:
    """Formats are validated before anything is printed or bound."""

    def test_unknown_format_raises(self):
        with pytest.raises(fteproxy.cli.StartupError) as excinfo:
            fteproxy.cli.check_format('no-such-format')
        assert 'no-such-format' in str(excinfo.value)

    def test_known_format_passes(self):
        fteproxy.cli.check_format('manual-http-request')


class TestMainExitStatus:
    """The statuses the plan fixes: 0 clean, 1 runtime failure, 2 usage."""

    def test_no_arguments_is_usage(self, capsys):
        assert fteproxy.cli.main([]) == fteproxy.cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert 'usage:' in err
        assert '--mode' in err

    def test_unknown_upstream_format_is_failure(self, capsys):
        status = fteproxy.cli.main(
            ['--mode', 'client', '--upstream-format', 'nope'])
        assert status == fteproxy.cli.EXIT_FAILURE
        assert 'nope' in capsys.readouterr().err

    def test_unknown_downstream_format_is_failure(self):
        assert fteproxy.cli.main(
            ['--mode', 'client', '--downstream-format', 'nope']) == \
            fteproxy.cli.EXIT_FAILURE

    def test_bind_failure_is_failure(self):
        """A port already taken exits 1 rather than leaving a dead thread and
        exiting 0."""
        import socket

        taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        taken.bind(('127.0.0.1', 0))
        taken.listen(1)
        port = taken.getsockname()[1]
        try:
            status = fteproxy.cli.main([
                '--mode', 'client',
                '--client_ip', '127.0.0.1', '--client_port', str(port),
            ])
        finally:
            taken.close()
        assert status == fteproxy.cli.EXIT_FAILURE

    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['--version'])
        assert excinfo.value.code == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert fteproxy.__version__ in out
        assert 'NO WARRANTY' in out


class TestFormatsSubcommand:

    def test_lists_base_names_with_capacity(self, capsys):
        assert fteproxy.cli.main(['formats']) == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert 'manual-http' in out
        # Base names only: the direction suffixes are columns, not rows.
        assert 'manual-http-request' not in out
        assert '(default)' in out
        # manual-http-response carries 192 bytes per covertext at length 256.
        assert '192' in out

    def test_marks_the_configured_default(self, capsys):
        fteproxy.cli.main(['--upstream-format', 'ssh-request', 'formats'])
        for line in capsys.readouterr().out.splitlines():
            if '(default)' in line:
                assert line.split()[0] == 'ssh'
                break
        else:
            pytest.fail('no format marked as the default')

    def test_honours_the_release(self, capsys):
        assert fteproxy.cli.main(['--release', '20131224', 'formats']) == \
            fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert '20131224' in out


class TestLogging:
    """Verbosity flags set the package logger's level; output is on stderr.

    ``conftest.restore_fteproxy_logger`` puts the logger back afterwards.
    """

    def test_default_is_info(self):
        assert fteproxy.cli.configure_logging() == logging.INFO

    def test_quiet_is_error(self):
        assert fteproxy.cli.configure_logging(quiet=True) == logging.ERROR

    def test_verbose_is_debug(self):
        assert fteproxy.cli.configure_logging(verbose=True) == logging.DEBUG

    def test_messages_go_to_stderr(self, capsys):
        fteproxy.cli.configure_logging()
        # The handler is bound to whatever sys.stderr is when it is built, so
        # build it under capsys's replacement.
        fteproxy.warn('a warning')
        captured = capsys.readouterr()
        assert 'a warning' in captured.err
        assert captured.out == ''
