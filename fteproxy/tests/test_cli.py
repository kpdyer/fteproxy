#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the command line and the configuration it reads.

These call :func:`fteproxy.cli.main` in process, so they assert on the status
the process would exit with rather than on a subprocess return code.
``test_system.py`` covers the subprocess path.
"""

import logging
import os
import stat

import pytest

import fteproxy
import fteproxy.cli
import fteproxy.conf
import fteproxy.config
import fteproxy.defs


PUBLIC = bytes(range(32))
SERVER_ID = fteproxy.config.encode_server_id(PUBLIC)


@pytest.fixture(autouse=True)
def restore_conf():
    """Snapshot and restore the global configuration around each test.

    The CLI writes process-global state; without this a test that selects a
    non-default definitions release would leak into the next one.
    """
    saved = dict(fteproxy.conf.conf)
    saved_defs = fteproxy.defs._definitions
    yield
    fteproxy.conf.conf.clear()
    fteproxy.conf.conf.update(saved)
    fteproxy.defs._definitions = saved_defs


def parse(argv):
    return fteproxy.cli.build_parser().parse_args(argv)


# --------------------------------------------------------------------------- #
# The connection string
# --------------------------------------------------------------------------- #

class TestConnectionString:

    @pytest.mark.parametrize('host', [
        'example.com', '203.0.113.5', '2001:db8::1', '::1',
    ])
    def test_round_trip(self, host):
        uri = fteproxy.config.ConnectionString(PUBLIC, host, 8080)
        assert fteproxy.config.ConnectionString.parse(uri.format()) == uri

    def test_round_trip_with_hints(self):
        uri = fteproxy.config.ConnectionString(
            PUBLIC, 'example.com', 443, format_name='words', mode='format',
            defs='20260110')
        text = uri.format()
        assert 'format=words' in text
        assert 'mode=format' in text
        assert 'defs=20260110' in text
        assert fteproxy.config.ConnectionString.parse(text) == uri

    def test_ipv6_is_bracketed(self):
        uri = fteproxy.config.ConnectionString(PUBLIC, '2001:db8::1', 8080)
        assert '@[2001:db8::1]:8080' in uri.format()

    def test_the_server_id_is_43_characters(self):
        assert len(SERVER_ID) == 43
        assert '=' not in SERVER_ID

    def test_parse_recovers_the_key(self):
        uri = fteproxy.config.ConnectionString.parse(
            'fte://%s@203.0.113.5:8080' % SERVER_ID)
        assert uri.server_id == PUBLIC
        assert uri.address == ('203.0.113.5', 8080)

    def test_port_defaults_to_8080(self):
        uri = fteproxy.config.ConnectionString.parse(
            'fte://%s@203.0.113.5' % SERVER_ID)
        assert uri.port == 8080

    def test_unknown_query_parameters_are_ignored(self):
        """So a later version can add one without breaking today's clients."""
        uri = fteproxy.config.ConnectionString.parse(
            'fte://%s@host:1?pk2=abc&future=1&mode=format' % SERVER_ID)
        assert uri.mode == 'format'

    @pytest.mark.parametrize('text', [
        '',
        'http://%s@host:8080' % SERVER_ID,
        'fte://host:8080',
        'fte://short@host:8080',
        'fte://%s@host:8080/path' % SERVER_ID,
        'fte://%s@host:8080#frag' % SERVER_ID,
        'fte://%s@host:0' % SERVER_ID,
        'fte://%s@host:99999' % SERVER_ID,
        'fte://%s@host:8080?mode=nonsense' % SERVER_ID,
        'fte://%s@host:8080?defs=lastweek' % SERVER_ID,
        'fte://%s@:8080' % SERVER_ID,
    ])
    def test_bad_strings_are_refused(self, text):
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ConnectionString.parse(text)

    def test_errors_never_quote_the_string(self):
        """An unparseable connection string is still a secret."""
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.ConnectionString.parse(
                'fte://%s@host:99999' % SERVER_ID)
        assert SERVER_ID not in str(excinfo.value)

    def test_str_and_repr_are_redacted(self):
        uri = fteproxy.config.ConnectionString(PUBLIC, '203.0.113.5', 8080)
        assert SERVER_ID not in str(uri)
        assert SERVER_ID not in repr(uri)
        assert str(uri) == 'fte://…@203.0.113.5:8080'
        assert uri.redacted() in repr(uri)


class TestSpecParsers:

    @pytest.mark.parametrize('text,expected', [
        (':8080', ('', 8080)),
        ('1.2.3.4:8080', ('1.2.3.4', 8080)),
        ('[::]:8080', ('::', 8080)),
        ('[2001:db8::1]:443', ('2001:db8::1', 443)),
        ('example.com:80', ('example.com', 80)),
    ])
    def test_host_port(self, text, expected):
        assert fteproxy.config.split_host_port(text) == expected

    @pytest.mark.parametrize('text', [
        '', 'example.com', '[::1', '[::1]80', 'host:http', 'host:0',
        'host:65536',
    ])
    def test_bad_host_port(self, text):
        with pytest.raises(ValueError):
            fteproxy.config.split_host_port(text)

    @pytest.mark.parametrize('text,expected', [
        ('2222:127.0.0.1:22', (('127.0.0.1', 2222), ('127.0.0.1', 22))),
        ('0.0.0.0:2222:example.com:22',
         (('0.0.0.0', 2222), ('example.com', 22))),
        ('[::1]:2222:[2001:db8::1]:22',
         (('::1', 2222), ('2001:db8::1', 22))),
    ])
    def test_forward_spec(self, text, expected):
        assert fteproxy.config.split_forward_spec(text) == expected

    @pytest.mark.parametrize('text', [
        '2222', '2222:host', '2222:host:22:extra', 'a:b:c', '[::1:2222:h:22',
    ])
    def test_bad_forward_spec(self, text):
        with pytest.raises(ValueError):
            fteproxy.config.split_forward_spec(text)

    @pytest.mark.parametrize('text,expected', [
        ('1080', ('127.0.0.1', 1080)),
        ('0.0.0.0:1080', ('0.0.0.0', 1080)),
        ('[::1]:1080', ('::1', 1080)),
    ])
    def test_socks_spec(self, text, expected):
        assert fteproxy.config.split_socks_spec(text) == expected

    @pytest.mark.parametrize('text', ['', 'http', '1:2:3'])
    def test_bad_socks_spec(self, text):
        with pytest.raises(ValueError):
            fteproxy.config.split_socks_spec(text)


class TestStateDirectory:

    def test_resolution_order(self, tmp_path):
        explicit = str(tmp_path / 'explicit')
        environ = {'FTEPROXY_STATE_DIR': str(tmp_path / 'env'),
                   'XDG_STATE_HOME': str(tmp_path / 'xdg')}
        assert fteproxy.config.state_dir(explicit, environ) == explicit
        assert fteproxy.config.state_dir(None, environ) == \
            str(tmp_path / 'env')
        assert fteproxy.config.state_dir(None, {'XDG_STATE_HOME':
                                                str(tmp_path / 'xdg')}) == \
            str(tmp_path / 'xdg' / 'fteproxy')
        assert fteproxy.config.state_dir(None, {}).endswith(
            os.path.join('.local', 'state', 'fteproxy'))

    def test_created_with_mode_0700(self, tmp_path):
        directory = str(tmp_path / 'state')
        fteproxy.config.ensure_state_dir(directory)
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700

    def test_a_loose_directory_is_tightened(self, tmp_path):
        """A state directory other local users can read is a directory they
        can read the private key out of."""
        directory = tmp_path / 'state'
        directory.mkdir(mode=0o755)
        fteproxy.config.ensure_state_dir(str(directory))
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700

    def test_key_and_connection_files_are_0600(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        _private, public, created = fteproxy.config.ensure_server_key(directory)
        assert created
        uri = fteproxy.config.ConnectionString(public, 'example.com', 8080)
        fteproxy.config.write_connection_string(directory, uri)
        for path in (fteproxy.config.server_key_path(directory),
                     fteproxy.config.connection_path(directory)):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_an_existing_key_is_kept(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        first, public, created = fteproxy.config.ensure_server_key(directory)
        assert created
        again, public_again, created_again = \
            fteproxy.config.ensure_server_key(directory)
        assert (again, public_again) == (first, public)
        assert not created_again

    def test_a_world_readable_key_warns(self, tmp_path, caplog):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        fteproxy.config.ensure_server_key(directory)
        os.chmod(fteproxy.config.server_key_path(directory), 0o644)
        with caplog.at_level(logging.WARNING, logger='fteproxy'):
            fteproxy.config.load_server_key(directory)
        assert 'readable by other users' in caplog.text

    @pytest.mark.parametrize('contents', ['', 'abcdef', 'z' * 64])
    def test_a_corrupt_key_file_is_an_error(self, tmp_path, contents):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        with open(fteproxy.config.server_key_path(directory), 'w') as handle:
            handle.write(contents)
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.load_server_key(directory)


class TestResolveClientUri:

    def _write(self, tmp_path, text):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        with open(fteproxy.config.connection_path(directory), 'w') as handle:
            handle.write(text + '\n')
        return directory

    def test_the_argument_wins(self, tmp_path):
        directory = self._write(tmp_path, 'fte://%s@from-file:1' % SERVER_ID)
        uri, source = fteproxy.config.resolve_client_uri(
            'fte://%s@from-argument:2' % SERVER_ID, directory,
            {'FTEPROXY_URI': 'fte://%s@from-env:3' % SERVER_ID})
        assert uri.host == 'from-argument'
        assert source == 'the command line'

    def test_the_environment_is_next(self, tmp_path):
        directory = self._write(tmp_path, 'fte://%s@from-file:1' % SERVER_ID)
        uri, source = fteproxy.config.resolve_client_uri(
            None, directory, {'FTEPROXY_URI': 'fte://%s@from-env:3' % SERVER_ID})
        assert uri.host == 'from-env'
        assert source == 'FTEPROXY_URI'

    def test_the_file_is_last(self, tmp_path):
        directory = self._write(tmp_path, 'fte://%s@from-file:1' % SERVER_ID)
        uri, source = fteproxy.config.resolve_client_uri(None, directory, {})
        assert uri.host == 'from-file'
        assert source.endswith('connection.txt')

    def test_nothing_anywhere(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        assert fteproxy.config.resolve_client_uri(None, directory, {}) == \
            (None, None)

    def test_the_placeholder_becomes_loopback(self, tmp_path):
        """A string still carrying <server-ip> can only have been written by a
        server on this host, which is what makes `fteproxy server` then
        `fteproxy client` work with no arguments at all."""
        directory = self._write(
            tmp_path, 'fte://%s@%s:9999'
            % (SERVER_ID, fteproxy.config.HOST_PLACEHOLDER))
        uri, _source = fteproxy.config.resolve_client_uri(None, directory, {})
        assert uri.address == ('127.0.0.1', 9999)


# --------------------------------------------------------------------------- #
# The parser
# --------------------------------------------------------------------------- #

class TestParser:

    def test_subcommands(self):
        for name in ('server', 'client', 'keygen', 'formats'):
            assert parse([name]).command == name

    def test_no_subcommand(self):
        assert parse([]).command is None

    def test_client_flags(self):
        args = parse(['client', 'fte://x@h:1', '-D', '1080',
                      '-L', '2222:127.0.0.1:22', '-L', '3333:h:80',
                      '--format', 'words', '--mode', 'format', '--no-check'])
        assert args.uri == 'fte://x@h:1'
        assert args.socks == ['1080']
        assert args.forwards == ['2222:127.0.0.1:22', '3333:h:80']
        assert args.format == 'words'
        assert args.mode == 'format'
        assert args.no_check

    def test_server_flags(self):
        args = parse(['server', '--listen', ':9000', '--allow', 'any',
                      '--allow', '10.0.0.0/8', '--advertise', 'vpn.example:9000',
                      '--defs', '20131224'])
        assert args.listen == ':9000'
        assert args.allow == ['any', '10.0.0.0/8']
        assert args.advertise == 'vpn.example:9000'
        assert args.defs == '20131224'

    def test_mode_choices(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['client', '--mode', 'nonsense'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_quiet_and_verbose_are_mutually_exclusive(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['server', '-q', '-v'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE


class TestRemovedFlags:
    """Every pre-0.4 flag is recognised only to point at the upgrade notes."""

    @pytest.mark.parametrize('flag', fteproxy.cli.REMOVED_FLAGS)
    def test_each_removed_flag(self, flag, capsys):
        assert fteproxy.cli.main([flag, 'whatever']) == fteproxy.cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert flag in err
        assert 'Upgrading to 0.4.0' in err

    def test_flag_with_an_equals_sign(self, capsys):
        assert fteproxy.cli.main(['--key=deadbeef']) == fteproxy.cli.EXIT_USAGE
        assert '--key' in capsys.readouterr().err

    def test_mode_still_works_under_client(self):
        """--mode means the record-layer mode now, so it is only a removed
        flag before a subcommand."""
        assert fteproxy.cli.removed_flag(['client', '--mode', 'hybrid']) is None
        assert fteproxy.cli.removed_flag(['--mode', 'client']) == '--mode'

    def test_no_alias_is_offered(self, capsys):
        """A silent alias would run a different topology than was asked for."""
        fteproxy.cli.main(['--proxy_ip', '127.0.0.1'])
        err = capsys.readouterr().err
        assert 'destination is chosen on the client' in err


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

class TestBareInvocation:

    def test_prints_usage_and_exits_2(self, capsys):
        assert fteproxy.cli.main([]) == fteproxy.cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert 'usage:' in err
        for name in ('server', 'client', 'keygen', 'formats'):
            assert name in err

    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['--version'])
        assert excinfo.value.code == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert fteproxy.__version__ in out
        assert 'NO WARRANTY' in out


class TestKeygen:

    def test_creates_a_key_and_prints_the_string(self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        assert fteproxy.cli.main(['keygen', '--state-dir', directory]) == \
            fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out.strip()
        assert out.startswith('fte://')
        assert fteproxy.config.HOST_PLACEHOLDER in out
        uri = fteproxy.config.ConnectionString.parse(out)
        private = fteproxy.config.load_server_key(directory)
        assert fteproxy.server_id(private) == uri.server_id

    def test_advertise(self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        fteproxy.cli.main(['keygen', '--state-dir', directory,
                           '--advertise', 'vpn.example.com:9000'])
        uri = fteproxy.config.ConnectionString.parse(
            capsys.readouterr().out.strip())
        assert uri.address == ('vpn.example.com', 9000)

    def test_is_idempotent(self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        fteproxy.cli.main(['keygen', '--state-dir', directory])
        first = capsys.readouterr().out
        fteproxy.cli.main(['keygen', '--state-dir', directory])
        assert capsys.readouterr().out == first

    def test_a_bad_advertise_is_a_usage_error(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['keygen', '--state-dir', str(tmp_path),
                               '--advertise', '[::1'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE


class TestFormats:

    def test_lists_base_names_with_capacity(self, capsys):
        assert fteproxy.cli.main(['formats']) == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert 'manual-http' in out
        # Base names only: the direction suffixes are columns, not rows.
        assert 'manual-http-request' not in out
        assert '(default)' in out
        # manual-http-response carries 192 bytes per covertext at length 256.
        assert '192' in out

    def test_honours_the_release(self, capsys):
        assert fteproxy.cli.main(['formats', '--defs', '20131224']) == \
            fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert '20131224' in out
        assert 'manual-ssh' in out

    def test_an_unknown_release_is_a_failure(self, capsys):
        assert fteproxy.cli.main(['formats', '--defs', '19700101']) == \
            fteproxy.cli.EXIT_FAILURE


class TestClientStartup:

    def test_an_unknown_format_is_a_failure(self, tmp_path, capsys):
        assert fteproxy.cli.main([
            'client', 'fte://%s@127.0.0.1:1' % SERVER_ID,
            '--format', 'no-such-format', '--no-check',
            '--state-dir', str(tmp_path)]) == fteproxy.cli.EXIT_FAILURE
        assert 'no-such-format' in capsys.readouterr().err

    def test_a_bad_forward_spec_is_a_usage_error(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main([
                'client', 'fte://%s@127.0.0.1:1' % SERVER_ID,
                '-L', 'nonsense', '--no-check', '--state-dir', str(tmp_path)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_the_startup_check_fails_with_a_reason(self, tmp_path, capsys):
        import socket

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()

        status = fteproxy.cli.main([
            'client', 'fte://%s@127.0.0.1:%d' % (SERVER_ID, port),
            '--state-dir', str(tmp_path)])
        assert status == fteproxy.cli.EXIT_FAILURE
        captured = capsys.readouterr()
        assert 'checking 127.0.0.1:%d' % port in captured.err
        assert 'not running fteproxy 0.4' in captured.err

    def test_no_uri_anywhere_is_a_usage_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv('FTEPROXY_URI', raising=False)
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['client', '--no-check',
                               '--state-dir', str(tmp_path / 'empty')])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE


class TestServerStartup:

    def test_a_bad_allow_rule_is_a_usage_error(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['server', '--listen', ':0',
                               '--allow', 'host:not-a-port',
                               '--state-dir', str(tmp_path)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_a_bad_listen_spec_is_a_usage_error(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['server', '--listen', '[::1',
                               '--state-dir', str(tmp_path)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_a_taken_port_is_a_failure(self, tmp_path, capsys):
        import socket

        taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        taken.bind(('127.0.0.1', 0))
        taken.listen(1)
        port = taken.getsockname()[1]
        try:
            status = fteproxy.cli.main([
                'server', '--listen', '127.0.0.1:%d' % port,
                '--state-dir', str(tmp_path)])
        finally:
            taken.close()
        assert status == fteproxy.cli.EXIT_FAILURE
        assert 'cannot listen' in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

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


class TestLogRedaction:
    """Secrets must not reach a log file, whatever a call site passes.

    The filter lives on the package logger, so it applies to every handler an
    embedding program attaches as well as to the CLI's own.
    """

    def test_a_connection_string_keeps_only_its_shape(self, caplog):
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            fteproxy.info('checking fte://g7RzVlLwycSzfHmHwo2LOdkvZ2rG_-J4lmso'
                          'smKPzQY@203.0.113.5:8080')
        assert 'g7RzVlLwycSz' not in caplog.text
        assert 'fte://…@203.0.113.5:8080' in caplog.text

    def test_a_hex_key_is_removed(self, caplog):
        key = '0123456789abcdef' * 4
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            fteproxy.info('loaded key %s' % key)
        assert key not in caplog.text
        assert '<redacted>' in caplog.text

    def test_a_bare_server_id_is_removed(self, caplog):
        _private, public = fteproxy.generate_server_key()
        text = fteproxy.config.encode_server_id(public)
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            fteproxy.info('server-id ' + text)
        assert text not in caplog.text

    def test_a_secret_passed_as_an_argument_is_removed(self, caplog):
        """%-args are expanded before the filter runs, and the arguments are
        cleared afterwards so a handler cannot re-expand them."""
        key = 'ab' * 32
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            fteproxy.logger.info('key is %s', key)
        assert key not in caplog.text
        assert caplog.records[0].args in ((), None)

    def test_ordinary_messages_are_untouched(self, caplog):
        with caplog.at_level(logging.INFO, logger='fteproxy'):
            fteproxy.info('listening on 127.0.0.1:1080, format manual-http')
        assert 'listening on 127.0.0.1:1080, format manual-http' in caplog.text
