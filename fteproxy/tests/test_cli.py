#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the command line and the configuration it reads.

These call :func:`fteproxy.cli.main` in process, so they assert on the status
the process would exit with rather than on a subprocess return code.
``test_system.py`` covers the subprocess path.
"""

import concurrent.futures
import logging
import os
import stat
import threading
import traceback

import pytest

import fteproxy
import fteproxy.cli
import fteproxy.conf
import fteproxy.config
import fteproxy.defs
import fteproxy.relay


PUBLIC = bytes(range(32))
SERVER_ID = fteproxy.config.encode_server_id(PUBLIC)


@pytest.fixture(autouse=True)
def restore_conf():
    """Snapshot and restore the global configuration around each test.

    The CLI writes process-global state; without this a test that selects a
    non-default definitions release would leak into the next one.
    """
    saved = dict(fteproxy.conf.conf)
    yield
    fteproxy.conf.conf.clear()
    fteproxy.conf.conf.update(saved)


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
        'fte://%s@host:8080?defs=shapes-20260110' % SERVER_ID,
        'fte://%s@:8080' % SERVER_ID,
        # urlsplit itself raises on these, rather than returning a bad parse.
        'fte://[bad',
        'fte://%s@[::1:8080' % SERVER_ID,
    ])
    def test_bad_strings_are_refused(self, text):
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ConnectionString.parse(text)

    def test_an_unsplittable_uri_is_a_config_error(self):
        """An unbalanced bracket makes urlsplit raise ValueError. That is a
        malformed connection string, so it has to reach the user as a usage
        error and not as a traceback -- and still without the string in it."""
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.ConnectionString.parse(
                'fte://%s@[2001:db8::1:8080' % SERVER_ID)
        assert SERVER_ID not in str(excinfo.value)
        assert '2001:db8' not in str(excinfo.value)

    def test_errors_never_quote_the_string(self):
        """An unparseable connection string is still a secret."""
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.ConnectionString.parse(
                'fte://%s@host:99999' % SERVER_ID)
        assert SERVER_ID not in str(excinfo.value)

    @pytest.mark.parametrize('text,secret', [
        ('fte://%s@secret.example:not-a-port' % SERVER_ID, 'secret.example'),
        ('fte://%s@secret.example\uff0fhidden:80' % SERVER_ID,
         'secret.example'),
    ])
    def test_parser_exceptions_suppress_secret_bearing_context(self, text,
                                                               secret):
        """A generic outer message is insufficient if traceback chaining
        preserves the parser exception that quoted the capability."""
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.ConnectionString.parse(text)

        rendered = ''.join(traceback.format_exception(
            type(excinfo.value), excinfo.value, excinfo.value.__traceback__))
        assert excinfo.value.__suppress_context__
        assert SERVER_ID not in rendered
        assert secret not in rendered

    @pytest.mark.parametrize('release', [
        '../private', '..%2Fprivate', '/tmp/private', 'nested/release',
        r'nested\release', '.hidden', 'release.json', 'two words',
        'x' * 65,
    ])
    def test_defs_hint_is_an_identifier_not_a_path(self, release):
        text = 'fte://%s@host:8080?defs=%s' % (SERVER_ID, release)
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ConnectionString.parse(text)

    def test_str_and_repr_are_redacted(self):
        uri = fteproxy.config.ConnectionString(PUBLIC, '203.0.113.5', 8080)
        assert SERVER_ID not in str(uri)
        assert SERVER_ID not in repr(uri)
        assert str(uri) == 'fte://…@203.0.113.5:8080'
        assert uri.redacted() in repr(uri)

    @pytest.mark.parametrize('host', [
        'safe.example\nERROR: forged', 'safe.example\rforged',
        'safe.example\x9bforged',
        'name@example.com', 'example.com/path', 'example.com?query',
        '[::1]',
    ])
    def test_constructor_rejects_log_and_authority_injection(self, host):
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ConnectionString(PUBLIC, host, 8080)

    @pytest.mark.parametrize('port', ['8080', True, None])
    def test_constructor_rejects_non_integral_ports(self, port):
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ConnectionString(PUBLIC, 'example.com', port)


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

    @pytest.mark.parametrize('text,expected', [
        ('example.com', ('example.com', 8080)),
        ('example.com:443', ('example.com', 443)),
        ('203.0.113.5:9000', ('203.0.113.5', 9000)),
        ('[2001:db8::1]:8443', ('2001:db8::1', 8443)),
    ])
    def test_advertise_address_round_trips_through_a_uri(self, text,
                                                          expected):
        address = fteproxy.cli.parse_advertise(text, 8080)
        uri = fteproxy.config.ConnectionString(PUBLIC, *address)
        assert fteproxy.config.ConnectionString.parse(uri.format()).address \
            == expected == address

    @pytest.mark.parametrize('text', [
        '<server-ip>:8080', 'name@example.com:8080',
        'example.com/path:8080', 'example.com?mode=format:8080',
        'example.com#fragment:8080', 'host name:8080',
    ])
    def test_advertise_rejects_uri_delimiters_and_the_placeholder(self, text):
        """An advertised address must produce the address the operator gave.

        Reserved delimiters otherwise move text into the URI's userinfo, path,
        query or fragment when the connection string is rendered.
        """
        with pytest.raises(fteproxy.cli.UsageError):
            fteproxy.cli.parse_advertise(text, 8080)


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

    def test_an_explicit_empty_directory_does_not_fall_back(self):
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.state_dir('', {})
        assert 'must not be empty' in str(excinfo.value)

    def test_created_with_mode_0700(self, tmp_path):
        directory = str(tmp_path / 'state')
        fteproxy.config.ensure_state_dir(directory)
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700

    def test_a_loose_existing_directory_is_refused_without_chmod(self,
                                                                  tmp_path):
        """A surprising privileged invocation must not chmod another tree."""
        directory = tmp_path / 'state'
        directory.mkdir(mode=0o755)
        before = stat.S_IMODE(os.stat(directory).st_mode)
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.ensure_state_dir(str(directory))
        assert stat.S_IMODE(os.stat(directory).st_mode) == before == 0o755
        assert 'chmod 700' in str(excinfo.value)

    def test_a_state_directory_symlink_is_refused(self, tmp_path):
        target = tmp_path / 'actual-state'
        target.mkdir(mode=0o700)
        link = tmp_path / 'state-link'
        link.symlink_to(target, target_is_directory=True)

        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.ensure_state_dir(str(link))
        assert link.is_symlink()
        assert list(target.iterdir()) == []

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

    def test_concurrent_first_key_creation_converges_on_one_identity(
            self, tmp_path, monkeypatch):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        candidates = [fteproxy.generate_server_key()[0] for _ in range(2)]
        barrier = threading.Barrier(2)
        publish = fteproxy.config._write_private_if_absent

        def publish_together(path, text):
            barrier.wait(timeout=5)
            return publish(path, text)

        monkeypatch.setattr(fteproxy.config, '_write_private_if_absent',
                            publish_together)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(
                lambda candidate: fteproxy.config.claim_server_key(
                    directory, candidate),
                candidates))

        assert sum(created for _private, _public, created in results) == 1
        assert results[0][0] == results[1][0] == \
            fteproxy.config.load_server_key(directory)
        assert results[0][1] == results[1][1]

    def test_a_world_readable_key_warns(self, tmp_path, caplog):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        fteproxy.config.ensure_server_key(directory)
        os.chmod(fteproxy.config.server_key_path(directory), 0o644)
        with caplog.at_level(logging.WARNING, logger='fteproxy'):
            fteproxy.config.load_server_key(directory)
        assert 'readable by other users' in caplog.text

    def test_a_world_readable_connection_file_warns(self, tmp_path, caplog):
        path = tmp_path / 'connection.txt'
        uri = fteproxy.config.ConnectionString(PUBLIC, 'example.com', 8080)
        path.write_text(uri.format() + '\n')
        os.chmod(path, 0o644)

        with caplog.at_level(logging.WARNING, logger='fteproxy'):
            assert fteproxy.config.read_connection_file(str(path)) == \
                uri.format()

        assert 'readable by other users' in caplog.text
        assert 'chmod 600' in caplog.text
        assert 'rotate the connection capability' in caplog.text

    def test_managed_server_key_symlink_is_refused(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        private, _public = fteproxy.generate_server_key()
        outside = tmp_path / 'outside.key'
        outside.write_text(private.hex() + '\n')
        os.chmod(outside, 0o600)
        (tmp_path / 'state' / fteproxy.config.SERVER_KEY_FILE).symlink_to(
            outside)

        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.load_server_key(directory)
        assert 'symlink' in str(excinfo.value)

    def test_managed_server_key_hard_link_is_refused(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        private, _public = fteproxy.generate_server_key()
        outside = tmp_path / 'outside.key'
        outside.write_text(private.hex() + '\n')
        os.chmod(outside, 0o600)
        os.link(outside, tmp_path / 'state' / fteproxy.config.SERVER_KEY_FILE)

        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.load_server_key(directory)
        assert 'hard links' in str(excinfo.value)

    @pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='FIFO is POSIX-only')
    def test_managed_fifo_is_rejected_without_opening_it(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        os.mkfifo(tmp_path / 'state' / fteproxy.config.SERVER_KEY_FILE, 0o600)

        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.load_server_key(directory)
        assert 'regular file' in str(excinfo.value)

    def test_implicit_connection_symlink_is_refused(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        outside = tmp_path / 'outside-connection.txt'
        uri = fteproxy.config.ConnectionString(PUBLIC, 'example.com', 8080)
        outside.write_text(uri.format() + '\n')
        os.chmod(outside, 0o600)
        (tmp_path / 'state' / fteproxy.config.CONNECTION_FILE).symlink_to(
            outside)

        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.resolve_client_uri(None, directory, {})
        assert 'symlink' in str(excinfo.value)

    def test_explicit_connection_file_may_be_a_symlink(self, tmp_path):
        """Explicit files are caller-selected inputs, not trusted managed state."""
        target = tmp_path / 'connection.txt'
        uri = fteproxy.config.ConnectionString(PUBLIC, 'example.com', 8080)
        target.write_text(uri.format() + '\n')
        os.chmod(target, 0o600)
        link = tmp_path / 'selected.txt'
        link.symlink_to(target)

        assert fteproxy.config.read_connection_file(str(link)) == uri.format()

    @pytest.mark.parametrize('contents', ['', 'abcdef', 'z' * 64])
    def test_a_corrupt_key_file_is_an_error(self, tmp_path, contents):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        with open(fteproxy.config.server_key_path(directory), 'w') as handle:
            handle.write(contents)
        with pytest.raises(fteproxy.config.ConfigError):
            fteproxy.config.load_server_key(directory)

    @pytest.mark.parametrize('filename', [fteproxy.config.SERVER_KEY_FILE,
                                          fteproxy.config.CONNECTION_FILE])
    def test_a_symlink_at_the_target_is_not_followed(self, tmp_path, filename):
        """Opening the path itself would write the private key wherever a
        symlink planted in the state directory pointed, and apply the 0600 to
        that file rather than to ours."""
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        outside = tmp_path / 'outside.txt'
        outside.write_text('not the key\n')
        planted = tmp_path / 'state' / filename
        planted.symlink_to(outside)

        private, public = fteproxy.generate_server_key()
        fteproxy.config.save_server_key(directory, private)
        fteproxy.config.write_connection_string(
            directory, fteproxy.config.ConnectionString(public, 'host', 8080))

        assert outside.read_text() == 'not the key\n'
        assert not planted.is_symlink()
        assert stat.S_IMODE(os.stat(str(planted)).st_mode) == 0o600
        assert fteproxy.config.load_server_key(directory) == private
        # And nothing was left lying around beside them.
        assert sorted(entry.name for entry in (tmp_path / 'state').iterdir()) \
            == sorted([fteproxy.config.SERVER_KEY_FILE,
                       fteproxy.config.CONNECTION_FILE])

    def test_a_failed_write_leaves_nothing_behind(self, tmp_path):
        """The error the caller sees is the one that happened.

        A lone surrogate cannot be encoded, so the write fails on the way out.
        The descriptor has to be closed exactly once on that path: closing it
        twice raised EBADF from the handler and buried the real error -- or,
        worse, closed whatever file had since been given the number.
        """
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        path = fteproxy.config.server_key_path(directory)
        with pytest.raises(UnicodeEncodeError):
            fteproxy.config._write_private(path, 'key\ud800\n')
        assert list((tmp_path / 'state').iterdir()) == []


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

    @pytest.mark.parametrize('source', ['argument', 'environment'])
    def test_a_supplied_placeholder_is_an_error(self, tmp_path, source):
        text = 'fte://%s@%s:9999' \
            % (SERVER_ID, fteproxy.config.HOST_PLACEHOLDER)
        argument = text if source == 'argument' else None
        environ = {'FTEPROXY_URI': text} if source == 'environment' else {}
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.resolve_client_uri(argument, str(tmp_path),
                                               environ)
        assert '<server-ip>' in str(excinfo.value)
        assert SERVER_ID not in str(excinfo.value)

    def test_the_file_is_last(self, tmp_path):
        directory = self._write(tmp_path, 'fte://%s@from-file:1' % SERVER_ID)
        uri, source = fteproxy.config.resolve_client_uri(None, directory, {})
        assert uri.host == 'from-file'
        assert source.endswith('connection.txt')

    def test_nothing_anywhere(self, tmp_path):
        directory = fteproxy.config.ensure_state_dir(str(tmp_path / 'state'))
        assert fteproxy.config.resolve_client_uri(None, directory, {}) == \
            (None, None)

    def test_an_explicit_connection_file_is_bounded(self, tmp_path):
        path = tmp_path / 'connection.txt'
        path.write_text('x' * (fteproxy.config.MAX_CONNECTION_STRING_BYTES + 1))
        with pytest.raises(fteproxy.config.ConfigError) as excinfo:
            fteproxy.config.resolve_client_uri(
                connection_file=str(path), environ={})
        assert 'too long' in str(excinfo.value)

    def test_the_placeholder_becomes_loopback(self, tmp_path):
        """Legacy placeholders in managed same-host state resolve to loopback."""
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
        for name in ('server', 'client', 'keygen', 'formats', 'defs-check'):
            assert parse([name]).command == name

    def test_no_subcommand(self):
        assert parse([]).command is None

    def test_client_flags(self):
        args = parse(['client', 'fte://x@h:1', '-D', '1080',
                      '-L', '2222:127.0.0.1:22', '-L', '3333:h:80',
                      '--format', 'words', '--mode', 'format', '--no-check',
                      '--expose-listeners', '--max-pending', '19',
                      '--max-pending-per-source', '7'])
        assert args.uri == 'fte://x@h:1'
        assert args.socks == ['1080']
        assert args.forwards == ['2222:127.0.0.1:22', '3333:h:80']
        assert args.format == 'words'
        assert args.mode == 'format'
        assert args.no_check
        assert args.expose_listeners
        assert args.max_pending == 19
        assert args.max_pending_per_source == 7

    def test_secure_connection_source_flags(self):
        from_file = parse(['client', '--connection-file', 'secret.txt'])
        assert from_file.connection_file == 'secret.txt'
        assert not from_file.connection_stdin

        from_stdin = parse(['client', '--connection-stdin'])
        assert from_stdin.connection_stdin
        assert from_stdin.connection_file is None

    def test_listener_options_have_readable_long_names(self):
        args = parse([
            'client', '--socks-listen', '1080',
            '--forward', '2222:target.example:22'])
        assert args.socks == ['1080']
        assert args.forwards == ['2222:target.example:22']

    def test_server_flags(self):
        args = parse(['server', '--listen', ':9000', '--allow', 'any',
                      '--allow', '10.0.0.0/8', '--advertise', 'vpn.example:9000',
                      '--defs', '20131224', '--max-pending', '23',
                      '--max-pending-per-source', '5', '--max-active', '101',
                      '--max-active-per-source', '37'])
        assert args.listen == ':9000'
        assert args.allow == ['any', '10.0.0.0/8']
        assert args.advertise == 'vpn.example:9000'
        assert args.defs == '20131224'
        assert args.max_pending == 23
        assert args.max_pending_per_source == 5
        assert args.max_active == 101
        assert args.max_active_per_source == 37

    @pytest.mark.parametrize('flag', ['--max-pending',
                                      '--max-pending-per-source'])
    @pytest.mark.parametrize('value', ['0', '-1', 'many'])
    @pytest.mark.parametrize('command', ['server', 'client'])
    def test_setup_limits_must_be_positive_integers(self, command, flag, value):
        with pytest.raises(SystemExit) as excinfo:
            parse([command, flag, value])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    @pytest.mark.parametrize('flag', ['--max-active',
                                      '--max-active-per-source'])
    @pytest.mark.parametrize('value', ['0', '-1', 'many'])
    def test_active_limits_must_be_positive_integers(self, flag, value):
        with pytest.raises(SystemExit) as excinfo:
            parse(['server', flag, value])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_mode_choices(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['client', '--mode', 'nonsense'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_quiet_and_verbose_are_mutually_exclusive(self):
        with pytest.raises(SystemExit) as excinfo:
            parse(['server', '-q', '-v'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    @pytest.mark.parametrize('argv', [
        ['--vers'],
        ['server', '--lis', ':8080'],
        ['server', '--adv', 'example.com:8080'],
        ['client', '--no-c'],
        ['client', '--connection-f', 'secret.txt'],
        ['client', '--connection-s'],
        ['client', '--expose-l'],
        ['keygen', '--adv', 'example.com:8080'],
        ['formats', '--de', '20260903'],
        ['defs-check', '--de', '20260903'],
    ])
    def test_long_options_cannot_be_abbreviated(self, argv):
        with pytest.raises(SystemExit) as excinfo:
            parse(argv)
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    @pytest.mark.parametrize('command', ['formats', 'defs-check'])
    @pytest.mark.parametrize('release', [
        '../private', '/tmp/private', r'nested\release', 'release.json',
        '.hidden', 'x' * 65,
    ])
    def test_defs_argument_is_a_bounded_identifier(self, command, release):
        with pytest.raises(SystemExit) as excinfo:
            parse([command, '--defs', release])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    @pytest.mark.parametrize('command', ['formats', 'defs-check'])
    def test_a_named_catalog_release_remains_valid(self, command):
        assert parse([command, '--defs', 'shapes-20260110']).defs == \
            'shapes-20260110'

    @pytest.mark.parametrize('release', [
        '2026090', '202609030', 'shapes-20260110', 'abcdefgh',
    ])
    def test_a_server_defs_release_is_exactly_eight_digits(self, release):
        with pytest.raises(SystemExit) as excinfo:
            parse(['server', '--defs', release])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_keygen_uses_the_same_dated_release_contract_as_server(self):
        assert parse(['keygen', '--defs', '20260903']).defs == '20260903'
        with pytest.raises(SystemExit) as excinfo:
            parse(['keygen', '--defs', 'shapes-20260110'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE


class TestRemovedFlags:
    """Every pre-1.0 flag is recognised only to point at the upgrade notes."""

    @pytest.mark.parametrize('flag', fteproxy.cli.REMOVED_FLAGS)
    def test_each_removed_flag(self, flag, capsys):
        assert fteproxy.cli.main([flag, 'whatever']) == fteproxy.cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert flag in err
        assert 'Upgrading to 1.0.0' in err

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
        for name in ('server', 'client', 'keygen', 'formats', 'defs-check'):
            assert name in err

    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['--version'])
        assert excinfo.value.code == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert fteproxy.__version__ in out
        assert 'NO WARRANTY' in out


class TestKeygen:

    def test_creates_a_key_and_prints_a_valid_local_string(self, tmp_path,
                                                            capsys):
        directory = str(tmp_path / 'state')
        assert fteproxy.cli.main(['keygen', '--state-dir', directory]) == \
            fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out.strip()
        assert out.startswith('fte://')
        assert fteproxy.config.HOST_PLACEHOLDER not in out
        uri = fteproxy.config.ConnectionString.parse(out)
        assert uri.address == ('127.0.0.1', fteproxy.config.DEFAULT_PORT)
        private = fteproxy.config.load_server_key(directory)
        assert fteproxy.server_id(private) == uri.server_id

    def test_advertise(self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        fteproxy.cli.main(['keygen', '--state-dir', directory,
                           '--advertise', 'vpn.example.com:9000'])
        uri = fteproxy.config.ConnectionString.parse(
            capsys.readouterr().out.strip())
        assert uri.address == ('vpn.example.com', 9000)

    def test_without_advertise_preserves_the_existing_remote_endpoint(
            self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        assert fteproxy.cli.main([
            'keygen', '--state-dir', directory,
            '--advertise', 'vpn.example.com:9000']) == fteproxy.cli.EXIT_OK
        capsys.readouterr()

        assert fteproxy.cli.main(['keygen', '--state-dir', directory]) == \
            fteproxy.cli.EXIT_OK
        captured = capsys.readouterr()
        uri = fteproxy.config.ConnectionString.parse(captured.out.strip())
        assert uri.address == ('vpn.example.com', 9000)
        assert 'kept the previously advertised remote endpoint' in captured.err

    def test_is_idempotent(self, tmp_path, capsys):
        directory = str(tmp_path / 'state')
        fteproxy.cli.main(['keygen', '--state-dir', directory])
        first = capsys.readouterr().out
        fteproxy.cli.main(['keygen', '--state-dir', directory])
        assert capsys.readouterr().out == first

    def test_a_bad_advertise_is_a_usage_error(self, tmp_path):
        directory = tmp_path / 'state'
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['keygen', '--state-dir', str(directory),
                               '--advertise', '[::1'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert not directory.exists()

    def test_an_unsafe_advertise_does_not_create_a_key(self, tmp_path):
        directory = tmp_path / 'state'
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main([
                'keygen', '--state-dir', str(directory),
                '--advertise', 'name@example.com:8080'])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert not directory.exists()


class TestFormats:

    def test_release_lookup_cannot_escape_the_definitions_directories(
            self, tmp_path):
        defs_dir = tmp_path / 'defs'
        defs_dir.mkdir()
        escaped = tmp_path / 'outside.json'
        escaped.write_text('{}\n')
        fteproxy.conf.setValue('general.defs_dir', str(defs_dir))

        with pytest.raises(fteproxy.defs.DefinitionsError):
            fteproxy.defs._release_path('../outside')

    def test_lists_base_names_with_capacity(self, capsys):
        """The shape catalog, which is where manual-http lives since the
        20260903 release made the five cleartext protocols the default."""
        assert fteproxy.cli.main(['formats', '--defs', '20260110']) == \
            fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert 'manual-http' in out
        # Base names only: the direction suffixes are columns, not rows.
        assert 'manual-http-request' not in out
        # The table reports cipher capacity, before the record seal and type byte.
        assert '192' in out

    def test_the_default_release_is_the_five_protocols(self, capsys):
        assert fteproxy.cli.main(['formats']) == fteproxy.cli.EXIT_OK
        out = capsys.readouterr().out
        assert '20260903' in out
        for base in ('http', 'ftp', 'smtp', 'sip', 'dns'):
            assert base in out
        # Base names only: the direction suffixes are columns, not rows.
        assert 'http-request' not in out
        assert '(default)' in out
        # The default base is http, and it is the only one marked.
        assert out.count('(default)') == 1
        assert 'http' in [line.split()[0] for line in out.splitlines()
                          if '(default)' in line]

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
        assert 'not running fteproxy 1.0' in captured.err

    def test_no_uri_anywhere_is_a_usage_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv('FTEPROXY_URI', raising=False)
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['client', '--no-check',
                               '--state-dir', str(tmp_path / 'empty')])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    def test_local_listener_is_bound_before_check_and_stopped_on_failure(
            self, tmp_path, monkeypatch):
        events = []

        class _Listener:
            def __init__(self, local_ip, local_port, **kwargs):
                self.address = (local_ip, local_port)

            def bind(self):
                events.append('bind')

            def stop(self):
                events.append('stop')

        def fail_check(args, listener, uri):
            events.append('check')
            return False

        monkeypatch.setattr(fteproxy.relay, 'SocksListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'run_startup_check', fail_check)
        uri = fteproxy.config.ConnectionString(
            PUBLIC, 'server.example', 8080).format()

        status = fteproxy.cli.main([
            'client', uri, '--state-dir', str(tmp_path / 'state')])

        assert status == fteproxy.cli.EXIT_FAILURE
        assert events == ['bind', 'check', 'stop']


class TestClientConnectionSources:
    """Secure URI sources work without putting a capability in process argv."""

    @pytest.fixture
    def client_cli(self, monkeypatch, tmp_path):
        built = []
        directory = tmp_path / 'state'

        class _Listener:
            def __init__(self, local_ip, local_port, *args, **kwargs):
                self.address = (local_ip, local_port)
                self.daemon = False
                built.append({'bind': self.address, **kwargs})

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'SocksListener', _Listener)
        monkeypatch.setattr(fteproxy.relay, 'ForwardListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)
        monkeypatch.delenv(fteproxy.config.ENV_URI, raising=False)

        def invoke(extra):
            built[:] = []
            status = fteproxy.cli.main(
                ['client'] + list(extra) +
                ['--no-check', '--state-dir', str(directory)])
            return status, list(built)

        return invoke, directory

    @staticmethod
    def _uri(host, port=8080):
        return fteproxy.config.ConnectionString(PUBLIC, host, port).format()

    def test_client_setup_limits_reach_every_listener(self, client_cli):
        invoke, _directory = client_cli

        status, built = invoke([
            self._uri('server.example'), '-D', '1080',
            '-L', '2222:target.example:22', '--max-pending', '11',
            '--max-pending-per-source', '3'])

        assert status == fteproxy.cli.EXIT_OK
        assert len(built) == 2
        assert all(item['max_pending'] == 11 for item in built)
        assert all(item['max_pending_per_source'] == 3 for item in built)
        assert built[0]['setup_admission'] is built[1]['setup_admission']
        assert built[0]['setup_admission'].maximum == 11
        assert built[0]['setup_admission'].per_source == 3

    def test_connection_file_beats_environment_and_implicit_state(
            self, client_cli, monkeypatch, tmp_path):
        invoke, directory = client_cli
        state = fteproxy.config.ensure_state_dir(str(directory))
        fteproxy.config.write_connection_string(
            state, fteproxy.config.ConnectionString(
                PUBLIC, 'from-state.example', 8001))
        monkeypatch.setenv(
            fteproxy.config.ENV_URI, self._uri('from-env.example', 8002))
        connection_file = tmp_path / 'given-connection.txt'
        connection_file.write_text(self._uri('from-file.example', 8003) + '\n')
        os.chmod(connection_file, 0o600)

        status, built = invoke(
            ['--connection-file', str(connection_file)])

        assert status == fteproxy.cli.EXIT_OK
        assert built[0]['server_address'] == ('from-file.example', 8003)

    def test_connection_stdin_beats_environment_and_implicit_state(
            self, client_cli, monkeypatch):
        import io

        invoke, directory = client_cli
        state = fteproxy.config.ensure_state_dir(str(directory))
        fteproxy.config.write_connection_string(
            state, fteproxy.config.ConnectionString(
                PUBLIC, 'from-state.example', 8001))
        monkeypatch.setenv(
            fteproxy.config.ENV_URI, self._uri('from-env.example', 8002))
        monkeypatch.setattr(
            fteproxy.cli.sys, 'stdin',
            io.StringIO(self._uri('from-stdin.example', 8004) + '\n'))

        status, built = invoke(['--connection-stdin'])

        assert status == fteproxy.cli.EXIT_OK
        assert built[0]['server_address'] == ('from-stdin.example', 8004)

    def test_implicit_connection_refuses_a_loose_state_directory(
            self, client_cli):
        invoke, directory = client_cli
        directory.mkdir(mode=0o755)
        connection = directory / fteproxy.config.CONNECTION_FILE
        connection.write_text(self._uri('replaceable.example') + '\n')
        os.chmod(connection, 0o600)

        status, built = invoke([])

        assert status == fteproxy.cli.EXIT_FAILURE
        assert built == []
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o755

    @pytest.mark.parametrize('sources', [
        ('argument', 'file'), ('argument', 'stdin'), ('file', 'stdin'),
    ])
    def test_explicit_connection_sources_are_mutually_exclusive(
            self, client_cli, monkeypatch, tmp_path, capsys, sources):
        import io

        invoke, _directory = client_cli
        uri = self._uri('secret-source.example')
        connection_file = tmp_path / 'connection.txt'
        connection_file.write_text(uri + '\n')
        os.chmod(connection_file, 0o600)
        monkeypatch.setattr(fteproxy.cli.sys, 'stdin', io.StringIO(uri + '\n'))
        args = []
        if 'argument' in sources:
            args.append(uri)
        if 'file' in sources:
            args += ['--connection-file', str(connection_file)]
        if 'stdin' in sources:
            args.append('--connection-stdin')

        with pytest.raises(SystemExit) as excinfo:
            invoke(args)

        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        captured = capsys.readouterr()
        assert SERVER_ID not in captured.err
        assert 'secret-source.example' not in captured.err

    @pytest.mark.parametrize('source', [
        'argument', 'environment', 'file', 'stdin',
    ])
    def test_placeholder_is_rejected_from_every_explicit_source(
            self, client_cli, monkeypatch, tmp_path, capsys, source):
        import io

        invoke, _directory = client_cli
        uri = self._uri(fteproxy.config.HOST_PLACEHOLDER)
        args = []
        if source == 'argument':
            args.append(uri)
        elif source == 'environment':
            monkeypatch.setenv(fteproxy.config.ENV_URI, uri)
        elif source == 'file':
            path = tmp_path / 'explicit.txt'
            path.write_text(uri + '\n')
            os.chmod(path, 0o600)
            args += ['--connection-file', str(path)]
        else:
            monkeypatch.setattr(fteproxy.cli.sys, 'stdin',
                                io.StringIO(uri + '\n'))
            args.append('--connection-stdin')

        with pytest.raises(SystemExit) as excinfo:
            invoke(args)

        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        captured = capsys.readouterr()
        assert SERVER_ID not in captured.err

    def test_implicit_state_placeholder_alone_maps_to_loopback(self,
                                                               client_cli):
        invoke, directory = client_cli
        state = fteproxy.config.ensure_state_dir(str(directory))
        fteproxy.config.write_connection_string(
            state, fteproxy.config.ConnectionString(
                PUBLIC, fteproxy.config.HOST_PLACEHOLDER, 8080))

        status, built = invoke([])

        assert status == fteproxy.cli.EXIT_OK
        assert built[0]['server_address'] == ('127.0.0.1', 8080)

    def test_argparse_error_does_not_echo_an_extra_uri(self, client_cli,
                                                        capsys):
        invoke, _directory = client_cli
        uri = self._uri('secret-argument.example')

        with pytest.raises(SystemExit) as excinfo:
            invoke([uri, uri])

        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        captured = capsys.readouterr()
        assert SERVER_ID not in captured.err
        assert 'secret-argument.example' not in captured.err

    def test_argparse_redacts_a_uri_suffix_after_embedded_whitespace(
            self, client_cli, capsys):
        invoke, _directory = client_cli
        valid = self._uri('first.example')
        malformed = self._uri('secret-prefix.example') + \
            '\nSECRET-SUFFIX.example:9443'

        with pytest.raises(SystemExit) as excinfo:
            invoke([valid, malformed])

        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        captured = capsys.readouterr()
        assert SERVER_ID not in captured.err
        assert 'secret-prefix.example' not in captured.err
        assert 'SECRET-SUFFIX.example' not in captured.err


class TestClientListenerExposure:
    @pytest.fixture
    def listener_cli(self, monkeypatch, tmp_path):
        built = []

        class _Listener:
            def __init__(self, local_ip, local_port, *args, **kwargs):
                self.address = (local_ip, local_port)
                self.daemon = False
                built.append((self.address, kwargs))

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'SocksListener', _Listener)
        monkeypatch.setattr(fteproxy.relay, 'ForwardListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)
        uri = fteproxy.config.ConnectionString(
            PUBLIC, 'server.example', 8080).format()

        def invoke(extra):
            built[:] = []
            status = fteproxy.cli.main([
                'client', uri, '--no-check',
                '--state-dir', str(tmp_path / 'state')] + list(extra))
            return status, list(built)

        return invoke

    @pytest.mark.parametrize('listener', [
        ['-D', ':1080'],
        ['-D', '0.0.0.0:1080'],
        ['-D', '[::]:1080'],
        ['-D', '192.0.2.10:1080'],
        ['-L', '0.0.0.0:2222:target.example:22'],
        ['-L', '[::]:2222:target.example:22'],
    ])
    def test_non_loopback_listener_needs_an_explicit_gate(
            self, listener_cli, listener):
        with pytest.raises(SystemExit) as excinfo:
            listener_cli(listener)
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE

    @pytest.mark.parametrize('listener,expected', [
        (['-D', '0.0.0.0:1080'], ('0.0.0.0', 1080)),
        (['-D', '[::]:1080'], ('::', 1080)),
        (['-L', '192.0.2.10:2222:target.example:22'],
         ('192.0.2.10', 2222)),
    ])
    def test_expose_listeners_permits_the_requested_bind(
            self, listener_cli, listener, expected):
        status, built = listener_cli(listener + ['--expose-listeners'])
        assert status == fteproxy.cli.EXIT_OK
        assert built[0][0] == expected

    @pytest.mark.parametrize('listener,expected', [
        (['-D', '1080'], ('127.0.0.1', 1080)),
        (['-D', '127.0.0.2:1080'], ('127.0.0.2', 1080)),
        (['-D', '[::1]:1080'], ('::1', 1080)),
        (['-L', '2222:target.example:22'], ('127.0.0.1', 2222)),
    ])
    def test_loopback_listeners_need_no_gate(self, listener_cli, listener,
                                              expected):
        status, built = listener_cli(listener)
        assert status == fteproxy.cli.EXIT_OK
        assert built[0][0] == expected


class TestPortSelectsTheFormat:
    """Format selection uses URI hints before port metadata and the fallback.

    An explicit --format wins over both; a port mismatch produces a warning.
    """

    @pytest.fixture
    def chosen(self, monkeypatch, tmp_path):
        """Run ``fteproxy client`` and report the format it handed a listener.

        The listener is replaced, so nothing is dialled and no port is bound:
        the assertion is about the choice, which is made before either.
        """
        captured = {}

        class _Listener:
            def __init__(self, local_ip, local_port, *args, **kwargs):
                captured.update(kwargs)
                self.address = (local_ip, local_port)
                self.daemon = False

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ForwardListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)

        def run(port, *extra, query=''):
            captured.clear()
            status = fteproxy.cli.main([
                'client', 'fte://%s@203.0.113.5:%d%s' % (SERVER_ID, port, query),
                '-L', '19999:127.0.0.1:22', '--no-check',
                '--state-dir', str(tmp_path)] + list(extra))
            assert status == fteproxy.cli.EXIT_OK
            return captured['format']

        return run

    @pytest.mark.parametrize('port,expected', [
        (21, 'ftp'),
        (25, 'smtp'),
        (587, 'smtp'),
        (53, 'dns'),
        (5060, 'sip'),
        (80, 'http'),
        (8080, 'http'),
    ])
    def test_the_port_picks_the_format(self, chosen, port, expected):
        assert chosen(port) == expected

    @pytest.mark.parametrize('port', [1, 4433, 9001, 51820])
    def test_an_unlisted_port_falls_back_to_http(self, chosen, port):
        assert chosen(port) == fteproxy.cli.DEFAULT_FORMAT == 'http'

    def test_the_uri_hint_beats_the_port(self, chosen):
        assert chosen(21, query='?format=sip') == 'sip'

    def test_the_flag_beats_everything(self, chosen):
        assert chosen(21, '--format', 'smtp', query='?format=sip') == 'smtp'

    def test_a_flag_that_disagrees_with_the_port_warns(self, chosen, capsys):
        """The choice is honoured, but an FTP-shaped stream on port 53 is what
        the format is meant to avoid, so it is said out loud."""
        assert chosen(21, '--format', 'dns') == 'dns'
        assert 'does not match port 21' in capsys.readouterr().err

    def test_the_port_default_does_not_warn(self, chosen, capsys):
        assert chosen(21) == 'ftp'
        assert 'does not match port' not in capsys.readouterr().err


class TestFormatForPort:
    """The mapping itself, without the command line around it."""

    @pytest.mark.parametrize('port,expected', [
        (21, 'ftp'), (25, 'smtp'), (587, 'smtp'), (53, 'dns'),
        (5060, 'sip'), (80, 'http'), (8000, 'http'), (8080, 'http'),
    ])
    def test_a_listed_port(self, port, expected):
        assert fteproxy.config.format_for_port(port) == expected

    @pytest.mark.parametrize('port', [1, 22, 443, 1080, 9001])
    def test_an_unlisted_port_matches_nothing(self, port):
        assert fteproxy.config.format_for_port(port) is None

    def test_a_release_without_port_lists_matches_nothing(self):
        """The shape catalog carries no ports, so the caller's own default
        stands and nothing is silently renamed."""
        shapes = {'manual-http-request': {'regex': '^[a-z]+$'},
                  'manual-http-response': {'regex': '^[a-z]+$'}}
        assert fteproxy.config.format_for_port(80, shapes) is None


class TestServeForeverLifecycle:

    def test_a_later_thread_start_failure_cleans_every_listener_and_signal(
            self, monkeypatch):
        events = []
        old_handlers = {
            fteproxy.cli.signal.SIGINT: object(),
            fteproxy.cli.signal.SIGTERM: object(),
        }
        handlers = dict(old_handlers)

        def set_signal(signum, handler):
            previous = handlers[signum]
            handlers[signum] = handler
            return previous

        class _Listener:
            def __init__(self, name, fail=False):
                self.name = name
                self.fail = fail
                self.daemon = False

            def start(self):
                events.append(('start', self.name))
                if self.fail:
                    raise RuntimeError('thread start failed')

            def stop(self):
                events.append(('stop', self.name))

        monkeypatch.setattr(fteproxy.cli.signal, 'signal', set_signal)
        first = _Listener('first')
        second = _Listener('second', fail=True)

        assert fteproxy.cli.serve_forever([first, second]) == \
            fteproxy.cli.EXIT_FAILURE

        assert events == [('start', 'first'), ('start', 'second'),
                          ('stop', 'first'), ('stop', 'second')]
        assert handlers == old_handlers

    def test_a_terminal_listener_error_is_a_failed_run(self, monkeypatch):
        events = []

        class _Listener:
            daemon = False
            terminal_error = 'accept failed: descriptor exhausted'

            def start(self):
                events.append('start')

            def is_alive(self):
                return True

            def stop(self):
                events.append('stop')

        monkeypatch.setattr(fteproxy.cli.signal, 'signal',
                            lambda signum, handler: object())

        assert fteproxy.cli.serve_forever([_Listener()]) == \
            fteproxy.cli.EXIT_FAILURE
        assert events == ['start', 'stop']


class TestServerStartup:

    def test_active_session_limits_reach_the_server_listener(
            self, tmp_path, monkeypatch):
        captured = {}

        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                captured.update(kwargs)
                self.address = (host, port)

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)

        status = fteproxy.cli.main([
            'server', '--listen', '127.0.0.1:8080', '--max-active', '91',
            '--max-active-per-source', '17', '--state-dir',
            str(tmp_path / 'state')])

        assert status == fteproxy.cli.EXIT_OK
        assert captured['max_active'] == 91
        assert captured['max_active_per_source'] == 17

    def test_a_bad_allow_rule_is_a_usage_error(self, tmp_path):
        directory = tmp_path / 'state'
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['server', '--listen', '127.0.0.1:8080',
                               '--allow', 'host:not-a-port',
                               '--state-dir', str(directory)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert not directory.exists()

    def test_a_bad_listen_spec_is_a_usage_error(self, tmp_path):
        directory = tmp_path / 'state'
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main(['server', '--listen', '[::1',
                               '--state-dir', str(directory)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert not directory.exists()

    @pytest.mark.parametrize('advertise', [
        '<server-ip>:8080', 'name@example.com:8080',
        'example.com/path:8080', 'example.com?mode=format:8080',
    ])
    def test_a_bad_advertise_has_no_state_side_effect(self, tmp_path,
                                                       advertise):
        directory = tmp_path / 'state'
        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main([
                'server', '--advertise', advertise,
                '--state-dir', str(directory)])
        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert not directory.exists()

    def test_invalid_arguments_do_not_chmod_an_existing_directory(self,
                                                                   tmp_path):
        directory = tmp_path / 'unrelated'
        directory.mkdir(mode=0o755)
        sentinel = directory / 'keep.txt'
        sentinel.write_text('untouched\n')
        before = stat.S_IMODE(os.stat(directory).st_mode)

        with pytest.raises(SystemExit) as excinfo:
            fteproxy.cli.main([
                'server', '--listen', '[::1',
                '--state-dir', str(directory)])

        assert excinfo.value.code == fteproxy.cli.EXIT_USAGE
        assert stat.S_IMODE(os.stat(directory).st_mode) == before == 0o755
        assert sentinel.read_text() == 'untouched\n'
        assert sorted(entry.name for entry in directory.iterdir()) == \
            ['keep.txt']

    def test_a_taken_port_is_a_failure_without_rewriting_state(
            self, tmp_path, monkeypatch, capsys):
        directory = fteproxy.config.ensure_state_dir(
            str(tmp_path / 'state'))
        private, public, _created = \
            fteproxy.config.ensure_server_key(directory)
        old_uri = fteproxy.config.ConnectionString(
            public, 'old.example', 4444, defs='20260903')
        fteproxy.config.write_connection_string(directory, old_uri)
        key_path = tmp_path / 'state' / fteproxy.config.SERVER_KEY_FILE
        connection_path = (tmp_path / 'state'
                           / fteproxy.config.CONNECTION_FILE)
        key_before = key_path.read_text()
        connection_before = connection_path.read_text()

        class _TakenListener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                raise OSError('address already in use')

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _TakenListener)
        status = fteproxy.cli.main([
            'server', '--listen', '127.0.0.1:43210',
            '--advertise', 'new.example:43210',
            '--state-dir', directory])
        assert status == fteproxy.cli.EXIT_FAILURE
        assert 'cannot listen' in capsys.readouterr().err
        assert key_path.read_text() == key_before
        assert connection_path.read_text() == connection_before
        assert fteproxy.config.load_server_key(directory) == private

    def test_bind_failure_does_not_persist_a_new_identity(
            self, tmp_path, monkeypatch, capsys):
        directory = tmp_path / 'new-state'

        class _TakenListener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                raise OSError('address already in use')

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _TakenListener)
        status = fteproxy.cli.main([
            'server', '--listen', '127.0.0.1:43210',
            '--advertise', 'new.example:43210',
            '--state-dir', str(directory)])

        assert status == fteproxy.cli.EXIT_FAILURE
        assert 'cannot listen' in capsys.readouterr().err
        assert not directory.exists()

    def test_concurrent_identity_winner_stops_the_mismatched_listener(
            self, tmp_path, monkeypatch, capsys):
        events = []

        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                events.append('bind')

            def stop(self):
                events.append('stop')

        other_private, other_public = fteproxy.generate_server_key()
        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(
            fteproxy.config, 'claim_server_key',
            lambda directory, candidate:
                (other_private, other_public, False))
        directory = tmp_path / 'state'

        status = fteproxy.cli.main([
            'server', '--listen', '127.0.0.1:8080',
            '--state-dir', str(directory)])

        assert status == fteproxy.cli.EXIT_FAILURE
        assert 'initialized concurrently' in capsys.readouterr().err
        assert events == ['bind', 'stop']
        assert not (directory / fteproxy.config.CONNECTION_FILE).exists()

    def test_output_failure_after_bind_stops_the_server_listener(
            self, tmp_path, monkeypatch):
        events = []

        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                events.append('bind')

            def stop(self):
                events.append('stop')

        def broken_output(*args, **kwargs):
            raise BrokenPipeError('closed output')

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, '_report', broken_output)
        monkeypatch.setattr(
            fteproxy.cli, 'serve_forever',
            lambda listeners: pytest.fail('must not start after output fails'))

        with pytest.raises(BrokenPipeError):
            fteproxy.cli.do_server(parse([
                'server', '--listen', '127.0.0.1:8080',
                '--state-dir', str(tmp_path / 'state')]))

        assert events == ['bind', 'stop']

    @pytest.mark.parametrize('advertise,expected_host', [
        (None, '127.0.0.1'),
        ('secret-host.example:8080', 'secret-host.example'),
    ])
    def test_server_writes_a_valid_uri_without_printing_the_capability(
            self, tmp_path, monkeypatch, capsys, advertise, expected_host):
        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)
        directory = str(tmp_path / 'state')

        argv = [
            'server', '--listen', '127.0.0.1:8080',
            '--state-dir', directory]
        if advertise is not None:
            argv += ['--advertise', advertise]
        assert fteproxy.cli.main(argv) == fteproxy.cli.EXIT_OK

        captured = capsys.readouterr()
        secret = (tmp_path / 'state' / fteproxy.config.CONNECTION_FILE) \
            .read_text().strip()
        parsed = fteproxy.config.ConnectionString.parse(secret)
        assert secret.startswith('fte://')
        assert fteproxy.config.HOST_PLACEHOLDER not in secret
        assert parsed.host == expected_host
        assert secret not in captured.out
        assert secret not in captured.err
        assert fteproxy.config.encode_server_id(parsed.server_id) not in \
            captured.out + captured.err

    @pytest.mark.parametrize('listen', [':8080', '127.0.0.1:8080'])
    def test_restart_preserves_a_previous_remote_endpoint(
            self, tmp_path, monkeypatch, capsys, listen):
        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)
        directory = str(tmp_path / 'state')
        common = ['server', '--listen', listen, '--state-dir', directory]

        assert fteproxy.cli.main(
            common + ['--advertise', 'vpn.example.com:8443']) == \
            fteproxy.cli.EXIT_OK
        capsys.readouterr()
        assert fteproxy.cli.main(common) == fteproxy.cli.EXIT_OK

        text = (tmp_path / 'state' / fteproxy.config.CONNECTION_FILE) \
            .read_text().strip()
        parsed = fteproxy.config.ConnectionString.parse(text)
        assert parsed.address == ('vpn.example.com', 8443)
        captured = capsys.readouterr()
        assert 'kept the previously advertised remote endpoint' in captured.err
        assert text not in captured.out + captured.err

    def test_new_wildcard_server_explains_that_its_invite_is_local_only(
            self, tmp_path, monkeypatch, capsys):
        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)

        assert fteproxy.cli.main([
            'server', '--listen', ':8080',
            '--state-dir', str(tmp_path / 'state')]) == fteproxy.cli.EXIT_OK

        captured = capsys.readouterr()
        assert 'connection.txt is local-only' in captured.err
        assert '--advertise HOST[:PORT]' in captured.err

    def test_print_connection_is_an_explicit_capability_export(
            self, tmp_path, monkeypatch, capsys):
        class _Listener:
            def __init__(self, host, port, private, **kwargs):
                self.address = (host, port)

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ServerListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)
        directory = tmp_path / 'state'

        assert fteproxy.cli.main([
            'server', '--listen', '127.0.0.1:8080',
            '--state-dir', str(directory), '--print-connection', '-q']) == \
            fteproxy.cli.EXIT_OK

        printed = capsys.readouterr().out.strip()
        stored = (directory / fteproxy.config.CONNECTION_FILE).read_text().strip()
        assert printed == stored
        assert fteproxy.config.ConnectionString.parse(printed).host == \
            '127.0.0.1'


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
    """Recognized secret forms are redacted through the package logger's handlers."""

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


class TestModeFollowsTheFormat:
    """Mode precedence is CLI flag, URI hint, format hint, then built-in default."""

    @pytest.fixture
    def chosen_mode(self, monkeypatch, tmp_path):
        captured = {}

        class _Listener:
            def __init__(self, local_ip, local_port, *args, **kwargs):
                captured.update(kwargs)
                self.address = (local_ip, local_port)
                self.daemon = False

            def bind(self):
                pass

            def stop(self):
                pass

        monkeypatch.setattr(fteproxy.relay, 'ForwardListener', _Listener)
        monkeypatch.setattr(fteproxy.cli, 'serve_forever',
                            lambda listeners: fteproxy.cli.EXIT_OK)

        def run(port, *extra, query=''):
            captured.clear()
            status = fteproxy.cli.main([
                'client', 'fte://%s@203.0.113.5:%d%s' % (SERVER_ID, port, query),
                '-L', '19999:127.0.0.1:22', '--no-check',
                '--state-dir', str(tmp_path)] + list(extra))
            assert status == fteproxy.cli.EXIT_OK
            return captured['format'], captured['mode']

        return run

    @pytest.mark.parametrize('port,expected', [
        (21, ('ftp', 'format')),
        (25, ('smtp', 'format')),
        (53, ('dns', 'format')),
        (5060, ('sip', 'format')),
        (80, ('http', 'hybrid')),
        (8080, ('http', 'hybrid')),
    ])
    def test_the_port_default_brings_its_mode(self, chosen_mode, port, expected):
        assert chosen_mode(port) == expected

    def test_an_unlisted_port_is_http_and_hybrid(self, chosen_mode):
        assert chosen_mode(9001) == ('http', 'hybrid')

    def test_the_flag_beats_the_format_hint(self, chosen_mode):
        assert chosen_mode(21, '--mode', 'hybrid') == ('ftp', 'hybrid')
        assert chosen_mode(8080, '--mode', 'format') == ('http', 'format')

    def test_the_uri_hint_beats_the_format_hint(self, chosen_mode):
        assert chosen_mode(21, query='?mode=hybrid') == ('ftp', 'hybrid')

    def test_mode_hint_for_reads_the_release(self):
        assert fteproxy.cli.mode_hint_for('ftp') == 'format'
        assert fteproxy.cli.mode_hint_for('http') == 'hybrid'
        assert fteproxy.cli.mode_hint_for('no-such-format') is None


class TestParseNeverEchoesTheAuthority:
    """Every part of a malformed connection string is secret, host and port
    included, so no ConfigError may quote any of it -- not via urlsplit, not
    via split_host_port, not via the port-range check."""

    @pytest.mark.parametrize('authority,pieces', [
        ('example-host.test:notaport', ('example-host.test', 'notaport')),
        ('example-host.test:99999', ('example-host.test', '99999')),
        ('[::1', ('::1',)),
        ('example-host.test:1:2', ('example-host.test', '1:2')),
    ])
    def test_bad_authority_is_redacted(self, authority, pieces):
        with pytest.raises(fteproxy.config.ConfigError) as info:
            fteproxy.config.ConnectionString.parse(
                'fte://%s@%s' % (SERVER_ID, authority))
        message = str(info.value)
        for piece in pieces:
            assert piece not in message


class TestBareMultiColonHostsMustBeIPv6:
    """An unbracketed host with several colons is accepted only if it really
    is an IPv6 literal; a host name cannot contain a colon, so anything else
    is malformed rather than a strange name with the default port."""

    @pytest.mark.parametrize('text', ['2001:db8::1', '::1', 'fe80::1'])
    def test_a_bare_ipv6_literal_still_works(self, text):
        assert fteproxy.config.split_host_port(text, default_port=8080) == (text, 8080)

    @pytest.mark.parametrize('text', ['example-host.test:1:2', 'a:b:c', 'host:1:2:3'])
    def test_colon_bearing_garbage_is_rejected(self, text):
        with pytest.raises(ValueError):
            fteproxy.config.split_host_port(text, default_port=8080)
