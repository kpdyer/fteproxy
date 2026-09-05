"""Failure cleanup for the two ways of publishing private state files."""

import errno
import os

import pytest

from fteproxy import config


@pytest.fixture(params=['_write_private', '_write_private_if_absent'])
def writer(request):
    return getattr(config, request.param)


def test_fdopen_failure_closes_descriptor(writer, tmp_path, monkeypatch):
    descriptors = []

    def fail_fdopen(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        raise OSError(errno.EIO, 'injected fdopen failure')

    monkeypatch.setattr(config.os, 'fdopen', fail_fdopen)
    with pytest.raises(OSError, match='injected fdopen failure'):
        writer(tmp_path / 'server.key', 'test key\n')
    assert len(descriptors) == 1
    try:
        os.fstat(descriptors[0])
    except OSError as closed:
        assert closed.errno == errno.EBADF
    else:
        os.close(descriptors[0])
        pytest.fail('the temporary file descriptor was left open')
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('stage', ['sync', 'publish'])
def test_failed_publication_preserves_existing_file(
        writer, stage, tmp_path, monkeypatch):
    path = tmp_path / 'server.key'
    path.write_text('existing key\n')

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, 'injected publication failure')

    if stage == 'sync':
        monkeypatch.setattr(config.os, 'fsync', fail)
    else:
        monkeypatch.setattr(config.os, 'replace', fail)
        monkeypatch.setattr(config.os, 'link', fail)

    with pytest.raises(OSError, match='injected publication failure'):
        writer(path, 'replacement key\n')
    assert path.read_text() == 'existing key\n'
    assert list(tmp_path.iterdir()) == [path]
