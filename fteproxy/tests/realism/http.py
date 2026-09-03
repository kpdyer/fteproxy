#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realism check for the ``http`` format, judged by an independent parser.

``check(covertext)`` raises if ``covertext`` is not a structurally valid HTTP/1.1
message. To avoid grading fteproxy's own regex with a mirror of itself, the
judgement is delegated to the standard library's HTTP machinery -- the same code
a real client or DPI stack would lean on:

* a **request** covertext has its request line parsed by
  :class:`http.server.BaseHTTPRequestHandler` (the ``parse_request`` state
  machine) and its header block parsed by :mod:`email.parser`;
* a **response** covertext is parsed by :class:`http.client.HTTPResponse` driven
  over a fake in-memory socket -- the exact class ``http.client`` uses to read a
  real server's reply.

A message that these parsers reject, or that parses into a shape outside the
format's design (an unexpected method, version, status, or a missing mandatory
header), fails the check.
"""

import email.parser
import http.client
import http.server
import io


_METHODS = ('GET', 'POST', 'HEAD')
#: 304 joined the format when the response dropped its body: a response whose
#: status says "no body" is the honest shape for a header-block-only covertext.
_STATUS = {200: 'OK', 302: 'Found', 304: 'Not Modified', 404: 'Not Found'}
_REQUEST_HEADERS = ('Host', 'User-Agent', 'Accept', 'Accept-Language')
_RESPONSE_HEADERS = ('Content-Type', 'Content-Length', 'Server')


class _RequestLineParser(http.server.BaseHTTPRequestHandler):
    """Parse a single request line with the stdlib request state machine.

    ``BaseHTTPRequestHandler.parse_request`` reads ``self.raw_requestline`` and
    fills ``command`` / ``path`` / ``request_version``; on a malformed line it
    calls ``send_error``, which we capture instead of writing to a socket.
    """

    def __init__(self, request_line):
        self.rfile = io.BytesIO(b'')
        self.wfile = io.BytesIO()
        self.raw_requestline = request_line
        self.error_code = None
        self.error_message = None
        self.request_version = ''
        self.command = ''
        self.path = ''
        self.parsed_ok = self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message

    def log_message(self, *args, **kwargs):
        pass


class _FakeSocket:
    """A read-only socket whose ``makefile`` hands back the covertext bytes."""

    def __init__(self, data):
        self._data = data

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self._data)


def _check_request(covertext):
    request_line, separator, remainder = covertext.partition(b'\r\n')
    if not separator:
        raise ValueError('http request: no CRLF after the request line')

    parser = _RequestLineParser(request_line + b'\r\n')
    if not parser.parsed_ok or parser.error_code is not None:
        raise ValueError('http request: unparsable request line %r (error %r)'
                         % (request_line, parser.error_code))
    if parser.command not in _METHODS:
        raise ValueError('http request: unexpected method %r' % parser.command)
    if parser.request_version != 'HTTP/1.1':
        raise ValueError('http request: version %r is not HTTP/1.1'
                         % parser.request_version)
    if not parser.path.startswith('/'):
        raise ValueError('http request: path %r is not absolute' % parser.path)

    # The header block runs from just after the request line to the blank line;
    # email.parser reads the headers and treats anything past the blank line as
    # the (empty) body.
    headers = email.parser.BytesParser().parsebytes(remainder)
    if headers.defects:
        raise ValueError('http request: malformed header block: %r'
                         % headers.defects)
    for name in _REQUEST_HEADERS:
        if headers.get(name) is None:
            raise ValueError('http request: missing %s header' % name)


def _check_response(covertext):
    response = http.client.HTTPResponse(_FakeSocket(covertext))
    try:
        response.begin()
    except Exception as error:
        raise ValueError('http response: unparsable: %s' % error)

    if response.version != 11:
        raise ValueError('http response: version %r is not HTTP/1.1'
                         % response.version)
    if response.status not in _STATUS:
        raise ValueError('http response: unexpected status %r' % response.status)
    if response.reason != _STATUS[response.status]:
        raise ValueError('http response: status %d has reason %r, not %r'
                         % (response.status, response.reason,
                            _STATUS[response.status]))
    for name in _RESPONSE_HEADERS:
        if response.getheader(name) is None:
            raise ValueError('http response: missing %s header' % name)
    # Content-Length must be a well-formed decimal count.
    length = response.getheader('Content-Length')
    if not length.isdigit():
        raise ValueError('http response: Content-Length %r is not numeric'
                         % length)


def check(covertext):
    """Raise if ``covertext`` is not a structurally valid HTTP/1.1 message."""
    if not isinstance(covertext, (bytes, bytearray)):
        raise TypeError('covertext must be bytes, got %r' % type(covertext))
    covertext = bytes(covertext)
    if covertext.startswith(b'HTTP/'):
        _check_response(covertext)
    else:
        _check_request(covertext)
