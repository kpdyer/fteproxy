:mod:`fte.bit_ops` Module
*************************

Overview
--------
The ``fte.bit_ops`` module is an internal module used by modules such as ``fte.encrypter`` and ``fte.encoder``.

Interface
---------

.. automodule:: fte.bit_ops
    :members:
    :undoc-members:
    :show-inheritance:

Examples
--------

In its simplest form, you can use the default keys to perform encryption.

.. code-block:: python

    >>> fte.bit_ops.random_bytes(8)
    'N\xa1\x1aa\x93\xe2\xda+'
    >>> fte.bit_ops.random_bytes(16)
    'WZ\xddS\x83\x86`\xd9\x15\xe91p\xd8\xfdS\x00'
    >>> fte.bit_ops.random_bytes(32)
    '\x86\xc6Pq\xe5\xb8w@\x80=_r\x08X\x02\n\xfa^\x1f\x05\xe0\xa4\x95\xd8br\xe6\x95y\xeb\x05i'

.. code-block:: python

    >>> fte.bit_ops.long_to_bytes(2**20)
    '\x10\x00\x00'
    >>> fte.bit_ops.long_to_bytes(2**100-1)
    '\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'

.. code-block:: python
        
    >>> fte.bit_ops.bytes_to_long('\x10\x00\x00')
    mpz(1048576)
    >>> fte.bit_ops.bytes_to_long('\xff\xff\xff\xff')
    mpz(4294967295L)