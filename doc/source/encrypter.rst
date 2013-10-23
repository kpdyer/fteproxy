Overview
--------

The ``fte.encrypter`` module implements an authenticated encryption (AE) scheme desgined to be used with the initial release of the Format-Transforming Encryption (FTE) Proxy.
An AE scheme used with with the FTE proxy must have the following four properties.

- Stateless
- Randomized
- Provably secure
- Output of ``encrypt`` must be uniformly random

For more details about the scheme and its design, please see [missing reference].


:mod:`fte.encrypter` Module
***************************


.. automodule:: fte.encrypter
    :members:
    :undoc-members:


Examples
--------

In its simplest form, you can use the default keys to perform encryption.

.. code-block:: python

    >>> import fte.encrypter
    >>>
    >>> my_encrypter = fte.encrypter.Encrypter()
    >>> C = my_encrypter.encrypt('Hello, World!')
    >>> P = my_encrypter.decrypt(C)
    >>>
    >>> C.encode('hex')
    '6705f231c062cdc75d5f358c3131bfa03ddc6f0e3bbc2ccbef9f8af74d2f164fc9f7b97f2412c787ac1e9a0407'
    >>> print P
    'Hello, World!'

Next, because the AE scheme is randomized, notice that the same input will not produce the same output.
Two invocations of ``fte.encrypter.encrypt`` on the same string ``"Hello, World!`` will result in
two completely different ciphertexts.
    
.. code-block:: python

    >>> import fte.encrypter
    >>>
    >>> my_encrypter = fte.encrypter.Encrypter()
    >>> C = my_encrypter.encrypt('Hello, World!')
    >>> C.encode('hex')
    '37df241180b90785a203f66c0c651866de7008cf92f4bb37448a45b9c5b2eaee5575b6423d4e455fcec7387328'
    >>> C = my_encrypter.encrypt('Hello, World!')
    >>> C.encode('hex')
    'b369b9eb369260154ca687eba71c7c188af56579bb8b3ac4f6aee646cab1e4aaf51928a18321805ea1cdfd3227'
    
If you do wish to supply your own keys, you can may specify ``K1`` and/or ``K1`` in the construction of ``fte.encrypter.Encrypter``.
    
.. code-block:: python

    >>> import fte.encrypter
    >>> import fte.bit_ops
    >>> 
    >>> K1 = fte.bit_ops.random_bytes(16)
    >>> K2 = fte.bit_ops.random_bytes(16)
    >>> my_encrypter = fte.encrypter.Encrypter(K1, K2)
    >>>
    >>> K1.encode('hex')
    '23c5ae56db7c94e973ff10d9150293f3'
    >>> 
    >>> C = my_encrypter.encrypt('Hello, World!')
    >>> C.encode('hex')
    '211b49ce34dc06f4284c1229dc281993c453f2b84dfad61479c5c2faf372b1ba0bdd7a5a55c9849079d152c036'
    
