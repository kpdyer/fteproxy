:mod:`fte.dfa` Module
***********************

Overview
--------

This is a class used internally by fteproxy and should not be invoked directly.

Interface
---------

.. automodule:: fte.dfa
    :members:
    :undoc-members:
    :show-inheritance:

Examples
--------

.. code-block:: python

    >>> import fte.dfa
    >>> dfaObj = fte.dfa.from_regex('^(A|B)+$',16)
    >>> dfaObj.unrank(0)
    'AAAAAAAAAAAAAAAA'
    >>> dfaObj.rank('AAAAAAAAAAAAAAAA')
    0

.. code-block:: python

    >>> import fte.dfa
    >>> dfaObj = fte.dfa.from_regex('^(0|1)+$', 16)
    >>> dfaObj.unrank(2**16 - 1)
    '1111111111111111'
    >>> dfaObj.rank('1111111111111111')
    65535
