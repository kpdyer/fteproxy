=====
pyre2
=====

.. contents::

Summary
=======

pyre2 is a Python extension that wraps
`Google's RE2 regular expression library
<http://code.google.com/p/re2/>`_.

This version of pyre2 is similar to the one you'd
find at `facebook's github repository <http://github.com/facebook/pyre2/>`_
except that the stated goal of this version is to be a *drop-in replacement* for
the ``re`` module.

Backwards Compatibility
=======================

The stated goal of this module is to be a drop-in replacement for ``re``. 
My hope is that some will be able to go to the top of their module and put::

    try:
        import re2 as re
    except ImportError:
        import re

That being said, there are features of the ``re`` module that this module may
never have. For example, ``RE2`` does not handle lookahead assertions (``(?=...)``).
For this reason, the module will automatically fall back to the original ``re`` module
if there is a regex that it cannot handle.

However, there are times when you may want to be notified of a failover. For this reason,
I'm adding the single function ``set_fallback_notification`` to the module.
Thus, you can write::

    try:
        import re2 as re
    except ImportError:
        import re
    else:
	re.set_fallback_notification(re.FALLBACK_WARNING)

And in the above example, ``set_fallback_notification`` can handle 3 values:
``re.FALLBACK_QUIETLY`` (default), ``re.FALLBACK_WARNING`` (raises a warning), and
``re.FALLBACK_EXCEPTION`` (which raises an exception).

**Note**: The re2 module treats byte strings as UTF-8. This is fully backwards compatible with 7-bit ascii.
However, bytes containing values larger than 0x7f are going to be treated very differently in re2 than in re.
The RE library quietly ignores invalid utf8 in input strings, and throws an exception on invalid utf8 in patterns.
For example:

    >>> re.findall(r'.', '\x80\x81\x82')
    ['\x80', '\x81', '\x82']
    >>> re2.findall(r'.', '\x80\x81\x82')
    []

If you require the use of regular expressions over an arbitrary stream of bytes, then this library might not be for you.

Installation
============

To install, you must first install the prerequisites:

* The `re2 library from Google <http://code.google.com/p/re2/>`_
* The Python development headers (e.g. *sudo apt-get install python-dev*)
* A build environment with ``g++`` (e.g. *sudo apt-get install build-essential*)

After the prerequisites are installed, you can try installing using ``easy_install``::

    $ sudo easy_install re2

if you have setuptools installed (or use ``pip``).

If you don't want to use ``setuptools``, you can alternatively download the tarball from `pypi <http://pypi.python.org/pypi/re2/>`_.

Alternative to those, you can clone this repository and try installing it from there. To do this, run::

    $ git clone git://github.com/axiak/pyre2.git
    $ cd pyre2.git
    $ sudo python setup.py install

If you want to make changes to the bindings, you must have Cython >=0.13.

Unicode Support
===============

One current issue is Unicode support. As you may know, ``RE2`` supports UTF8,
which is certainly distinct from unicode. Right now the module will automatically
encode any unicode string into utf8 for you, which is *slow* (it also has to
decode utf8 strings back into unicode objects on every substitution or split).
Therefore, you are better off using bytestrings in utf8 while working with RE2
and encoding things after everything you need done is finished.

Performance
===========

Performance is of course the point of this module, so it better perform well.
Regular expressions vary widely in complexity, and the salient feature of ``RE2`` is
that it behaves well asymptotically. This being said, for very simple substitutions,
I've found that occasionally python's regular ``re`` module is actually slightly faster.
However, when the ``re`` module gets slow, it gets *really* slow, while this module
buzzes along.

In the below example, I'm running the data against 8MB of text from the collosal Wikipedia
XML file. I'm running them multiple times, being careful to use the ``timeit`` module.
To see more details, please see the `performance script <http://github.com/axiak/pyre2/tree/master/tests/performance.py>`_.

+-----------------+---------------------------------------------------------------------------+------------+--------------+---------------+-------------+-----------------+----------------+
|Test             |Description                                                                |# total runs|``re`` time(s)|``re2`` time(s)|% ``re`` time|``regex`` time(s)|% ``regex`` time|
+=================+===========================================================================+============+==============+===============+=============+=================+================+
|Findall URI|Email|Find list of '([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)'|2           |19.961        |0.336          |1.68%        |11.463           |2.93%           |
+-----------------+---------------------------------------------------------------------------+------------+--------------+---------------+-------------+-----------------+----------------+
|Replace WikiLinks|This test replaces links of the form [[Obama|Barack_Obama]] to Obama.      |100         |16.032        |2.622          |16.35%       |2.895            |90.54%          |
+-----------------+---------------------------------------------------------------------------+------------+--------------+---------------+-------------+-----------------+----------------+
|Remove WikiLinks |This test splits the data by the <page> tag.                               |100         |15.983        |1.406          |8.80%        |2.252            |62.43%          |
+-----------------+---------------------------------------------------------------------------+------------+--------------+---------------+-------------+-----------------+----------------+

Feel free to add more speed tests to the bottom of the script and send a pull request my way!

Current Status
==============

pyre2 has only received basic testing. Please use it
and let me know if you run into any issues!

Contact
=======

You can file bug reports on GitHub, or contact the author:
`Mike Axiak  contact page <http://mike.axiak.net/contact>`_.

Tests
=====

If you would like to help, one thing that would be very useful
is writing comprehensive tests for this. It's actually really easy:

* Come up with regular expression problems using the regular python 're' module.
* Write a session in python traceback format `Example <http://github.com/axiak/pyre2/blob/master/tests/search.txt>`_.
* Replace your ``import re`` with ``import re2 as re``.
* Save it as a .txt file in the tests directory. You can comment on it however you like and indent the code with 4 spaces.

Missing Features
================

Currently the features missing are:

* If you use substitution methods without a callback, a non 0/1 maxsplit argument is not supported.


Credits
=======

Though I ripped out the code, I'd like to thank David Reiss
and Facebook for the initial inspiration. Plus, I got to
gut this readme file!

Moreover, this library would of course not be possible if not for
the immense work of the team at RE2 and the few people who work
on Cython.
