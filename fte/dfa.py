#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.


import copy
import math

import fte.automata
import fte.cDFA


class LanguageIsEmptySetException(Exception):

    """Raised when the input language results in a set that is not rankable.
    """
    pass


class IntegerOutOfRangeException(Exception):
    pass


class DFA(object):

    def __init__(self, cDFA, max_len):
        self._cDFA = cDFA
        self.max_len = max_len

        self._words_in_language = self._cDFA.getNumWordsInLanguage(
            0, self.max_len)
        self._words_in_slice = self._cDFA.getNumWordsInLanguage(
            self.max_len, self.max_len)

        self._offset = self._words_in_language - self._words_in_slice

        if self._words_in_slice == 0:
            raise LanguageIsEmptySetException()

        self._capacity = int(math.floor(math.log(self._words_in_slice, 2)))-1

    def rank(self, X):
        """Given a string ``X`` return ``c``, where ``c`` is the lexicographical
        rank of ``X`` in the language of all strings of length ``max_len``
        generated by ``regex``.
        """

        return self._cDFA.rank(X)

    def unrank(self, c):
        """The inverse of ``rank``.
        """

        return self._cDFA.unrank(c)

    def getCapacity(self):
        """Returns the size, in bits, of the language of our input ``regex``.
        Calculated as the floor of log (base 2) of the cardinality of the set of
        strings up to length ``max_len`` in the language generated by the input
        ``regex``.
        """

        return self._capacity

    def getNumWordsInSlice(self, n):
        """Returns the number of words in the language of length ``n``"""
        return self._cDFA.getNumWordsInLanguage(n, n)


def _attFstFromRegex(regex):
    """Inputs a perl-compatible regular expression and outputs a minimized AT&T-formatted finite state transducer"""

    att_fst = fte.cDFA.attFstFromRegex(str(regex))
    att_fst = att_fst.strip()

    return att_fst


def _attFstMinimize(att_fst):
    """On input of an AT&T-formatted finite-state transducer, returns a transducer that accepts the same languge with the minimal amount of states."""

    automata = _attFstToFTEAutomata(att_fst)
    automata.minimize()
    retval = _FTEAutomataToAttFst(automata)

    return retval


def _attFstToFTEAutomata(att_fst):
    """On input of an AT&T-formatted finite-state transducer, returns an ``fte.automata.DFA`` that accepts the same language.
    All state names in the input transducer are assumed to be non-negative integers."""

    att_fst = att_fst.strip()

    states = set()
    alphabet = set()
    delta = {}
    start = att_fst.split('\n')[0].split(' ')[0]
    accepts = set()

    DEAD_STATE = '-1'

    # read the input string, set states, alphabet and accepts
    for line in att_fst.split('\n'):
        bits = line.split(' ')
        if len(bits) == 4:
            src_state = bits[0]
            dst_state = bits[1]
            symbol = bits[2]
            states.add(src_state)
            states.add(dst_state)
            alphabet.add(symbol)
        elif len(bits) == 1:
            src_state = bits[0]
            states.add(src_state)
            accepts.add(src_state)
        else:
            assert False

    # add our DEAD_STATE as a state in the DFA
    assert DEAD_STATE not in states, "Sorry '-1' is a reserved state name."
    states.add(DEAD_STATE)

    # fill out our transition function delta, initialize all transitions to
    # the DEAD_STATE
    for state in states:
        delta[state] = {}
        for symbol in alphabet:
            delta[state][symbol] = DEAD_STATE

    # iterate through our FST again and fill out our delta function
    for line in att_fst.split('\n'):
        bits = line.split(' ')
        if len(bits) == 4:
            src_state = bits[0]
            dst_state = bits[1]
            symbol = bits[2]
            delta[src_state][symbol] = dst_state

    new_delta = lambda x, y: delta[x][y]

    dfa = fte.automata.DFA(states, alphabet, new_delta, start, accepts)

    return dfa


def _FTEAutomataToAttFst(dfa):
    """On input of an ``fte.automata.DFA``, returns an AT&T-formatted finite-state transducer that accepts the same language."""

    stateMappingTable = []

    def state_allocator(state):
        if isDeadState(dfa, state):
            retval = str(len(dfa.states))
        else:
            if state not in stateMappingTable:
                stateMappingTable.append(state)
            retval = str(stateMappingTable.index(state))
        return retval

    def isDeadState(dfa, state):
        """A state is dead if it is not in accepting and is a self-loop."""
        notInAccepts = state not in dfa.accepts
        selfLoop = True
        for symbol in dfa.alphabet:
            if dfa.delta(state, symbol) != state:
                selfLoop = False
                break
        return notInAccepts and selfLoop

    alphabet = copy.deepcopy(dfa.alphabet)
    alphabet = list(alphabet)
    alphabet.sort(key=lambda x: int(x))

    att_fst = ''
    processed_states = []
    working_states = [dfa.start]
    while len(working_states) > 0:
        current_state = working_states.pop(0)
        for symbol in alphabet:
            dst_state = dfa.delta(current_state, symbol)

            # add new states that we haven't seen before to our working_states
            # set
            dstNotInWorking = dst_state not in working_states
            dstNotInProcessed = dst_state not in processed_states
            dstNotCurrent = (dst_state != current_state)
            if dstNotInWorking and dstNotInProcessed and dstNotCurrent:
                working_states.append(dst_state)

            # don't print transitions to/from dead states
            srcIsDead = isDeadState(dfa, current_state)
            dstIsDead = isDeadState(dfa, dfa.delta(current_state, symbol))
            if srcIsDead or dstIsDead:
                continue

            # build up FST
            att_fst += '\n' + state_allocator(current_state)
            att_fst += '\t' + state_allocator(dst_state)
            att_fst += '\t' + symbol
            att_fst += '\t' + symbol

        # add our current state to our set of processed states
        processed_states.append(current_state)

        # print our current state if it is an accepting state
        if current_state in dfa.accepts:
            att_fst += '\n' + state_allocator(current_state)

    # ensure we have no leading/trailing whitespace
    att_fst = att_fst.strip()

    return att_fst


def from_regex(regex, max_len):
    """Given an input ``regex`` and integer ``max_len`` constructs an
    ``fte.dfa.DFA()`` object that can be used to ``(un)rank`` into the language
    generated by ``regex`` with strings of length ``max_len``.
    """

    regex = str(regex)
    max_len = int(max_len)

    att_fst = _attFstFromRegex(regex)
    att_fst = _attFstMinimize(att_fst)

    dfa = fte.cDFA.DFA(att_fst, max_len)
    retval = DFA(dfa, max_len)

    return retval
