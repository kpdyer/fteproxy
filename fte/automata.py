# Updated by Kevin P. Dyer 2013-12-07
# for use with fteproxy

# Original banner:
#  python-automata, the Python DFA library
#  License: New BSD License
#  Author: Andrew Badr
#  Version: July 17, 2008
#  Contact: andrewbadr@gmail.com
#  Code contributions are welcome.


class DFA:

    """This class represents a deterministic finite automaton."""

    def __init__(self, states, alphabet, delta, start, accepts):
        """The inputs to the class are as follows:
         - states: An iterable containing the states of the DFA. States must be immutable.
         - alphabet: An iterable containing the symbols in the DFA's alphabet. Symbols must be immutable.
         - delta: A complete function from [states]x[alphabets]->[states].
         - start: The state at which the DFA begins operation.
         - accepts: A list containing the "accepting" or "final" states of the DFA.

        Making delta a function rather than a transition table makes it much easier to define certain DFAs. 
        If you want to use a transition table, you can just do this:
         delta = lambda q,c: transition_table[q][c]
        One caveat is that the function should not depend on the value of 'states' or 'accepts', since
        these may be modified during minimization.

        Finally, the names of states and inputs should be hashable. This generally means strings, numbers,
        or tuples of hashables.
        """
        self.states = set(states)
        self.start = start
        self.delta = delta
        self.accepts = set(accepts)
        self.alphabet = set(alphabet)
        self.current_state = start

#
# Minimization methods and their helper functions
#
    def state_hash(self, value):
        """Creates a hash with one key for every state in the DFA, and
        all values initialized to the 'value' passed.
        """
        d = {}
        for state in self.states:
            if callable(value):
                d[state] = value()
            else:
                d[state] = value
        return d

    def reachable_from(self, q0, inclusive=True):
        """Returns the set of states reachable from given state q0. The optional
        parameter "inclusive" indicates that q0 should always be included.
        """
        reached = self.state_hash(False)
        if inclusive:
            reached[q0] = True
        to_process = [q0]
        while len(to_process):
            q = to_process.pop()
            for c in self.alphabet:
                next = self.delta(q, c)
                if reached[next] == False:
                    reached[next] = True
                    to_process.append(next)
        return filter(lambda q: reached[q], self.states)

    def reachable(self):
        """Returns the reachable subset of the DFA's states."""
        return self.reachable_from(self.start)

    def delete_unreachable(self):
        """Deletes all the unreachable states."""
        reachable = self.reachable()
        self.states = reachable
        new_accepts = []
        for q in self.accepts:
            if q in self.states:
                new_accepts.append(q)
        self.accepts = new_accepts

    def mn_classes(self):
        """Returns a partition of self.states into Myhill-Nerode equivalence classes."""
        changed = True
        classes = []
        if self.accepts != []:
            classes.append(self.accepts)
        nonaccepts = filter(lambda x: x not in self.accepts, self.states)
        if nonaccepts != []:
            classes.append(nonaccepts)
        while changed:
            changed = False
            for cl in classes:
                local_change = False
                for alpha in self.alphabet:
                    next_class = None
                    new_class = []
                    for state in cl:
                        next = self.delta(state, alpha)
                        if next_class == None:
                            for c in classes:
                                if next in c:
                                    next_class = c
                        elif next not in next_class:
                            new_class.append(state)
                            changed = True
                            local_change = True
                    if local_change == True:
                        old_class = []
                        for c in cl:
                            if c not in new_class:
                                old_class.append(c)
                        classes.remove(cl)
                        classes.append(old_class)
                        classes.append(new_class)
                        break
        return classes

    def collapse(self, partition):
        """Given a partition of the DFA's states into equivalence classes,
        collapses every equivalence class into a single "representative" state.
        Returns the hash mapping each old state to its new representative.
        """
        new_states = []
        new_start = None
        new_delta = None
        new_accepts = []
        # alphabet stays the same
        new_current_state = None
        state_map = {}
        # build new_states, new_start, new_current_state:
        for state_class in partition:
            representative = state_class[0]
            new_states.append(representative)
            for state in state_class:
                state_map[state] = representative
                if state == self.start:
                    new_start = representative
                if state == self.current_state:
                    new_current_state = representative
        # build new_accepts:
        for acc in self.accepts:
            if acc in new_states:
                new_accepts.append(acc)
        # build new_delta:
        transitions = {}
        for state in new_states:
            transitions[state] = {}
            for alpha in self.alphabet:
                transitions[state][alpha] = state_map[self.delta(state, alpha)]
        new_delta = (lambda s, a: transitions[s][a])
        self.states = new_states
        self.start = new_start
        self.delta = new_delta
        self.accepts = new_accepts
        self.current_state = new_current_state
        return state_map

    def minimize(self):
        """Classical DFA minimization, using the simple O(n^2) algorithm.
        Side effect: can mix up the internal ordering of states.
        """
        # Step 1: Delete unreachable states
        self.delete_unreachable()
        # Step 2: Partition the states into equivalence classes
        classes = self.mn_classes()
        # Step 3: Construct the new DFA
        self.collapse(classes)
