# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python
# -*- coding: utf-8 -*-
from sets import Set
import random
import fte.conf


class DeadStateException(Exception):

    pass


class DummyModel(object):

    def __init__(self, language):
        self.language = language

    def transition(self):
        return '000'

    def getState(self):
        return '000'

    def isAlive(self):
        return True

    def reset(self):
        pass


class MarkovModel(object):

    def __init__(self, language, exceptionOnDeath=True):
        self.language = language
        self.exceptionOnDeath = exceptionOnDeath
        self.seed = 0
        self.rnd = random.Random(self.seed)
        self.loadMarkovMode(language)

    def loadMarkovMode(self, language):
        markov_model = fte.conf.getValue('formats.' + language
                                         + '.markov_file')
        f = open(markov_model)
        contents = f.read()
        f.close()
        lines = contents.split('\n')
        self.starting_state = str(lines[0])
        self.state = self.starting_state
        self.model = {}
        self.states = []
        for line in lines[1:]:
            if not line:
                continue
            transition = line.split(' ')
            stateA = str(transition[0])
            stateB = str(transition[1])
            prob = float(transition[2])
            if not self.model.get(stateA):
                self.model[stateA] = {}
            self.model[stateA][stateB] = prob
            self.states.append(stateA)
            self.states.append(stateB)
        self.states = list(Set(self.states))

    def transition(self):
        if self.isAlive():
            if self.state != None:
                dart = self.rnd.random()
                sum = 0
                for key in self.model[self.state].keys():
                    sum += self.model[self.state][key]
                    if sum >= dart:
                        self.state = key
                        break
            else:
                self.state = self.starting_state
        if not self.isAlive():
            raise DeadStateException('Can\'t recover: dead state')
        return self.state

    def reset(self):
        self.state = self.starting_state

    def isAlive(self):
        return self.state != 'END'


class CompoundMarkovModel(object):

    def __init__(
        self,
        languageA,
        languageB,
        exceptionOnDeath=True,
    ):
        self.mmA = MarkovModel(languageA, exceptionOnDeath)
        if languageB == 'dummy':
            self.mmB = DummyModel(languageB)
        else:
            self.mmB = MarkovModel(languageB, exceptionOnDeath)

    def transition(self):
        return [self.mmA.transition(), self.mmB.transition()]

    def isAlive(self):
        return self.mmA.isAlive() and self.mmB.isAlive()

    def reset(self):
        self.mmA.reset()
        self.mmB.reset()