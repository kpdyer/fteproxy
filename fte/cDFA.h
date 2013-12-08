// This file is part of FTE.
//
// FTE is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// FTE is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#include <Python.h>
#include <structmember.h>

#include <map>
#include <unordered_set>

#include <gmpxx.h>

typedef std::vector<char> array_type_char_t1;
typedef std::vector<bool> array_type_bool_t1;
typedef std::vector<uint32_t> array_type_uint32_t1;
typedef std::vector< std::vector<uint32_t> > array_type_uint32_t2;
typedef std::vector< std::vector<mpz_class> > array_type_mpz_t2;
typedef std::vector< std::string > array_type_string_t1;

// copied from gmpy
// allows us to use gmp.mpz objects in python for input to our unrank function
typedef long Py_hash_t;
typedef struct {
    PyObject_HEAD
    mpz_t z;
    Py_hash_t hash_cache;
} PympzObject;
#define Pympz_AS_MPZ(obj) (((PympzObject *)(obj))->z)

// the initialization function for our fte.dfa module
void dfainit();

class DFA {
private:
    // the maximum value for which buildTable is computed
    uint32_t _max_len;

    // the integer of our DFA start state
    int32_t _start_state;

    uint32_t _num_states;
    uint32_t _num_symbols;

    // our mapping between integers and the symbols in our alphabet; ints -> chars
    std::map<uint32_t, char> _sigma;

    // the reverse mapping of sigma, chars -> ints
    std::map<char, uint32_t> _sigma_reverse;

    // our transitions table
    array_type_uint32_t2 _delta;

    // a lookup table used for performance gain
    // for each state we detect if all outgoing transitions are to the same state
    array_type_bool_t1 _delta_dense;

    // the set of final states in our DFA
    std::unordered_set<uint32_t> _final_states;

    // buildTable builds a mapping from [q, i] -> n
    //   q: a state in our DFA
    //   i: an integer
    //   n: the number of words in our language that have a path to a final
    //      state that is exactly length i
    void _buildTable();

    // _T is our cached table, the output of buildTable
    array_type_mpz_t2 _T;
public:
    DFA(std::string, uint32_t);

    // our unrank function an int -> str mapping
    // given an integer i, return the ith lexicographically ordered string in
    // the language accepted by the DFA
    std::string unrank( PyObject* );

    // our rank function performs the inverse operation of unrank
    // we have the output PyObject as an input for performance
    void rank( std::string, PyObject* );

    // given integers [n,m] returns the number of words accepted by the
    // DFA that are at least length n and no greater than length m
    PyObject* getNumWordsInLanguage( uint32_t, uint32_t );
};

// given an input perl-compatiable regular-expression
// returns an ATT FST formatted DFA
static PyObject * fte_cDFA_attFstFromRegex(PyObject*, PyObject*);
