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
#include <vector>
#include <unordered_set>

#include <gmpxx.h>

typedef std::vector<char> array_type_char_t1;
typedef std::vector<bool> array_type_bool_t1;
typedef std::vector<uint16_t> array_type_uint16_t1;
typedef std::unordered_set<uint16_t> unordered_set_uint16_t1;
typedef std::vector< std::vector<uint16_t> > array_type_uint16_t2;
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

class DFA {
private:
    // the maximum value for which buildTable is computed
    uint16_t _max_len;

    // the integer of our DFA start state
    int32_t _start_state;

    uint16_t _num_states;
    uint16_t _num_symbols;

    // our mapping between integers and the symbols in our alphabet; ints -> chars
    std::map<uint16_t, char> _sigma;

    // the reverse mapping of sigma, chars -> ints
    std::map<char, uint16_t> _sigma_reverse;

    // our transitions table
    array_type_uint16_t2 _delta;

    // a lookup table used for performance gain
    // for each state we detect if all outgoing transitions are to the same state
    array_type_bool_t1 _delta_dense;

    // the set of final states in our DFA
    unordered_set_uint16_t1 _final_states;

    // buildTable builds a mapping from [q, i] -> n
    //   q: a state in our DFA
    //   i: an integer
    //   n: the number of words in our language that have a path to a final
    //      state that is exactly length i
    void _buildTable();

    // _T is our cached table, the output of buildTable
    array_type_mpz_t2 _T;
public:
    DFA(std::string, uint16_t);

    // our unrank function an int -> str mapping
    // given an integer i, return the ith lexicographically ordered string in
    // the language accepted by the DFA
    std::string unrank( const mpz_class );

    // our rank function performs the inverse operation of unrank
    // we have the output PyObject as an input for performance
    mpz_class rank( const std::string );

    // given integers [n,m] returns the number of words accepted by the
    // DFA that are at least length n and no greater than length m
    mpz_class getNumWordsInLanguage( const uint16_t, const uint16_t );
};

// given an input perl-compatiable regular-expression
// returns an ATT FST formatted DFA
static std::string attFstFromRegex( const std::string );
