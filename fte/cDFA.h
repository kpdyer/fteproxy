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

#include <gmpxx.h>
#include <map>

#include <boost/multi_array.hpp>
#include <boost/unordered_set.hpp>

typedef boost::multi_array<char, 1> array_type_char_t1;
typedef boost::multi_array<uint32_t, 1> array_type_uint32_t1;
typedef boost::multi_array<uint32_t, 2> array_type_uint32_t2;
typedef boost::multi_array<mpz_class, 2> array_type_mpz_t2;

typedef long Py_hash_t;
typedef struct {
    PyObject_HEAD
    mpz_t z;
    Py_hash_t hash_cache;
} PympzObject;
#define Pympz_AS_MPZ(obj) (((PympzObject *)(obj))->z)

void dfainit();

class DFA {
private:
    uint32_t _max_len = 0;
    int32_t _q0 = -1;
    std::map<uint32_t, char> _sigma;
    std::map<char, uint32_t> _sigma_reverse;
    array_type_uint32_t2 _delta;
    array_type_uint32_t1 _delta_dense;
    boost::unordered_set<uint32_t> _final_states;
    array_type_mpz_t2 _T;
    
    void doRank(mpz_t c,
                array_type_uint32_t1 X,
                const uint32_t q0,
                array_type_uint32_t2 delta,
                array_type_uint32_t1 delta_dense,
                array_type_mpz_t2 T);
    void doUnrank(array_type_uint32_t1 & X,
                  const mpz_t c,
                  const uint32_t q0,
                  array_type_uint32_t2 delta,
                  array_type_uint32_t1 delta_dense,
                  array_type_mpz_t2 T);
public:
    DFA(std::string DFA, uint32_t MAX_WORD_LEN);
    
    std::string unrank( PyObject* );
    void rank( PyObject*, std::string );
    
    uint32_t delta( uint32_t, uint32_t );
    
    PyObject* getNumWordsInLanguage();
    PyObject* getNumWordsInSlice( uint32_t );
};

std::string attFstFromRegex(std::string regex);
std::string attFstMinimize(std::string regex);
