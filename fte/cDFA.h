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

#include <boost/assign/std/vector.hpp>
#include <boost/multi_array.hpp>
#include <boost/unordered_set.hpp>

typedef boost::multi_array<char, 1> array_type_char_t1;
typedef boost::multi_array<uint32_t, 1> array_type_uint32_t1;
typedef boost::multi_array<uint32_t, 2> array_type_uint32_t2;
typedef boost::multi_array<mpz_class, 2> array_type_mpz_t2;
typedef boost::const_multi_array_ref<uint32_t, 1> const_array_type_uint32_t1;
typedef boost::const_multi_array_ref<uint32_t, 2> const_array_type_uint32_t2;
typedef boost::const_multi_array_ref<mpz_class, 2> const_array_type_mpz_t2;
typedef std::map< mpz_class, std::vector<uint32_t> > map_type_str_vec;

void dfainit();

class DFA {
private:
    int32_t _q0 = -1;
    std::map<uint32_t, char> _sigma;
    std::map<char, uint32_t> _sigma_reverse;
    array_type_uint32_t2 _delta;
    array_type_uint32_t1 _delta_dense;
    boost::unordered_set<uint32_t> _final_states;
    array_type_mpz_t2 _T;
public:
    DFA(std::string DFA, uint32_t MAX_WORD_LEN);
    std::string unrank( PyObject * c );
    void rank( PyObject * c, std::string X );
    void getT( PyObject * c, uint32_t q, uint32_t i );
    uint32_t getSizeOfT();
    uint32_t delta(uint32_t q, uint32_t c );
    uint32_t getStart();
    uint32_t getNumStates();
    void doRank(mpz_t c,
                          array_type_uint32_t1 X,
                          const uint32_t q0,
                          const_array_type_uint32_t2 delta,
                          const_array_type_uint32_t1 delta_dense,
                          const_array_type_mpz_t2 T);
    void doUnrank(array_type_uint32_t1 & X,
                            const mpz_t c,
                            const uint32_t q0,
                            const_array_type_uint32_t2 delta,
                            const_array_type_uint32_t1 delta_dense,
                            const_array_type_mpz_t2 T);
};

std::string minimize(std::string regex);
std::string fromRegex(std::string regex);
