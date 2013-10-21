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

void regexinit();

inline static std::string unrank( std::string DFA_ID, PyObject * c );
inline static void rank( std::string DFA_ID, PyObject * c, std::string X );
void releaseLanguage(std::string DFA_ID);
void loadLanguage(std::string DFA_DIR, std::string DFA_ID, uint32_t MAX_WORD_LEN);
inline static void getT( std::string DFA_ID, PyObject * c, uint32_t q, uint32_t i );
inline static uint32_t getSizeOfT( std::string DFA_ID );
inline static uint32_t delta( std::string DFA_ID, uint32_t q, uint32_t c );
inline static uint32_t getStart( std::string DFA_ID);
inline static uint32_t getNumStates( std::string DFA_ID);
