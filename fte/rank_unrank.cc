// This file is part of fteproxy.
//
// fteproxy is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// fteproxy is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

#include <rank_unrank.h>

#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/prog.h"


/*
 * Please see rank_unrank.h for a detailed explantion of the
 * methods in this file and their purpose.
 */


// Helper fuction. Given a string and a token, performs a python .split()
// Returns a list of string delimnated on the token
array_type_string_t1 tokenize( std::string line, char delim ) {
    array_type_string_t1 retval;

    std::istringstream iss(line);
    std::string fragment;
    while(std::getline(iss, fragment, delim))
        retval.push_back(fragment);

    return retval;
}

// Exceptions
static class _invalid_fst_exception_state_name: public std::exception
{
    virtual const char* what() const throw()
    {
        return "Invalid DFA format: DFA has N states, and a state that is not in the range 0,1,...,N-1.";
    }
} invalid_fst_exception_state_name;

static class _invalid_fst_exception_symbol_name: public std::exception
{
    virtual const char* what() const throw()
    {
        return "Invalid DFA format: DFA has symbol that is not in the range 0,1,...,255.";
    }
} invalid_fst_exception_symbol_name;


/*
 * Parameters:
 *   dfa_str: a minimized ATT FST formatted DFA, see: http://www2.research.att.com/~fsmtools/fsm/man4/fsm.5.html
 *   max_len: the maxium length to compute DFA::buildTable
 */
DFA::DFA(const std::string dfa_str, const uint32_t max_len)
    : _fixed_slice(max_len),
      _start_state(0),
      _num_states(0),
      _num_symbols(0)
{
    // construct the _start_state, _final_states and symbols/states of our DFA
    bool startStateIsntSet = true;
    std::string line;
    std::istringstream my_str_stream(dfa_str);
    while ( getline (my_str_stream,line) )
    {
        if (line.empty()) break;

        array_type_string_t1 split_vec = tokenize( line, '\t' );
        if (split_vec.size() == 4) {
            uint32_t current_state = strtol(split_vec.at(0).c_str(),NULL,10);
            uint32_t symbol = strtol(split_vec.at(2).c_str(),NULL,10);
            if (find(_states.begin(), _states.end(), current_state)==_states.end()) {
                _states.push_back( current_state );
            }

            if (find(_symbols.begin(), _symbols.end(), symbol)==_symbols.end()) {
                _symbols.push_back( symbol );
            }

            if ( startStateIsntSet ) {
                _start_state = current_state;
                startStateIsntSet = false;
            }
        } else if (split_vec.size()==1) {
            uint32_t final_state = strtol(split_vec.at(0).c_str(),NULL,10);
            if (find(_final_states.begin(), _final_states.end(), final_state)==_final_states.end()) {
                _final_states.push_back( final_state );
            }
            if (find(_states.begin(), _states.end(), final_state)==_states.end()) {
                _states.push_back( final_state );
            }
        } else {
            // TODO: throw exception because we don't understand the file format
        }

    }
    _states.push_back( _states.size() ); // extra for the "dead" state

    _num_symbols = _symbols.size();
    _num_states = _states.size();

    // build up our sigma/sigma_reverse tables which enable mappings between
    // bytes/integers
    uint32_t j, k;
    for (j=0; j<_num_symbols; j++) {
        _sigma.insert( std::pair<uint32_t,char>( j, (char)(_symbols.at(j))) );
        _sigma_reverse.insert( std::pair<char,uint32_t>((char)(_symbols.at(j)), j) );
    }

    // intialize all transitions in our DFA to our dead state
    _delta.resize(_num_states);
    for (j=0; j<_num_states; j++) {
        _delta.at(j).resize(_num_symbols);
        for (k=0; k < _num_symbols; k++) {
            _delta.at(j).at(k) = _num_states - 1;
        }
    }

    // fill our our transition function delta
    std::istringstream my_str_stream2(dfa_str);
    while ( getline (my_str_stream2,line) )
    {
        array_type_string_t1 split_vec = tokenize( line, '\t' );
        if (split_vec.size() == 4) {
            uint32_t current_state = strtol(split_vec.at(0).c_str(),NULL,10);
            uint32_t symbol = strtol(split_vec.at(2).c_str(),NULL,10);
            uint32_t new_state = strtol(split_vec.at(1).c_str(),NULL,10);

            symbol = _sigma_reverse.at(symbol);

            _delta.at(current_state).at(symbol) = new_state;
        }
    }

    _delta_dense.resize(_num_states);
    uint32_t q, a;
    for (q=0; q < _num_states; q++ ) {
        _delta_dense.at(q) = true;
        for (a=1; a < _num_symbols; a++) {
            if (_delta.at(q).at(a-1) != _delta.at(q).at(a)) {
                _delta_dense.at(q) = false;
                break;
            }
        }
    }

    DFA::_validate();

    // perform our precalculation to speed up (un)ranking
    DFA::_buildTable();
}


void DFA::_validate() {
    // TODO: ensure DFA has at least one state
    // TODO: ensure DFA has at least one symbol

    // ensure we have N states, labeled 0,1,..N-1
    array_type_uint32_t1::iterator state;
    for (state=_states.begin(); state!=_states.end(); state++) {
        if (*state >= _states.size()) {
            throw invalid_fst_exception_state_name;
        }
    }

    // ensure all symbols are in the range 0,1,...,255
    for (uint32_t i = 0; i < _symbols.size(); i++) {
        if (_symbols.at(i) > 256 || _symbols.at(i) < 0) {
            throw invalid_fst_exception_symbol_name;
        }
    }
}

void DFA::_buildTable() {
    uint32_t i;
    uint32_t q;
    uint32_t a;

    // ensure our table _T is the correct size
    _T.resize(_num_states);
    for (q=0; q<_num_states; q++) {
        _T.at(q).resize(_fixed_slice+1);
        for (i=0; i<=_fixed_slice; i++) {
            _T.at(q).at(i) = 0;
        }
    }

    // set all _T.at(q).at(0) = 1 for all states in _final_states
    array_type_uint32_t1::iterator state;
    for (state=_final_states.begin(); state!=_final_states.end(); state++) {
        _T.at(*state).at(0) = 1;
    }

    // walk through our table _T
    // we want each entry _T.at(q).at(i) to contain the number of strings that start
    // from state q, terminate in a final state, and are of length i
    for (i=1; i<=_fixed_slice; i++) {
        for (q=0; q<_delta.size(); q++) {
            for (a=0; a<_delta.at(0).size(); a++) {
                uint32_t state = _delta.at(q).at(a);
                _T.at(q).at(i) += _T.at(state).at(i-1);
            }
        }
    }
}


std::string DFA::unrank( const mpz_class c_in ) {
    // TODO: throw exception if input integer is not in range of pre-computed
    //       values
    // TODO: throw exception if walking DFA does not end in a final state

    std::string retval;

    mpz_class c = c_in;

    // subtract values values from c, while increasing n, to determine
    // the length n of the string we're ranking
    uint32_t n = _fixed_slice;

    // walk the DFA subtracting values from c until we have our n symbols
    uint32_t i, q = _start_state;
    uint32_t chars_left, char_cursor, state_cursor;
    uint32_t sigma_zero = _sigma.at(0);
    mpz_class char_index;
    for (i=1; i<=n; i++) {
        chars_left = n-i;
        if (_delta_dense.at(q)) {
            q = _delta.at(q).at(0);
            if (_T.at(q).at(chars_left)!=0) {
                char_index = (c / _T.at(q).at(chars_left));
                char_cursor = char_index.get_ui();
                retval = retval + _sigma.at(char_cursor);
                c = c % _T.at(q).at(chars_left);
            } else {
                retval += sigma_zero;
            }
        } else {
            char_cursor = 0;
            state_cursor = _delta.at(q).at(char_cursor);
            while (c >= _T.at(state_cursor).at(chars_left)) {
                c -= _T.at(state_cursor).at(chars_left);
                char_cursor += 1;
                state_cursor =_delta.at(q).at(char_cursor);
            }
            retval += _sigma.at(char_cursor);
            q = state_cursor;
        }
    }

    return retval;
}

mpz_class DFA::rank( const std::string X_in ) {
    // TODO: verify that input symbols are in alphabet of DFA
    // TODO: verify len(X) == _fixed_slice

    mpz_class retval = 0;

    // walk the DFA, adding values from T to c
    uint32_t i, j;
    uint32_t n = X_in.size();
    uint32_t q = _start_state;
    uint32_t state;
    uint32_t symbol_as_int;
    for (i=1; i<=n; i++) {
        symbol_as_int = _sigma_reverse.at(X_in.at(i-1));
        if (_delta_dense.at(q)) {
            state = _delta.at(q).at(0);
            retval += (_T.at(state).at(n-i) * symbol_as_int);
        } else {
            for (j=1; j<=symbol_as_int; j++) {
                state = _delta.at(q).at(j-1);
                retval += _T.at(state).at(n-i);
            }
        }
        q = _delta.at(q).at(symbol_as_int);
    }

    // TODO: bail if our final state q is not in _final_states

    return retval;
}

mpz_class DFA::getNumWordsInLanguage( const uint32_t min_word_length,
                                      const uint32_t max_word_length )
{
    // TODO: verify min_word_length <= max_word_length <= _fixed_slice

    // count the number of words in the language of length
    // at least min_word_length and no greater than max_word_length
    mpz_class num_words = 0;
    for (uint32_t word_length = min_word_length;
            word_length <= max_word_length;
            word_length++) {
        num_words += _T.at(_start_state).at(word_length);
    }
    return num_words;
}

std::string attFstFromRegex( const std::string regex )
{
    // TODO: Throw exception if DFA is not generated correctly (how do we determine this case?)
    // TODO: Identify when DFA has >N states, then throw exception

    std::string retval;

    // specify compile flags for re2
    re2::Regexp::ParseFlags re_flags;
    re_flags = re2::Regexp::ClassNL;
    re_flags = re_flags | re2::Regexp::OneLine;
    re_flags = re_flags | re2::Regexp::PerlClasses;
    re_flags = re_flags | re2::Regexp::PerlB;
    re_flags = re_flags | re2::Regexp::PerlX;
    re_flags = re_flags | re2::Regexp::Latin1;

    re2::RegexpStatus status;

    // compile regex to DFA
    re2::Regexp* re = NULL;
    re2::Prog* prog = NULL;

    try {
        RE2::Options opt;
        re2::Regexp* re = re2::Regexp::Parse( regex, re_flags, &status );
        re2::Prog* prog = re->CompileToProg( opt.max_mem() );
        retval = prog->PrintEntireDFA( re2::Prog::kFullMatch );
    } catch (int e) {
        // do nothing, we return the empty string
    }

    // cleanup
    if (prog!=NULL)
        delete prog;
    if (re!=NULL)
        re->Decref();

    return retval;
}
