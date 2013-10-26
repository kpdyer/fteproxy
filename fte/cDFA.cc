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

#include <cDFA.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python/class.hpp>
#include <boost/algorithm/string.hpp>

#include "util/test.h"
#include "util/thread.h"
#include "re2/prog.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/testing/regexp_generator.h"
#include "re2/testing/string_generator.h"


DFA::DFA(std::string DFA, uint32_t MAX_WORD_LEN)
    : _max_len(MAX_WORD_LEN),
      _start_state(-1)
{
    std::vector<uint32_t> symbolsTmp;
    boost::unordered_set<uint32_t> statesTmp;
    boost::unordered_set<uint32_t> final_statesTmp;

    std::string line;
    std::istringstream myfile(DFA);
    while ( getline (myfile,line) )
    {
        if (line.empty()) break;

        typedef vector< std::string > split_vector_type;
        split_vector_type SplitVec;
        boost::split( SplitVec, line, boost::is_any_of("\t") );
        std::string bits = SplitVec[SplitVec.size()-1];

        if (SplitVec.size() == 4 || SplitVec.size()==5) {
            uint32_t current_state = strtol(SplitVec[0].c_str(),NULL,10);
            uint32_t symbol = strtol(SplitVec[2].c_str(),NULL,10);
            if (statesTmp.count(current_state)==0) {
                statesTmp.insert( current_state );
            }

            if (find(symbolsTmp.begin(), symbolsTmp.end(), symbol)==symbolsTmp.end()) {
                symbolsTmp.push_back( symbol );
            }

            if (_start_state==-1) {
                _start_state = current_state;
            }
        } else if (SplitVec.size()==1 || SplitVec.size()==2) {
            uint32_t final_state = strtol(SplitVec[0].c_str(),NULL,10);
            if (statesTmp.count(final_state)==0) {
                statesTmp.insert( final_state );
            }
            final_statesTmp.insert( final_state );
        }
    }

    _final_states = final_statesTmp;

    statesTmp.insert( statesTmp.size() );

    uint32_t j, k;

    const uint32_t NUM_STATES = statesTmp.size();
    const uint32_t NUM_SYMBOLS = symbolsTmp.size();

    statesTmp.clear();
    final_statesTmp.clear();

    array_type_uint32_t2 deltaTmp(boost::extents[NUM_STATES][NUM_SYMBOLS]);

    std::map<uint32_t, char> sigmaTmp;
    std::map<char,uint32_t> sigmaReverseTmp;
    for (j=0; j<NUM_SYMBOLS; j++) {
        sigmaTmp[j] = (char)(symbolsTmp[j]-1);
        sigmaReverseTmp[(char)(symbolsTmp[j]-1)] = j;
    }
    _sigma = sigmaTmp;
    _sigma_reverse = sigmaReverseTmp;

    for (j=0; j<NUM_STATES; j++) {
        for (k=0; k<NUM_SYMBOLS; k++) {
            deltaTmp[j][k] = NUM_STATES-1;
        }
    }

    std::istringstream myfile2(DFA);
    typedef std::vector< std::string > split_vector_type;

    while ( getline (myfile2,line) )
    {
        split_vector_type SplitVec;
        boost::split( SplitVec, line, boost::is_any_of("\t") );
        std::string bits = SplitVec[SplitVec.size()-1];

        if (SplitVec.size() > 2) {
            uint32_t current_state = strtol(SplitVec[0].c_str(),NULL,10);
            uint32_t symbol = strtol(SplitVec[2].c_str(),NULL,10);

            uint32_t i;
            for (i=0; i<symbolsTmp.size(); i++) {
                if(symbolsTmp[i]==symbol) {
                    symbol = i;
                    break;
                }
            }

            uint32_t new_state = strtol(SplitVec[1].c_str(),NULL,10);

            deltaTmp[current_state][symbol] = new_state;
        }
    }

    _delta.resize(boost::extents[NUM_STATES][NUM_SYMBOLS]);
    _delta = deltaTmp;

    array_type_mpz_t2 TTmp(boost::extents[NUM_STATES][MAX_WORD_LEN+1]);
    _T.resize(boost::extents[NUM_STATES][MAX_WORD_LEN+1]);
    DFA::buildTable();
}


void DFA::buildTable() {
    uint32_t i, q, a;
    uint32_t n = _max_len;

    boost::unordered_set<uint32_t>::iterator it;
    for (it=_final_states.begin(); it!=_final_states.end(); it++) {
        _T[*it][0] = 1;
    }

    mpz_t tmp;
    mpz_init(tmp);
    for (i=1; i<=n; i++) {
        for (q=0; q<_delta.size(); q++) {
            for (a=0; a<_delta[0].size(); a++) {
                if ( mpz_cmp_ui( _T[_delta[q][a]][i-1].get_mpz_t(), 0 ) > 0 )
                    _T[q][i] += _T[_delta[q][a]][i-1];
            }
        }
    }
    mpz_clear(tmp);

}


std::string DFA::unrank(PyObject * c_input ) {
    array_type_uint32_t1 Xtmp;

    mpz_t c;
    mpz_init_set(c, Pympz_AS_MPZ(c_input));
    //DFA::doUnrank(tmp, Pympz_AS_MPZ(c) );

    /////////////////////
    uint32_t q = _start_state;
    uint32_t n = 1;
    uint32_t i;
    uint32_t idx;
    const uint32_t *j;
    mpz_t cTmp;
    mpz_t jTmp;

    mpz_init(jTmp);
    mpz_init_set(cTmp,c);

    while ( mpz_cmp(cTmp, _T[_start_state][n].get_mpz_t()) >= 0 ) {
        mpz_sub( cTmp, cTmp, _T[_start_state][n].get_mpz_t() );
        n++;
    }

    Xtmp.resize(boost::extents[n]);

    for (i=1; i<=n; i++) {
        idx = n-i;
        j = &_delta[q][0];
        while (mpz_cmp( cTmp, _T[*j][idx].get_mpz_t() ) >= 0) {
            mpz_sub( cTmp, cTmp, _T[*j][idx].get_mpz_t() );
            j += 1;
        }
        Xtmp[i-1] = j - &_delta[q][0];
        q = *j;
    }

    mpz_clear(cTmp);
    mpz_clear(jTmp);

    if (_final_states.count(q)==0) {
        Xtmp.resize(boost::extents[0]);
        return NULL;
    }
    /////////////////////

    //uint32_t i;
    std::string X;
    for (i=0; i<Xtmp.size(); i++) {
        X += _sigma[Xtmp[i]];
    }

    return X;
}

PyObject* DFA::rank( std::string X_input ) {
    uint32_t i;
    mpz_t c;
    uint32_t q = _start_state;
    uint32_t j;
    array_type_uint32_t1 X(boost::extents[X_input.size()]);
    mpz_t tmp;

    for (i=0; i<X_input.size(); i++) {
        X[i] = _sigma_reverse[X_input.at(i)];
    }

    uint32_t n = X.size();
    mpz_init(c);

    /////////////////////////////
    if (_T[0].size() < X.size()) {
        mpz_set_si( c, -1 );
        return NULL;
    }

    mpz_init(tmp);

    mpz_init_set_si( c, 0 );

    for (i=1; i<=n; i++) {
        for (j=1; j<=X[i-1]; j++) {
            mpz_add( c, c, _T[_delta[q][j-1]][n-i].get_mpz_t() );
        }
        q = _delta[q][X[i-1]];

        if (q == (_delta.size()-1)) {
            mpz_set_si( c, -1 );
            return NULL;
        }
    }

    mpz_clear(tmp);

    if (_final_states.count(q)==0) {
        mpz_set_si( c, -1 );
        return NULL;
    }

    for (i=0; i<n; i++)
        mpz_add( c, c, _T[_start_state][i].get_mpz_t() );
    /////////////////////////////

    char * retval_str = mpz_get_str(NULL, 10, c);

    return PyLong_FromString(retval_str,NULL,10);
}

PyObject* DFA::getNumWordsInLanguage( uint32_t min_word_length,
                                      uint32_t max_word_length )
{
    PyObject* retval;

    // count the number of words in the language of length
    // at least min_word_length and no greater than max_word_length
    mpz_class num_words = 0;
    for (uint32_t word_length = min_word_length;
            word_length<= max_word_length;
            word_length++) {
        num_words += _T[_start_state][word_length];
    }

    // convert the resulting integer to a string
    uint8_t base = 10;
    char *num_words_str = new char[num_words.get_str().length() + 1];
    strcpy(num_words_str, num_words.get_str().c_str());
    retval = PyLong_FromString(num_words_str, NULL, base);

    // cleanup
    delete [] num_words_str;

    return retval;
}

std::string attFstFromRegex(std::string regex)
{
    std::string retval;

    // specify compile flags for re2
    re2::Regexp::ParseFlags re_flags;
    re_flags = re2::Regexp::ClassNL;
    re_flags = re_flags | re2::Regexp::OneLine;
    re_flags = re_flags | re2::Regexp::PerlClasses;
    re_flags = re_flags | re2::Regexp::PerlB;
    re_flags = re_flags | re2::Regexp::PerlX;
    re_flags = re_flags | re2::Regexp::Latin1;

    // compile regex to DFA
    RE2::Options opt;
    re2::Regexp* re = re2::Regexp::Parse( regex, re_flags, NULL );
    re2::Prog* prog = re->CompileToProg( opt.max_mem() );
    retval = prog->PrintEntireDFA( re2::Prog::kFullMatch );

    // cleanup
    delete prog;
    re->Decref();

    return retval;
}

std::string attFstMinimize(std::string str_dfa)
{
    std::string retval;

    // create the destinations for our working files
    boost::filesystem::path temp_dir = boost::filesystem::temp_directory_path();
    boost::filesystem::path temp_file = boost::filesystem::unique_path();

    std::string abspath_dfa     = temp_dir.native() + "/" + temp_file.native() + ".dfa";
    std::string abspath_fst     = temp_dir.native() + "/" + temp_file.native() + ".fst";
    std::string abspath_fst_min = temp_dir.native() + "/" + temp_file.native() + ".min.fst";
    std::string abspath_dfa_min = temp_dir.native() + "/" + temp_file.native() + ".min.dfa";

    // write our input DFA to disk
    std::ofstream dfa_stream;
    dfa_stream.open (abspath_dfa.c_str());
    dfa_stream << str_dfa;
    dfa_stream.close();

    std::string cmd;
    // convert our ATT DFA string to an FST
    cmd = "fstcompile " + abspath_dfa + " " + abspath_fst;
    system(cmd.c_str());

    // convert our FST to a minmized FST
    cmd = "fstminimize " + abspath_fst + " " + abspath_fst_min;
    system(cmd.c_str());

    // covert our minimized FST to an ATT FST string
    cmd = "fstprint " + abspath_fst_min + " " + abspath_dfa_min;
    system(cmd.c_str());

    // read the contents of of the file at abspath_dfa_min to our retval
    std::ifstream dfa_min_stream(abspath_dfa_min.c_str());
    std::stringstream buffer;
    buffer << dfa_min_stream.rdbuf();
    retval = std::string(buffer.str());
    dfa_min_stream.close();

    // cleanup
    remove( abspath_dfa.c_str() );
    remove( abspath_fst.c_str() );
    remove( abspath_fst_min.c_str() );
    remove( abspath_dfa_min.c_str() );

    return retval;
}

BOOST_PYTHON_MODULE(cDFA)
{
    boost::python::class_<DFA>("DFA",boost::python::init<std::string,int32_t>())
    .def("rank", &DFA::rank)
    .def("unrank", &DFA::unrank)
    .def("getNumWordsInLanguage", &DFA::getNumWordsInLanguage);

    boost::python::def("attFstFromRegex",attFstFromRegex);
    boost::python::def("attFstMinimize",attFstMinimize);
}
