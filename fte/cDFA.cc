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
  _q0(-1)
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

            if (_q0==-1) {
                _q0 = current_state;
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

    array_type_uint32_t1 delta_denseTmp(boost::extents[NUM_STATES]);
    for (j=0; j<deltaTmp.size(); j++) {
        delta_denseTmp[j] = 1;
        for (k=0; k<deltaTmp[0].size()-1; k++) {
            if (deltaTmp[j][k]!=deltaTmp[j][k+1]) {
                delta_denseTmp[j] = 0;
                break;
            }
        }
    }
    _delta_dense.resize(boost::extents[NUM_STATES]);
    _delta_dense = delta_denseTmp;
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

void DFA::doRank(mpz_t c, array_type_uint32_t1 X) {
    
    if (_T[0].size() < X.size()) {
        mpz_set_si( c, -1 );
        return;
    }
    
    uint32_t q = _q0;
    uint32_t n = X.size();
    uint32_t i, j;

    mpz_t tmp;
    mpz_init(tmp);

    mpz_init_set_si( c, 0 );

    for (i=1; i<=n; i++) {
        if (_delta_dense[q] == 1) {
            uint32_t state = _delta[q][0];
            mpz_mul_ui( tmp, _T[state][n-i].get_mpz_t(), X[i-1] );
            mpz_add( c, c, tmp );
        } else {
            for (j=1; j<=X[i-1]; j++) {
                mpz_add( c, c, _T[_delta[q][j-1]][n-i].get_mpz_t() );
            }
        }
        q = _delta[q][X[i-1]];

        if (q == (_delta.size()-1)) {
            mpz_set_si( c, -1 );
            return;
        }
    }

    mpz_clear(tmp);

    if (_final_states.count(q)==0) {
        mpz_set_si( c, -1 );
        return;
    }

    for (i=0; i<n; i++)
        mpz_add( c, c, _T[_q0][i].get_mpz_t() );
}

void DFA::doUnrank(array_type_uint32_t1 & X, const mpz_t c) {

    uint32_t q = _q0;
    uint32_t n = 1;
    uint32_t i;
    uint32_t idx;
    const uint32_t *j;
    mpz_t cTmp;
    mpz_t jTmp;

    mpz_init(jTmp);
    mpz_init_set(cTmp,c);

    while ( mpz_cmp(cTmp, _T[_q0][n].get_mpz_t()) >= 0 ) {
        mpz_sub( cTmp, cTmp, _T[_q0][n].get_mpz_t() );
        n++;
    }

    X.resize(boost::extents[n]);

    for (i=1; i<=n; i++) {
        idx = n-i;
        if (_delta_dense[q] == 1) {
            q = _delta[q][0];
            if ( mpz_cmp_ui( _T[q][idx].get_mpz_t(), 0 ) != 0 ) {
                mpz_fdiv_qr( jTmp, cTmp, cTmp, _T[q][idx].get_mpz_t() );
                X[i-1] = mpz_get_ui(jTmp);
            } else {
                X[i-1] = 0;
            }
        } else {
            j = &_delta[q][0];
            while (mpz_cmp( cTmp, _T[*j][idx].get_mpz_t() ) >= 0) {
                mpz_sub( cTmp, cTmp, _T[*j][idx].get_mpz_t() );
                j += 1;
            }
            X[i-1] = j - &_delta[q][0];
            q = *j;
        }
    }

    mpz_clear(cTmp);
    mpz_clear(jTmp);

    if (_final_states.count(q)==0) {
        X.resize(boost::extents[0]);
        return;
    }
}

std::string DFA::unrank(PyObject * c ) {
    array_type_uint32_t1 tmp;
    
    DFA::doUnrank(tmp, Pympz_AS_MPZ(c) );

    uint32_t i;
    std::string X;
    for (i=0; i<tmp.size(); i++) {
        X += _sigma[tmp[i]];
    }

    return X;
}

PyObject* DFA::rank( std::string X ) {
    uint32_t i;
    
    array_type_uint32_t1 tmpX(boost::extents[X.size()]);
    for (i=0; i<X.size(); i++) {
        tmpX[i] = _sigma_reverse[X.at(i)];
    }

    mpz_t c;
    mpz_init(c); 
    DFA::doRank( c, tmpX );
    
    char * retval_str = mpz_get_str(NULL, 10, c);
    
    return PyLong_FromString(retval_str,NULL,10);
}


PyObject* DFA::getNumWordsInLanguage() {
    mpz_class retval = 0;
    for (uint32_t i =0; i<=_max_len; i++) {
        retval += _T[_q0][i];
    }
    char *retval_str = new char[retval.get_str().length() + 1];
    strcpy(retval_str, retval.get_str().c_str());
    //delete [] retval_str;
    return PyLong_FromString(retval_str,NULL,10);
}

PyObject* DFA::getNumWordsInSlice( uint32_t i ) {
    mpz_class retval = _T[_q0][i];
    char *retval_str = new char[retval.get_str().length() + 1];
    strcpy(retval_str, retval.get_str().c_str());
    //delete [] retval_str;
    return PyLong_FromString(retval_str,NULL,10);
}


std::string attFstFromRegex(std::string regex)
{
    RE2::Options opt;
    opt.set_max_mem((int64_t)1<<40);
    re2::Regexp::ParseFlags re_flags = re2::Regexp::ClassNL | re2::Regexp::OneLine | re2::Regexp::PerlClasses | re2::Regexp::PerlB | re2::Regexp::PerlX | re2::Regexp::Latin1;
    re2::Regexp* re = re2::Regexp::Parse(regex, re_flags, NULL);
    re2::Prog* prog = re->CompileToProg(opt.max_mem());
    std::string retval = prog->PrintEntireDFA(re2::Prog::kFullMatch);
    delete prog;
    re->Decref();
    return retval;
}

std::string attFstMinimize(std::string dfa)
{
    boost::filesystem::path temp = boost::filesystem::unique_path();
    std::string tempstr    = temp.native();  // optional

    std::ofstream myfile;
    myfile.open (tempstr.c_str());
    myfile << dfa;
    myfile.close();

    std::string temp_fst = temp.native() + ".fst";
    std::string temp_fst_min = temp.native() + ".min.fst";
    std::string temp_dfa_min = temp.native() + ".min.dfa";

    std::string cmd1 = "fstcompile "+temp.native()+" "+temp_fst;
    std::string cmd2 = "fstminimize "+temp_fst+" "+temp_fst_min;
    std::string cmd3 = "fstprint "+temp_fst_min+" "+temp_dfa_min;

    int retval1 = system(cmd1.c_str());
    int retval2 = system(cmd2.c_str());
    int retval3 = system(cmd3.c_str());

    std::ifstream t(temp_dfa_min.c_str());
    std::stringstream buffer;
    buffer << t.rdbuf();

    remove( temp.native().c_str() );
    remove( temp_fst.c_str() );
    remove( temp_fst_min.c_str() );
    remove( temp_dfa_min.c_str() );

    return std::string(buffer.str());
}

BOOST_PYTHON_MODULE(cDFA)
{
    boost::python::class_<DFA>("DFA",boost::python::init<std::string,int32_t>())
        .def("rank", &DFA::rank)
        .def("unrank", &DFA::unrank)
        .def("getNumWordsInLanguage", &DFA::getNumWordsInLanguage)
        .def("getNumWordsInSlice", &DFA::getNumWordsInSlice);

    boost::python::def("attFstFromRegex",attFstFromRegex);
    boost::python::def("attFstMinimize",attFstMinimize);
}
