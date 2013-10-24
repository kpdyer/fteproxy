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
#include <boost/algorithm/string.hpp>

#include "util/test.h"
#include "util/thread.h"
#include "re2/prog.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/testing/regexp_generator.h"
#include "re2/testing/string_generator.h"

typedef long Py_hash_t;
typedef struct {
    PyObject_HEAD
    mpz_t z;
    Py_hash_t hash_cache;
} PympzObject;
#define Pympz_AS_MPZ(obj) (((PympzObject *)(obj))->z)

using namespace std;
using namespace re2;
using namespace boost::python;
using namespace boost::assign;

static std::map< std::string, uint32_t > _q0;
static std::map< std::string, std::map<uint32_t, char> > _sigma;
static std::map< std::string, std::map<char, uint32_t> > _sigma_reverse;
static std::map< std::string, array_type_uint32_t2 > _delta;
static std::map< std::string, array_type_uint32_t1 > _delta_dense;
static std::map< std::string, boost::unordered_set<uint32_t> > _final_states;
static std::map< std::string, array_type_mpz_t2 > _T;

const bool ENABLE_LINEAR = true;

class ex_lang_file_class: public exception {
    virtual const char* what() const throw() {
        return "Language file doesn't exist.";
    }
} ex_lang_file;

inline static void __buildTable(array_type_mpz_t2 & T,
                                const_array_type_uint32_t2 delta,
                                const_array_type_uint32_t1 delta_dense,
                                const uint32_t n,
                                boost::unordered_set<uint32_t> final_states) {
    uint32_t i, q, a;
    boost::unordered_set<uint32_t>::iterator it;
    for (it=final_states.begin(); it!=final_states.end(); it++) {
        T[*it][0] = 1;
    }

    mpz_t tmp;
    mpz_init(tmp);
    for (i=1; i<=n; i++) {
        for (q=0; q<delta.size(); q++) {
            for (a=0; a<delta[0].size(); a++) {
                if ( mpz_cmp_ui( T[delta[q][a]][i-1].get_mpz_t(), 0 ) > 0 )
                    T[q][i] += T[delta[q][a]][i-1];
            }
        }
    }
    mpz_clear(tmp);

}

inline static uint32_t getSizeOfT( std::string DFA_ID ) {
    uint32_t n = 0;
    for (uint32_t i = 0; i<_T[DFA_ID].size(); i++)
        for (uint32_t j = 0; j<_T[DFA_ID][i].size(); j++)
            n += sizeof(_T[DFA_ID][i][j]) + _T[DFA_ID][i][j].get_mpz_t()[0]._mp_alloc*8;
    return n;
}

inline static void getT( std::string DFA_ID, PyObject * c, uint32_t q, uint32_t i ) {
    mpz_set( Pympz_AS_MPZ(c), _T[DFA_ID][q][i].get_mpz_t() );
}

inline static uint32_t delta( std::string DFA_ID, uint32_t q, uint32_t c ) {
    return _delta[DFA_ID][q][c];
}

inline static uint32_t getStart( std::string DFA_ID) {
    return _q0[DFA_ID];
}

inline static uint32_t getNumStates( std::string DFA_ID) {
    return _T[DFA_ID].size();
}

inline static void doRank(std::string DFA_ID,
                          mpz_t c,
                          array_type_uint32_t1 X,
                          const uint32_t q0,
                          const_array_type_uint32_t2 delta,
                          const_array_type_uint32_t1 delta_dense,
                          const_array_type_mpz_t2 T) {
    if (T[0].size() < X.size()) {
        mpz_set_si( c, -1 );
        return;
    }


    uint32_t q = q0;
    uint32_t n = X.size();
    uint32_t i, j;

    mpz_t tmp;
    mpz_init(tmp);

    mpz_init_set_si( c, 0 );

    for (i=1; i<=n; i++) {
        if (ENABLE_LINEAR && delta_dense[q] == 1) {
            mpz_mul_ui( tmp, T[delta[q][0]][n-i].get_mpz_t(), X[i-1] );
            mpz_add( c, c, tmp );
        } else {
            for (j=1; j<=X[i-1]; j++) {
                mpz_add( c, c, T[delta[q][j-1]][n-i].get_mpz_t() );
            }
        }
        q = delta[q][X[i-1]];

        if (q == (delta.size()-1)) {
            mpz_set_si( c, -1 );
            return;
        }
    }

    mpz_clear(tmp);

    if (_final_states[DFA_ID].count(q)==0) {
        mpz_set_si( c, -1 );
        return;
    }

    for (i=0; i<n; i++)
        mpz_add( c, c, T[q0][i].get_mpz_t() );
}

inline static void doUnrank(std::string DFA_ID,
                            array_type_uint32_t1 & X,
                            const mpz_t c,
                            const uint32_t q0,
                            const_array_type_uint32_t2 delta,
                            const_array_type_uint32_t1 delta_dense,
                            const_array_type_mpz_t2 T) {

    uint32_t q = q0;
    uint32_t n = 1;
    uint32_t i;
    uint32_t idx;
    const uint32_t *j;
    mpz_t cTmp;
    mpz_t jTmp;

    mpz_init(jTmp);
    mpz_init_set(cTmp,c);

    while ( mpz_cmp(cTmp, T[q0][n].get_mpz_t()) >= 0 ) {
        mpz_sub( cTmp, cTmp, T[q0][n].get_mpz_t() );
        n++;
    }

    X.resize(boost::extents[n]);

    for (i=1; i<=n; i++) {
        idx = n-i;
        if (ENABLE_LINEAR && delta_dense[q] == 1) {
            q = delta[q][0];
            if ( mpz_cmp_ui( T[q][idx].get_mpz_t(), 0 ) != 0 ) {
                mpz_fdiv_qr( jTmp, cTmp, cTmp, T[q][idx].get_mpz_t() );
                X[i-1] = mpz_get_ui(jTmp);
            } else {
                X[i-1] = 0;
            }
        } else {
            j = &delta[q][0];
            while (mpz_cmp( cTmp, T[*j][idx].get_mpz_t() ) >= 0) {
                mpz_sub( cTmp, cTmp, T[*j][idx].get_mpz_t() );
                j += 1;
            }
            X[i-1] = j - &delta[q][0];
            q = *j;
        }
    }

    mpz_clear(cTmp);
    mpz_clear(jTmp);

    if (_final_states[DFA_ID].count(q)==0) {
        X.resize(boost::extents[0]);
        return;
    }
}

inline static std::string unrank( std::string DFA_ID, PyObject * c ) {
    array_type_uint32_t1 tmp;
    doUnrank( DFA_ID, tmp, Pympz_AS_MPZ(c), _q0[DFA_ID], _delta[DFA_ID], _delta_dense[DFA_ID], _T[DFA_ID] );

    uint32_t i;
    std::string X;
    for (i=0; i<tmp.size(); i++) {
        X += _sigma[DFA_ID][tmp[i]];
    }

    return X;
}

inline static void rank( std::string DFA_ID, PyObject * c, std::string X ) {
    uint32_t i;
    array_type_uint32_t1 tmp(boost::extents[X.size()]);
    for (i=0; i<X.size(); i++) {
        tmp[i] = _sigma_reverse[DFA_ID][X.at(i)];
    }

    doRank( DFA_ID, Pympz_AS_MPZ(c), tmp, _q0[DFA_ID], _delta[DFA_ID], _delta_dense[DFA_ID], _T[DFA_ID]  );
}

void releaseLanguage(std::string DFA_ID) {
    _T.erase(DFA_ID);
    _delta.erase(DFA_ID);
    _delta_dense.erase(DFA_ID);
    _sigma.erase(DFA_ID);
    _sigma_reverse.erase(DFA_ID);
}

void loadLanguage(std::string DFA_ID, std::string DFA, uint32_t MAX_WORD_LEN) {
    if (_delta.count(DFA_ID) == 1) {
        return;
    }

    std::vector<uint32_t> symbolsTmp;
    boost::unordered_set<uint32_t> statesTmp;
    boost::unordered_set<uint32_t> final_statesTmp;

    std::string line;
    {
        istringstream myfile(DFA);
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

                if (_q0.count(DFA_ID)==0) {
                    _q0[DFA_ID] = current_state;
                }
            } else if (SplitVec.size()==1 || SplitVec.size()==2) {
                uint32_t final_state = strtol(SplitVec[0].c_str(),NULL,10);
                if (statesTmp.count(final_state)==0) {
                    statesTmp.insert( final_state );
                }
                final_statesTmp.insert( final_state );
            }
        }
        //myfile.close();
            
        _final_states[DFA_ID] = final_statesTmp;

        statesTmp.insert( statesTmp.size() );
    }

    uint32_t j, k;

    const uint32_t NUM_STATES = statesTmp.size();
    const uint32_t NUM_SYMBOLS = symbolsTmp.size();

    statesTmp.clear();
    final_statesTmp.clear();

    array_type_uint32_t2 deltaTmp(boost::extents[NUM_STATES][NUM_SYMBOLS]);

    {
        std::map<uint32_t, char> sigmaTmp;
        std::map<char,uint32_t> sigmaReverseTmp;
        for (j=0; j<NUM_SYMBOLS; j++) {
            sigmaTmp[j] = (char)(symbolsTmp[j]-1);
            sigmaReverseTmp[(char)(symbolsTmp[j]-1)] = j;
        }
        _sigma[DFA_ID] = sigmaTmp;
        _sigma_reverse[DFA_ID] = sigmaReverseTmp;

        for (j=0; j<NUM_STATES; j++) {
            for (k=0; k<NUM_SYMBOLS; k++) {
                deltaTmp[j][k] = NUM_STATES-1;
            }
        }
    }

    
    std::istringstream myfile2(DFA);
    typedef vector< std::string > split_vector_type;

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
    
    
    _delta[DFA_ID].resize(boost::extents[NUM_STATES][NUM_SYMBOLS]);
    _delta[DFA_ID] = deltaTmp;

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
    _delta_dense[DFA_ID].resize(boost::extents[NUM_STATES]);
    _delta_dense[DFA_ID] = delta_denseTmp;
    array_type_mpz_t2 TTmp(boost::extents[NUM_STATES][MAX_WORD_LEN+1]);
    __buildTable( TTmp, deltaTmp, delta_denseTmp, MAX_WORD_LEN, _final_states[DFA_ID] );
    _T[DFA_ID].resize(boost::extents[NUM_STATES][MAX_WORD_LEN+1]);
    _T[DFA_ID] = TTmp;
    

}


std::string fromRegex(std::string regex)
{
    RE2::Options opt;
    opt.set_max_mem((int64_t)1<<40);
    Regexp* re = Regexp::Parse(regex, Regexp::ClassNL | Regexp::OneLine | Regexp::PerlClasses | Regexp::PerlB | Regexp::PerlX | Regexp::Latin1, NULL);
    Prog* prog = re->CompileToProg(opt.max_mem());
    std::string retval = prog->PrintEntireDFA(Prog::kFullMatch);
    delete prog;
    re->Decref();
    return retval;
}

std::string minimize(std::string dfa)
{
    //std::cout << "hi" << std::endl;
    
    boost::filesystem::path temp = boost::filesystem::unique_path();
    std::string tempstr    = temp.native();  // optional
    
    ofstream myfile;
    myfile.open (tempstr.c_str());
    myfile << dfa;
    myfile.close();
    
    std::string temp_fst = temp.native() + ".fst";
    std::string temp_fst_min = temp.native() + ".min.fst";
    std::string temp_dfa_min = temp.native() + ".min.dfa";
    
    std::string cmd1 = "fstcompile "+temp.native()+" "+temp_fst;
    std::string cmd2 = "fstminimize "+temp_fst+" "+temp_fst_min;
    std::string cmd3 = "fstprint "+temp_fst_min+" "+temp_dfa_min;
    
    //std::cout << cmd1 << std::endl;
    //std::cout << cmd2 << std::endl;
    //std::cout << cmd3 << std::endl;
    
    system(cmd1.c_str());
    system(cmd2.c_str());
    system(cmd3.c_str());
    
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
    def("unrank", unrank);
    def("rank", rank);
    def("loadLanguage", loadLanguage);
    def("releaseLanguage", releaseLanguage);
    def("getT", getT);
    def("delta", delta);
    def("getStart", getStart);
    def("getNumStates", getNumStates);
    def("getSizeOfT",getSizeOfT);
    def("fromRegex",fromRegex);
    def("minimize",minimize);
}
