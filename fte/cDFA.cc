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

#include <iostream>
#include <fstream>

#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/prog.h"

int _CRT_MT = 1;

array_type_string_t1 tokenize( std::string line, char delim ) {
    array_type_string_t1 retval;

    std::istringstream iss(line);
    std::string fragment;
    while(std::getline(iss, fragment, delim))
        retval.push_back(fragment);

    return retval;
}

/*
 * Parameters:
 *   dfa_str: an ATT FST formatted DFA, see: http://www2.research.att.com/~fsmtools/fsm/man4/fsm.5.html
 *   max_len: the maxium length to compute DFA::buildTable
 */
DFA::DFA(std::string dfa_str, uint16_t max_len)
    : _max_len(max_len),
      _start_state(-1),
      _num_states(0),
      _num_symbols(0)
{
    // construct the _start_state, _final_states and symbols/states of our DFA
    array_type_uint16_t1 symbols;
    unordered_set_uint16_t1 states;
    std::string line;
    std::istringstream my_str_stream(dfa_str);
    while ( getline (my_str_stream,line) )
    {
        if (line.empty()) break;

        array_type_string_t1 split_vec = tokenize( line, '\t' );
        if (split_vec.size() == 4) {
            uint16_t current_state = strtol(split_vec[0].c_str(),NULL,10);
            uint16_t symbol = strtol(split_vec[2].c_str(),NULL,10);
            states.insert( current_state );

            if (find(symbols.begin(), symbols.end(), symbol)==symbols.end()) {
                symbols.push_back( symbol );
            }

            if ( _start_state == -1 ) {
                _start_state = current_state;
            }
        } else if (split_vec.size()==1) {
            uint16_t final_state = strtol(split_vec[0].c_str(),NULL,10);
            _final_states.insert( final_state );
            states.insert( final_state );
        } else {
            // TODO: throw exception because we don't understand the file format
        }

    }
    states.insert( states.size() ); // extra for the "dead" state

    _num_symbols = symbols.size();
    _num_states = states.size();

    // build up our sigma/sigma_reverse tables which enable mappings between
    // bytes/integers
    uint16_t j, k;
    for (j=0; j<_num_symbols; j++) {
        _sigma[j] = (char)(symbols[j]);
        _sigma_reverse[(char)(symbols[j])] = j;
    }

    // intialize all transitions in our DFA to our dead state
    _delta.resize(_num_states);
    for (j=0; j<_num_states; j++) {
        _delta[j].resize(_num_symbols);
        for (k=0; k < _num_symbols; k++) {
            _delta[j][k] = _num_states - 1;
        }
    }

    // fill our our transition function delta
    std::istringstream my_str_stream2(dfa_str);
    while ( getline (my_str_stream2,line) )
    {
        array_type_string_t1 split_vec = tokenize( line, '\t' );
        if (split_vec.size() == 4) {
            uint16_t current_state = strtol(split_vec[0].c_str(),NULL,10);
            uint16_t symbol = strtol(split_vec[2].c_str(),NULL,10);
            uint16_t new_state = strtol(split_vec[1].c_str(),NULL,10);

            symbol = _sigma_reverse[symbol];

            _delta[current_state][symbol] = new_state;
        }
    }

    _delta_dense.resize(_num_states);
    uint16_t q, a;
    for (q=0; q < _num_states; q++ ) {
        _delta_dense[q] = true;
        for (a=1; a < _num_symbols; a++) {
            if (_delta[q][a-1] != _delta[q][a]) {
                _delta_dense[q] = false;
                break;
            }
        }
    }

    // perform our precalculation to speed up (un)ranking
    DFA::_buildTable();
}


void DFA::_buildTable() {
    // TODO: baild if _final_states, _delta, or _T are not initialized

    uint16_t i;
    uint16_t q;
    uint16_t a;

    // ensure our table _T is the correct size
    _T.resize(_num_states);
    for (q=0; q<_num_states; q++) {
        _T[q].resize(_max_len+1);
        for (i=0; i<=_max_len; i++) {
            _T[q][i] = 0;
        }
    }

    // set all _T[q][0] = 1 for all states in _final_states
    unordered_set_uint16_t1::iterator state;
    for (state=_final_states.begin(); state!=_final_states.end(); state++) {
        _T[*state][0] = 1;
    }

    // walk through our table _T
    // we want each entry _T[q][i] to contain the number of strings that start
    // from state q, terminate in a final state, and are of length i
    for (i=1; i<=_max_len; i++) {
        for (q=0; q<_delta.size(); q++) {
            for (a=0; a<_delta[0].size(); a++) {
                uint16_t state = _delta[q][a];
                _T[q][i] += _T[state][i-1];
            }
        }
    }
}


std::string DFA::unrank( const mpz_class c_in ) {
    // TODO: throw exception if input integer is not in range of pre-computed
    //       values
    // TODO: throw exception if walking DFA does not end in a final state
    // TODO: throw exception if input integer is not PympzObject*-type

    std::string retval;
    
    mpz_class c = c_in;

    // subtract values values from c, while increasing n, to determine
    // the length n of the string we're ranking
    uint16_t n = _max_len;

    // walk the DFA subtracting values from c until we have our n symbols
    uint16_t i, q = _start_state;
    uint16_t chars_left, char_cursor, state_cursor;
    for (i=1; i<=n; i++) {
        chars_left = n-i;
        if (_delta_dense[q]) {
            q = _delta[q][0];
            if (_T[q][chars_left]!=0) {
                mpz_class char_index = (c / _T[q][chars_left]);
                char_cursor = char_index.get_ui();
                retval = retval + _sigma[char_cursor];
                c = c % _T[q][chars_left];
            } else {
                retval += _sigma[0];
            }
        } else {
            char_cursor = 0;
            state_cursor = _delta[q][char_cursor];
            while (c >= _T[state_cursor][chars_left]) {
                c -= _T[state_cursor][chars_left];
                char_cursor += 1;
                state_cursor =_delta[q][char_cursor];
            }
            retval += _sigma[char_cursor];
            q = state_cursor;
        }
    }

    return retval;
}

mpz_class DFA::rank( const std::string X_in ) {
    // TODO: verify that input symbols are in alphabet of DFA
    
    mpz_class retval = 0;

    // walk the DFA, adding values from T to c
    uint16_t i, j;
    uint16_t n = X_in.size();
    uint16_t q = _start_state;
    uint16_t state;
    for (i=1; i<=n; i++) {
        uint8_t symbol_as_int = _sigma_reverse[X_in.at(i-1)];
        if (_delta_dense[q]) {
            state = _delta[q][0];
            retval += (_T[state][n-i] * symbol_as_int);
        } else {
            for (j=1; j<=symbol_as_int; j++) {
                state = _delta[q][j-1];
                retval += _T[state][n-i];
            }
        }
        q = _delta[q][symbol_as_int];
    }

    // bail if our final state is not in _final_states
    if (_final_states.count(q)==0) {
        // TODO: throw exception, because we are not in a final state
    }
    
    return retval;
}

mpz_class DFA::getNumWordsInLanguage( const uint16_t min_word_length,
                                      const uint16_t max_word_length )
{    
    // count the number of words in the language of length
    // at least min_word_length and no greater than max_word_length
    mpz_class num_words = 0;
    for (uint16_t word_length = min_word_length;
            word_length <= max_word_length;
            word_length++) {
        num_words += _T[_start_state][word_length];
    }
    return num_words;
}

static std::string attFstFromRegex( const std::string regex )
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
    RE2::Options opt;
    re2::Regexp* re = re2::Regexp::Parse( regex, re_flags, &status );
    re2::Prog* prog = re->CompileToProg( opt.max_mem() );
    retval = prog->PrintEntireDFA( re2::Prog::kFullMatch );

    // cleanup
    delete prog;
    re->Decref();

    return retval;
}





/*
 * Below is code for exposing our interface to Python.
 */


// ...
typedef struct {
    PyObject_HEAD
    DFA *obj;
} DFAObject;


// ...
static void
DFA_dealloc(PyObject* self)
{
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj != NULL)
        delete pDFAObject->obj;
    if (self != NULL)
        PyObject_Del(self);
}


// ...
static PyObject * DFA__rank(PyObject *self, PyObject *args) {
    char* word;
    Py_ssize_t len;
    PyObject* c_out;

    if (!PyArg_ParseTuple(args, "s#O", &word, &len, &c_out))
        return NULL;

    const std::string str_word = std::string(word, (int32_t)len);

    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    mpz_class result = pDFAObject->obj->rank(str_word);
    
    mpz_set(Pympz_AS_MPZ(c_out), result.get_mpz_t());
    Py_INCREF(c_out);

    Py_RETURN_NONE;
}


// ...
static PyObject * DFA__unrank(PyObject *self, PyObject *args) {
    PyObject* c_out;

    if (!PyArg_ParseTuple(args, "O", &c_out))
        return NULL;

    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    const mpz_class to_unrank = mpz_class( Pympz_AS_MPZ(c_out) );
    std::string result = pDFAObject->obj->unrank(to_unrank);

    PyObject* retval = Py_BuildValue("s#", result.c_str(), result.length());
    Py_INCREF(retval);
    
    return retval;
}


// ...
static PyObject * DFA__getNumWordsInLanguage(PyObject *self, PyObject *args) {
    PyObject* retval;
    
    int32_t min_val;
    int32_t max_val;

    if (!PyArg_ParseTuple(args, "ii", &min_val, &max_val))
        return NULL;

    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    
    mpz_class num_words = pDFAObject->obj->getNumWordsInLanguage(min_val, max_val);

    // convert the resulting integer to a string
    uint8_t base = 10;
    uint16_t num_words_str_len = num_words.get_str().length();
    char *num_words_str = new char[num_words_str_len + 1];
    strcpy(num_words_str, num_words.get_str().c_str());
    retval = PyLong_FromString(num_words_str, NULL, base);
    Py_INCREF(retval);
    
    // cleanup
    delete [] num_words_str;

    return retval;
}


// ...
static PyObject *
__attFstFromRegex(PyObject *self, PyObject *args) {
    const char *regex;
    if (!PyArg_ParseTuple(args, "s", &regex))
        return NULL;
    
    const std::string str_regex = std::string(regex);
    std::string result = attFstFromRegex(str_regex);
    PyObject* retval = Py_BuildValue("s", result.c_str());
    Py_INCREF(retval);
    
    return retval;
}


// ...
static PyObject *
DFA_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    DFAObject *self = (DFAObject *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}


// ...
static int
DFA_init(DFAObject *self, PyObject *args, PyObject *kwds)
{
    const char *regex;
    int32_t max_len;

    if (!PyArg_ParseTuple(args, "si", &regex, &max_len))
        return 0;
    
    self->obj = new DFA(std::string(regex), max_len);

    return 0;
}


// Methods in fte.cDFA.DFA
static PyMethodDef DFA_methods[] = {
    {"rank",  DFA__rank, METH_VARARGS, NULL},
    {"unrank",  DFA__unrank, METH_VARARGS, NULL},
    {"getNumWordsInLanguage",  DFA__getNumWordsInLanguage, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};


// The DFAType structure that contains the structure of the fte.cDFA.DFA type
static PyTypeObject DFAType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "DFA",
    sizeof(DFAObject),
    0,
    DFA_dealloc,    /*tp_dealloc*/
    0,                       /*tp_print*/
    0,                       /*tp_getattr*/
    0,                       /*tp_setattr*/
    0,                       /*tp_compare*/
    0,                       /*tp_repr*/
    0,                       /*tp_as_number*/
    0,                       /*tp_as_sequence*/
    0,                       /*tp_as_mapping*/
    0,                       /*tp_hash */
    0,			     /* tp_call */
    0,			     /* tp_str */
    0,  		     /* tp_getattro */
    0,		   	     /* tp_setattro */
    0,			     /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE, /*tp_flags*/
    0,			     /* tp_doc */
    0,			     /* tp_traverse */
    0,			     /* tp_clear */
    0,			     /* tp_richcompare */
    0,			     /* tp_weaklistoffset */
    0,			     /* tp_iter */
    0,			     /* tp_iternext */
    DFA_methods,	     /* tp_methods */
    0,			     /* tp_members */
    0,		   	     /* tp_getset */
    0,			     /* tp_base */
    0,			     /* tp_dict */
    0,			     /* tp_descr_get */
    0,			     /* tp_descr_set */
    0,		   	     /* tp_dictoffset */
    (initproc)DFA_init,	     /* tp_init */
    0,			     /* tp_alloc */
    DFA_new,		     /* tp_new */
    0,			     /* tp_free */
};


// Methods in our fte.cDFA package
static PyMethodDef ftecDFAMethods[] = {
    {"attFstFromRegex",  __attFstFromRegex, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};


// Main entry point for the fte.cDFA module.
#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initcDFA(void)
{
    if (PyType_Ready(&DFAType) < 0)
        return;
    
    PyObject *m;
    m = Py_InitModule("cDFA", ftecDFAMethods);
    if (m == NULL)
        return;

    Py_INCREF(&DFAType);
    PyModule_AddObject(m, "DFA", (PyObject *)&DFAType);
}
