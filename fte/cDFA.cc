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

#include <Python.h>
#include <structmember.h>
#include <iostream>
#include <rank_unrank.h>

/*
 * This is a wrapper around rank_unrank.cc, to create the fte.cDFA
 * python module.
 */


// Our custom DFAObject for holding and transporting a DFA*.
typedef struct {
    PyObject_HEAD
    DFA *obj;
} DFAObject;


// Our dealloc function for cleaning up when our fte.cDFA.DFA object is deleted.
static void
DFA_dealloc(PyObject* self)
{
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj != NULL)
        delete pDFAObject->obj;

    if (self != NULL)
        PyObject_Del(self);
}


// The wrapper for calling DFA::rank.
// Takes a string as input and returns an integer.
static PyObject * DFA__rank(PyObject *self, PyObject *args) {
    char* word;
    Py_ssize_t len;

    if (!PyArg_ParseTuple(args, "s#", &word, &len))
        return NULL;

    // Copy our input word into a string.
    // We have to do the following, because we may have NUL-bytes in our strings.
    const std::string str_word = std::string(word, (uint32_t)len);

    // Verify our environment is sane and perform ranking.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    mpz_class result = pDFAObject->obj->rank(str_word);

    // Set our c_out value
    uint32_t base = 10;
    std::string to_convert = result.get_str(base);
    PyObject *retval = PyLong_FromString((char*)(to_convert.c_str()), NULL, base);

    return retval;
}


// Wrapper for DFA::unrank.
// On input of an integer, returns a string.
static PyObject * DFA__unrank(PyObject *self, PyObject *args) {
    PyObject* c;

    if (!PyArg_ParseTuple(args, "O", &c))
        return NULL;
    
    // Verify our environment is sane and perform unranking.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    
    PyObject* as_str = PyObject_Str(c);
    if(!as_str) { /* error-handling to choice */ }
    const char* the_c_str = PyString_AsString(as_str);
    mpz_class to_unrank(the_c_str, 10);
    Py_DECREF(as_str);
    
    std::string result = pDFAObject->obj->unrank(to_unrank);

    // Format our std::string as a python string and return it.
    PyObject* retval = Py_BuildValue("s#", result.c_str(), result.length());

    return retval;
}


// Takes as input two integers [min, max].
// Returns the number of strings in our language that are at least
// length min and no longer than length max, inclusive.
static PyObject * DFA__getNumWordsInLanguage(PyObject *self, PyObject *args) {
    PyObject* retval;

    uint32_t min_val;
    uint32_t max_val;

    if (!PyArg_ParseTuple(args, "ii", &min_val, &max_val))
        return NULL;

    // Verify our environment is sane, then call getNumWordsInLanguage.
    DFAObject *pDFAObject = (DFAObject*)self;
    if (pDFAObject->obj == NULL)
        return NULL;
    mpz_class num_words = pDFAObject->obj->getNumWordsInLanguage(min_val, max_val);

    // Convert the resulting integer to a string.
    // -- Is there a better way?
    uint32_t base = 10;
    uint32_t num_words_str_len = num_words.get_str().length();
    char *num_words_str = new char[num_words_str_len + 1];
    strcpy(num_words_str, num_words.get_str().c_str());
    retval = PyLong_FromString(num_words_str, NULL, base);

    // cleanup
    delete [] num_words_str;

    return retval;
}


// On input of a PCRE, outputs a non-minimized AT&T FST-formated DFA.
static PyObject *
__attFstFromRegex(PyObject *self, PyObject *args) {
    const char *regex;
    if (!PyArg_ParseTuple(args, "s", &regex))
        return NULL;

    // Convert our input char* to a string and call attFstFromRegex.
    const std::string str_regex = std::string(regex);
    std::string result = attFstFromRegex(str_regex);

    // Return the result as a python string.
    PyObject* retval = Py_BuildValue("s", result.c_str());

    return retval;
}


// Boilerplat python object alloc.
static PyObject *
DFA_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    DFAObject *self;
    self = (DFAObject *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}


// Our initialization function for fte.cDFA.DFA
// On input of a [str, int], where str is a regex,
// returns an fte.cDFA.DFA object that can perform ranking/unranking
// See rank_unrank.h for the significance of the input parameters.
static int
DFA_init(DFAObject *self, PyObject *args, PyObject *kwds)
{
    // TODO: Figure out why the standard PyArg_ParseTuple pattern
    // doesn't work.
    // see: https://github.com/kpdyer/fteproxy/issues/94
    //if (!PyArg_ParseTuple(args, "s#i", &regex, &len, &max_len))
    //    return -1;

    PyObject *arg0 = PyTuple_GetItem(args, 0);
    if (!PyString_Check(arg0)) {
        PyErr_SetString(PyExc_RuntimeError, "First argument must be a string");
        return 0;
    }
    const char* regex = PyString_AsString(arg0);

    PyObject *arg1 = PyTuple_GetItem(args, 1);
    if (!PyInt_Check(arg1)) {
        PyErr_SetString(PyExc_RuntimeError, "Second argument must be an int");
        return 0;
    }
    uint32_t max_len = PyInt_AsLong(arg1);

    // Try to initialize our DFA object.
    // An exception is thrown if the input AT&T FST is not formatted as we expect.
    // See DFA::_validate for a list of assumptions.
    try {
        const std::string str_regex = std::string(regex);
        DFA *dfa = new DFA(str_regex, max_len);
        self->obj = dfa;
    } catch (std::exception& e) {
        PyErr_SetString(PyExc_RuntimeError, e.what());
        return 0;
    }

    return 0;
}


// Methods in fte.cDFA.DFA
static PyMethodDef DFA_methods[] = {
    {"rank",  DFA__rank, METH_VARARGS, NULL},
    {"unrank",  DFA__unrank, METH_VARARGS, NULL},
    {"getNumWordsInLanguage",  DFA__getNumWordsInLanguage, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};


// Boilerplate DFAType structure that contains the structure of the fte.cDFA.DFA type
static PyTypeObject DFAType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "DFA",
    sizeof(DFAObject),
    0,
    DFA_dealloc,             /*tp_dealloc*/
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
    Py_TPFLAGS_BASETYPE,     /*tp_flags*/
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
