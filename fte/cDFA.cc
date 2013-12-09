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

#include <rank_unrank.h>


// copied from gmpy
// allows us to use gmp.mpz objects in python for input to our unrank function
typedef long Py_hash_t;
typedef struct {
    PyObject_HEAD
    mpz_t z;
    Py_hash_t hash_cache;
} PympzObject;
#define Pympz_AS_MPZ(obj) (((PympzObject *)(obj))->z)


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

    const std::string str_word = std::string(word, (uint16_t)len);

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

    uint16_t min_val;
    uint16_t max_val;

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
    uint16_t max_len;

    if (!PyArg_ParseTuple(args, "si", &regex, &max_len))
        return 0;

    try {
        self->obj = new DFA(std::string(regex), max_len);
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


// The DFAType structure that contains the structure of the fte.cDFA.DFA type
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
