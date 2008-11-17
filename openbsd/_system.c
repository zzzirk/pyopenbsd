#include <sys/param.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Python.h>


static PyObject *OException;


PyObject *get_hostname(PyObject *self, PyObject *args){
    char hostname[MAXHOSTNAMELEN];
    if (gethostname(hostname, sizeof(hostname))) {
        PyErr_SetFromErrno(OException);
        return NULL;
    }
    return PyString_FromString(hostname);
}


PyObject *set_hostname(PyObject *self, PyObject *args){
    char *hostname;
    if (!PyArg_ParseTuple(args, "s", &hostname))
        return NULL;
    if (sethostname(hostname, strlen(hostname))){
        PyErr_SetFromErrno(OException);
        return NULL;
    }
    return Py_None;
}


static PyMethodDef SystemMethods[] = {
    {"get_hostname", get_hostname, METH_VARARGS, "Get hostname."},
    {"set_hostname", set_hostname, METH_VARARGS, "Set hostname."},
    {NULL, NULL, 0, NULL}            /* Sentinel */
};

void init_system(void){
    PyObject *module, *global;
    module = Py_InitModule("_system", SystemMethods);
    global = PyImport_ImportModule("_global");
    OException = PyObject_GetAttrString(global, "OException");
}
