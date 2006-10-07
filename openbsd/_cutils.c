#include <Python.h>

int stealingSetItem(PyObject *dict, char *str, PyObject *obj){
    int i;
    i = PyDict_SetItemString(dict, str, obj);
    Py_DECREF(obj);
    return i;
}

