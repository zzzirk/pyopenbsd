#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Python.h>

#include "_cutils.h"


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


PyObject *get_mntinfo(PyObject *self, PyObject *args){
    long mntsize, i;
    struct statfs *mntbuf;
    PyObject *mntlist, *tmpdict;

    if (!(mntlist = PyList_New(0)))
        return NULL;

    mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
    for (i = 0; i < mntsize; i++) {
        tmpdict = Py_BuildValue("{s:s}", "mntfromname", mntbuf[i].f_mntfromname);
        stealingSetItem(tmpdict, "fstypename", PyString_FromString(mntbuf[i].f_fstypename));
        stealingSetItem(tmpdict, "mntonname", PyString_FromString(mntbuf[i].f_mntonname));
        stealingSetItem(tmpdict, "ctime", PyLong_FromUnsignedLong(mntbuf[i].f_ctime));
        stealingSetItem(tmpdict, "owner", PyLong_FromUnsignedLong(mntbuf[i].f_owner));
        stealingSetItem(tmpdict, "flags", PyLong_FromUnsignedLong(mntbuf[i].f_flags));
        stealingSetItem(tmpdict, "bsize", PyLong_FromLong(mntbuf[i].f_bsize));
        stealingSetItem(tmpdict, "iosize", PyLong_FromUnsignedLong(mntbuf[i].f_iosize));
        stealingSetItem(tmpdict, "blocks", PyLong_FromUnsignedLong(mntbuf[i].f_blocks));
        stealingSetItem(tmpdict, "bfree", PyLong_FromUnsignedLong(mntbuf[i].f_bfree));
        stealingSetItem(tmpdict, "bavail", PyLong_FromLong(mntbuf[i].f_bavail));

        if (PyList_Append(mntlist, tmpdict) < 0) {
            Py_DECREF(tmpdict);
            Py_DECREF(mntlist);
            return NULL;
        }
    }
    return mntlist;
}


static PyMethodDef SystemMethods[] = {
    {"get_hostname", get_hostname, METH_VARARGS, "Get hostname."},
    {"set_hostname", set_hostname, METH_VARARGS, "Set hostname."},
    {"get_mntinfo", get_mntinfo, METH_VARARGS, "Get mount info."},
    {NULL, NULL, 0, NULL}            /* Sentinel */
};

void init_system(void){
    PyObject *module, *global;
    module = Py_InitModule("_system", SystemMethods);
    global = PyImport_ImportModule("_global");
    OException = PyObject_GetAttrString(global, "OException");
}
