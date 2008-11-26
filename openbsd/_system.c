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
    PyObject *mntdict, *tmpdict;

    if (!(mntdict = PyDict_New()))
        return NULL;

    if (!(mntsize = getmntinfo(&mntbuf, MNT_NOWAIT))){
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    for (i = 0; i < mntsize; i++){
        tmpdict = Py_BuildValue("{s:s}", "mntfromname", mntbuf[i].f_mntfromname);
        stealingSetItem(tmpdict, "mntonname", PyString_FromString(mntbuf[i].f_mntonname));
        stealingSetItem(tmpdict, "fstypename", PyString_FromString(mntbuf[i].f_fstypename));
        stealingSetItem(tmpdict, "ctime", PyLong_FromUnsignedLong(mntbuf[i].f_ctime));
        stealingSetItem(tmpdict, "owner", PyLong_FromUnsignedLong(mntbuf[i].f_owner));
        stealingSetItem(tmpdict, "flags", PyLong_FromUnsignedLong(mntbuf[i].f_flags));
        stealingSetItem(tmpdict, "bsize", PyLong_FromLong(mntbuf[i].f_bsize));
        stealingSetItem(tmpdict, "iosize", PyLong_FromUnsignedLong(mntbuf[i].f_iosize));
        stealingSetItem(tmpdict, "blocks", PyLong_FromUnsignedLong(mntbuf[i].f_blocks));
        stealingSetItem(tmpdict, "bfree", PyLong_FromUnsignedLong(mntbuf[i].f_bfree));
        stealingSetItem(tmpdict, "bavail", PyLong_FromLong(mntbuf[i].f_bavail));
        stealingSetItem(tmpdict, "files", PyLong_FromUnsignedLong(mntbuf[i].f_files));
        stealingSetItem(tmpdict, "ffree", PyLong_FromUnsignedLong(mntbuf[i].f_ffree));
        stealingSetItem(
                        tmpdict,
                        "syncwrites",
                        PyLong_FromUnsignedLong(mntbuf[i].f_syncwrites)
                    );
        stealingSetItem(
                        tmpdict,
                        "asyncwrites",
                        PyLong_FromUnsignedLong(mntbuf[i].f_asyncwrites)
                    );

        if (stealingSetItem(mntdict, mntbuf[i].f_mntonname, tmpdict)){
            Py_DECREF(tmpdict);
            Py_DECREF(mntdict);
            return NULL;
        }
    }
    return mntdict;
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
