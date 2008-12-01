#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/dkstat.h>

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


PyObject *get_boottime(PyObject *self, PyObject *args){
    size_t size;
    struct timeval boottime;
    int mib[2];

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;

    size = sizeof(boottime);
    if (sysctl(mib, 2, &boottime, &size, NULL, 0) < 0){
        PyErr_SetFromErrno(OException);
        return NULL;
    }
    return PyLong_FromLong(boottime.tv_sec);
}


PyObject *get_cpustats(PyObject *self, PyObject *args){
    PyObject *cpudict;
    size_t size;
    int mib[2];
    long cp_time[CPUSTATES];

    size = sizeof(cp_time);
    mib[0] = CTL_KERN;
    mib[1] = KERN_CPTIME;

    if (sysctl(mib, 2, cp_time, &size, NULL, 0) < 0){
        bzero(cp_time, sizeof(cp_time));
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    cpudict = Py_BuildValue("{s:l}", "user", cp_time[CP_USER]);
    stealingSetItem(cpudict, "nice", PyLong_FromLong(cp_time[CP_NICE]));
    stealingSetItem(cpudict, "sys", PyLong_FromLong(cp_time[CP_SYS]));
    stealingSetItem(cpudict, "intr", PyLong_FromLong(cp_time[CP_INTR]));
    stealingSetItem(cpudict, "idle", PyLong_FromLong(cp_time[CP_IDLE]));
    return cpudict;
}


static PyMethodDef SystemMethods[] = {
    {"get_hostname", get_hostname, METH_VARARGS, "Get hostname."},
    {"set_hostname", set_hostname, METH_VARARGS, "Set hostname."},
    {"get_mntinfo", get_mntinfo, METH_VARARGS, "Get mount info."},
    {"get_boottime", get_boottime, METH_VARARGS, "Get boot time."},
    {"get_cpustats", get_cpustats, METH_VARARGS, "Get CPU stats."},
    {NULL, NULL, 0, NULL}            /* Sentinel */
};

void init_system(void){
    PyObject *module, *global;
    module = Py_InitModule("_system", SystemMethods);
    global = PyImport_ImportModule("_global");
    OException = PyObject_GetAttrString(global, "OException");
}
