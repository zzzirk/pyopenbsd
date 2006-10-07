/*
	Copyright (c) 2003, 2006 Aldo Cortesi
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	*   Redistributions of source code must retain the above copyright notice, this
		list of conditions and the following disclaimer.
	*   Redistributions in binary form must reproduce the above copyright notice,
		this list of conditions and the following disclaimer in the documentation
		and/or other materials provided with the distribution.
	*   Neither the name of Nullcube nor the names of its contributors may be used to
		endorse or promote products derived from this software without specific prior
		written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
	ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <Python.h>

PyObject *OException;

static PyObject *pykqueue(PyObject *self, PyObject *args){
    int k;
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    k = kqueue();
    if (k < 0){
        PyErr_SetFromErrno(OException);
        return NULL;
    }
    return PyInt_FromLong((long int) k);
}

static PyObject *pykevent(PyObject *self, PyObject *args){
    PyObject *pchangelist, *ptimespec, *tmp, *ret, *udata;
    int nevents, kq;
    long seconds, nanoseconds;
    struct timespec timeout, *tptr;
    struct kevent *changelist, *eventlist;
    int i, csize, esize;

    if (!PyArg_ParseTuple(args, "iOiO", &kq, &pchangelist, &nevents, &ptimespec))
        return NULL;

    if (ptimespec == Py_None){
        tptr = NULL;
    } else {
        if (!PyTuple_Check(ptimespec)){
			PyErr_SetString(OException, "Timeout specification must be a tuple.");
            return NULL;
        }
        tmp = PyTuple_GetItem(ptimespec, 0);
        seconds = (int)PyInt_AsLong(tmp);
        tmp = PyTuple_GetItem(ptimespec, 1);
        nanoseconds = (int)PyInt_AsLong(tmp);
        timeout.tv_sec = seconds;
        timeout.tv_nsec = nanoseconds;
        tptr = &timeout;
    }

    if (pchangelist == Py_None){
        changelist = NULL;
        csize = 0;
    } else {
        csize = PySequence_Size(pchangelist);
        if ((changelist = malloc(sizeof(struct kevent) * csize)) == NULL){
		    PyErr_SetFromErrno(OException);
            return NULL;
        }
        for (i = 0; i < PySequence_Size(pchangelist); i++){
            PyObject *attr;
            tmp = PySequence_GetItem(pchangelist, i);
            attr = PyObject_GetAttrString(tmp, "ident");
            if (!attr){
                free(changelist);
                return NULL;
            }
            if (!PyNumber_Check(attr)){
                free(changelist);
                PyErr_SetString(OException, "ident must be a number.");
                return NULL;
                Py_DECREF(attr);
            }
            changelist[i].ident = PyInt_AsLong(attr);
            Py_DECREF(attr);

            attr = PyObject_GetAttrString(tmp, "_filter");
            if (!attr){
                free(changelist);
                return NULL;
            }
            if (!PyNumber_Check(attr)){
                free(changelist);
                PyErr_SetString(OException, "filter must be a number.");
                return NULL;
                Py_DECREF(attr);
            }
            changelist[i].filter = PyInt_AsLong(attr);
            Py_DECREF(attr);

            attr = PyObject_GetAttrString(tmp, "flags");
            if (!attr){
                free(changelist);
                return NULL;
            }
            if (!PyNumber_Check(attr)){
                free(changelist);
                PyErr_SetString(OException, "flags must be a number.");
                return NULL;
                Py_DECREF(attr);
            }
            changelist[i].flags = PyInt_AsLong(attr);
            Py_DECREF(attr);

            attr = PyObject_GetAttrString(tmp, "fflags");
            if (!attr){
                free(changelist);
                return NULL;
            }
            if (!PyNumber_Check(attr)){
                free(changelist);
                PyErr_SetString(OException, "fflags must be a number.");
                return NULL;
                Py_DECREF(attr);
            }
            changelist[i].fflags = PyInt_AsLong(attr);
            Py_DECREF(attr);

            udata = PyObject_GetAttrString(tmp, "udata");
            if (!udata){
                free(changelist);
                return NULL;
            }
            Py_INCREF(udata);
            changelist[i].udata = (void*)udata;

            attr = PyObject_GetAttrString(tmp, "data");
            if (!attr){
                free(changelist);
                return NULL;
            }
            if (!PyNumber_Check(attr)){
                free(changelist);
                PyErr_SetString(OException, "data must be a number.");
                return NULL;
                Py_DECREF(attr);
            }
            changelist[i].data = PyInt_AsLong(attr);
            Py_DECREF(attr);

            Py_DECREF(tmp);
        }
    }

    if (nevents){
        if ((eventlist = malloc(sizeof(struct kevent) * nevents)) == NULL){
            free(changelist);
		    PyErr_SetFromErrno(OException);
            return NULL;
        }
    } else
        eventlist = NULL;
    esize = kevent(kq, changelist, csize, eventlist, nevents, tptr);
    free(changelist);
    if (esize == -1){
        PyErr_SetFromErrno(OException);
        free(eventlist);
        return NULL;
    }

    if (esize > 0){
        ret = PyList_New(esize);
        for (i = 0; i < esize; i++){
            tmp = Py_BuildValue(
                        "(iihHOi)",
                        eventlist[i].filter,
                        eventlist[i].ident,
                        eventlist[i].flags,
                        eventlist[i].fflags,
                        (PyObject*)eventlist[i].udata,
                        eventlist[i].data
                    );
            if (PyList_SetItem(ret, i, tmp) < 0){
                Py_DECREF(ret);
                Py_DECREF(tmp);
                free(eventlist);
                return NULL;
            }
        }
        free(eventlist);
        return ret;
    } 
    free(eventlist);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef KEventMethods[] = {
	{"kqueue",			pykqueue,		METH_VARARGS,	"Initialise a kqueue."},
	{"kevent",			pykevent,		METH_VARARGS,	"Register or retrieve kevents."},
	{NULL, NULL, 0, NULL}		 /* Sentinel */
};

void init_kqueue(void){
	PyObject *module, *global;
	module = Py_InitModule("_kqueue", KEventMethods);
	global = PyImport_ImportModule("_global");
	OException = PyObject_GetAttrString(global, "OException");
}
