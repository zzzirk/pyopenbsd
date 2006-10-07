/*
	Copyright (c) 2005, 2006 Aldo Cortesi
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

#include <stdio.h>
#include <Python.h>

/* This method takes an integer argument specifying the length of the random
string to be returned. */
static PyObject * getbytes(PyObject *self, PyObject *args){
    PyObject *pstring;
    int buflen, padbuflen;
    int i;
    char *buf;

    if (!PyArg_ParseTuple(args, "i",&buflen ))
        return NULL;

    if (buflen <= 0){
        PyErr_SetString(PyExc_ValueError, "Number of bytes need to be > 0.");
        return NULL;
    };

    /* First we get a buffer length padded to 32 bits. Our random data comes in
     * chunks of this size. */
    padbuflen = buflen;
    if (buflen%4){
        padbuflen += 4-(buflen%4);
    }

    if ((buf = (char*) malloc(padbuflen)) == NULL){
        /* Set exception */
        PyErr_NoMemory();
        return NULL;
    };

    for (i = 0; i < padbuflen; i += 4){
        *(u_int32_t*)(buf+i) = arc4random();
    };

    pstring = PyString_FromStringAndSize(buf, buflen);
    free(buf);
    return pstring;
}

static PyMethodDef Arc4Methods[] = {
    {"getbytes",  getbytes, METH_VARARGS, "Get some random bytes."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

void
initarc4random(void)
{
    (void) Py_InitModule("arc4random", Arc4Methods);
}
