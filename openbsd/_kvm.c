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

#include <stdio.h>
#include <kvm.h>
#include <fcntl.h>
#include <Python.h>
#include "_kvm.h"

kvm_t *kvmd;
PyObject *OException;

/*
 * Read kernel memory. Return 0 on success.
 */
int kread(u_long addr, char *buf, int size){
	if (kvm_read(kvmd, addr, buf, size) != size) {
        PyErr_Format(OException, "Kernel read error: %s", kvm_geterr(kvmd));
		return (1);
	}
	return (0);
}

int kclose(void){
    return kvm_close(kvmd);
}

/*
 * Initialise the KVM access. Return 0 on success.
 */
int kvm_initialise(struct nlist *nl){
	char buf[_POSIX2_LINE_MAX];
    if ((kvmd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, buf)) == NULL) {
		/* FIXME: Get error using kvm_geterr */
        PyErr_Format(OException, "Error accessing kernel virtual memory: %s", buf);
        return 1;
	}
	if (kvm_nlist(kvmd, nl) < 0) {
        PyErr_SetString(OException, kvm_geterr(kvmd));
        return 1;
	}
    return 0;
}
