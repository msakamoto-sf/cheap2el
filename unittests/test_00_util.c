/*
 * Copyright 2010 sakamoto.gsyc.3s@gmail.com
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * cheap2el : unittests utility function implementation
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"

// {{{ _hexdump()

void
_hexdump(DWORD addr, int len)
{
    int i, r;
    unsigned char *p = (unsigned char*)addr;
    for (i = 0, r = 0; i < len; i++, r++, p++) {
        printf("%02X ", *p);
        if (15 == r) {
            printf("\n");
            r = -1;
        }
    }
}

// }}}
// {{{ _print_last_error()

void
_print_last_error(DWORD err)
{
    LPTSTR lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM 
            | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf, 0, NULL);
    fprintf(stderr, "%s\n", lpMsgBuf);
    LocalFree(lpMsgBuf);
}

// }}}
// {{{ _load_test_data()

LPVOID
_load_test_data(LPCTSTR lpFileName)
{
    HANDLE hFile;
    DWORD datalen;
    DWORD readlen;
    LPVOID membuf = NULL;
    hFile = CreateFile(
            lpFileName, 
            GENERIC_READ, 
            0,
            NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        _print_last_error(GetLastError());
        return NULL;
    }
    datalen = GetFileSize(hFile, NULL);
    if (INVALID_FILE_SIZE == datalen) {
        _print_last_error(GetLastError());
        return NULL;
    }
    membuf = (LPVOID)GlobalAlloc(GMEM_ZEROINIT, datalen);
    if (NULL == membuf) {
        _print_last_error(GetLastError());
        return NULL;
    }
    if (!ReadFile(hFile, membuf, datalen, &readlen, NULL)) {
        GlobalFree(membuf);
        _print_last_error(GetLastError());
        return NULL;
    }
    CloseHandle(hFile);
    return membuf;
}

// }}}
// {{{ _load_and_map_test_data()

typedef struct _lam_arg {
    LPVOID lpFileBuffer;
    LPVOID lpMemoryBuffer;
} lam_arg, *plam_arg;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data(
        plam_arg arg, LPCSTR lpFileName, CHEAP2EL_ERROR_CODE *err)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;

    arg->lpFileBuffer = _load_test_data(lpFileName);
    if (NULL == arg->lpFileBuffer) {
        CU_FAIL("memory error");
        return NULL;
    }

    cheap2el_get_sizeofimage_from_file(
            arg->lpFileBuffer, &sz_image, &sz_header, err);
    nLen = sz_image;
    arg->lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);

    pe = cheap2el_map_to_memory(
            arg->lpFileBuffer, arg->lpMemoryBuffer, nLen, err);

    return pe;
}

// }}}
// {{{ _load_and_map_test_data2()

typedef struct _lam_arg2 {
    LPVOID lpFileBuffer;
    LPVOID lpVirtualPage;
} lam_arg2, *plam_arg2;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data2(LPVOID addr, plam_arg2 arg, LPCSTR lpFileName, CHEAP2EL_ERROR_CODE *err)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;

    arg->lpFileBuffer = _load_test_data(lpFileName);
    if (NULL == arg->lpFileBuffer) {
        CU_FAIL("memory error");
        return NULL;
    }

    cheap2el_get_sizeofimage_from_file(
            arg->lpFileBuffer, &sz_image, &sz_header, err);
    nLen = sz_image;
    arg->lpVirtualPage = VirtualAlloc(
            addr, nLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == arg->lpVirtualPage) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualAlloc() error");
        return NULL;
    }

    pe = cheap2el_map_to_memory(
            arg->lpFileBuffer, arg->lpVirtualPage, nLen, err);

    return pe;
}

// }}}
