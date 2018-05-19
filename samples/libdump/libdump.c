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
 * COFF LIB file dump utility sample
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>

// {{{ _print_last_error()

static void
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
// {{{ _load_lib()

LPVOID
_load_lib(LPCTSTR lpFileName)
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
// {{{ enum_list_cb()

BOOL
enum_list_cb(
        PCHEAP2EL_COFF_LIB lib,
        PIMAGE_ARCHIVE_MEMBER_HEADER amh,
        char *sz_longname,
        LPVOID member,
        size_t size,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD offset = (DWORD)amh;
    offset -= lib->dwBase;
    printf("0x%08X\t%s\t%d\n", offset, sz_longname, size);
    return FALSE;
}

// }}}
// {{{ enum_sym_cb()

static BOOL
enum_sym_cb(
        PCHEAP2EL_COFF_LIB lib,
        char *sz_symname,
        PIMAGE_ARCHIVE_MEMBER_HEADER amh,
        char *sz_longname,
        LPVOID member,
        size_t size,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD offset = (DWORD)amh;
    offset -= lib->dwBase;
    printf("%s in 0x%08X\t%s\t%d\n", sz_symname, offset, sz_longname, size);
    return FALSE;
}

// }}}

int main(int argc, char *argv[])
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    LPVOID lpvBuffer = NULL;
    CHEAP2EL_ERROR_CODE err = 0;
    char *cmd = NULL;
    char *file = NULL;
    int result;

    if (3 != argc) {
        fprintf(stderr, "usage: %s [list|sym] foobar.lib", argv[0]);
        return 1;
    }

    cmd = argv[1];
    file = argv[2];

    lpvBuffer = _load_lib(file);
    if (NULL == lpvBuffer) {
        fprintf(stderr, "_load_lib(%s) failed\n", file);
        return 2;
    }

    lib = cheap2el_coff_lib_map_from_memory(lpvBuffer, &err);
    if (NULL == lib) {
        fprintf(stderr, "map failed, err = %d\n", err);
        return 3;
    }

    if (!_stricmp("list", cmd)) {
        printf("[Offset]\t[FileName]\t[Size]\n");
        result = cheap2el_coff_lib_enumerate_members(lib,
            enum_list_cb, (LPVOID)NULL);
        printf("-----------------\n%d files.\n", result);
    } else if (!_stricmp("sym", cmd)) {
        printf("[Symbol]\t[Offset]\t[FileName]\t[Size]\n");
        result = cheap2el_coff_lib_enumerate_symbols(lib,
            enum_sym_cb, (LPVOID)NULL);
        printf("-----------------\n%d symbols.\n", result);
    } else {
        fprintf(stderr, "unknown command : %s, use 'list' or 'sym'\n", cmd);
    }

    GlobalFree(lib);
    GlobalFree(lpvBuffer);
    return 0;
}
