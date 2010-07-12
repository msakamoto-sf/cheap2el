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
 * print export forwarding list for ".def" file
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

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

static BOOL
print_export_def_lines(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    char *basename = (char*)lpApplicationData;
    if (0 != ee->rvaOfName) {
        printf("    %s = %s.%s\n", ee->Name, basename, ee->Name);
    }
    // ignore ordinal export entry

    return FALSE;
}

int main(int argc, char *argv[])
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    char fullpath[MAX_PATH];
    char *basename;
    char *extptr;

    if (2 != argc) {
        fprintf(stderr, "usage: %s dllfile\n", argv[0]);
        return -1;
    }

    hModule = LoadLibrary(argv[1]);
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        return -2;
    }

    // fullpath should be "X:\foo\bar\baz.dll"
    GetModuleFileName(hModule, fullpath, MAX_PATH);

    // basename should be "baz.dll"
    basename = strrchr(fullpath, '\\');
    if (!basename) {
        printf("error: basename detection failed. no-back-slash.\n");
        return -3;
    }
    basename++;

    // basename should be "baz\00\00\00\00..."
    extptr = strstr(basename, ".dll");
    if (NULL != extptr) {
        ZeroMemory(extptr, 4);
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    if (NULL == pe) {
        printf("cheap2el failed, code:%d\n", err);
        return -4;
    }

    printf("LIBRARY %s.dll\n", basename);
    printf("EXPORTS\n");
    cheap2el_enumerate_export_tables(
            pe, print_export_def_lines, (LPVOID)basename);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return 0;
}
