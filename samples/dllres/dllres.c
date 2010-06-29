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
 * pseudo loading sample (dll is embedded in RCDATA resource).
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "resource.h"

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
// {{{ _load_and_map_rawdata()

PCHEAP2EL_PE_IMAGE
_load_and_map_rawdata(
        LPVOID lpRawData,
        LPVOID lpPageHead,
        LPVOID *lpVirtualPage,
        CHEAP2EL_ERROR_CODE *err)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;

    cheap2el_get_sizeofimage_from_file(
            lpRawData, &sz_image, &sz_header, err);
    nLen = sz_image;
    *lpVirtualPage = VirtualAlloc(
            lpPageHead, 
            nLen, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE);
    if (NULL == *lpVirtualPage) {
        return NULL;
    }

    pe = cheap2el_map_to_memory(
            lpRawData, *lpVirtualPage, nLen, err);

    return pe;
}

// }}}
// {{{ get_payload_dll()

BOOL
get_payload_dll(WORD resid, DWORD *addr, DWORD *len)
{
    HINSTANCE hCurrentInst;
    HRSRC hResRc;
    HGLOBAL hGlobal;
    LPVOID lpRes;

    hCurrentInst = GetModuleHandle(NULL);

    hResRc = FindResource(
        hCurrentInst, 
        MAKEINTRESOURCE(resid),
        RT_RCDATA);
    if (NULL == hResRc) {
        return FALSE;
    }

    *len = SizeofResource(hCurrentInst, hResRc);
    if (0 == *len) {
        return FALSE;
    }

    hGlobal = LoadResource(hCurrentInst, hResRc);
    if (NULL == hGlobal) {
        return FALSE;
    }

    lpRes = LockResource(hGlobal);
    if (NULL == lpRes) {
        return FALSE;
    }
    *addr = (DWORD)lpRes;

    return TRUE;
}

// }}}

int main(int argc, char *argv[])
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg;
    LPVOID lpVirtualPage;
    DWORD dwptr, len;
    DWORD (*pfunc)(void);
    DWORD dwVersion = 0; 
    DWORD dwMajorVersion = 0;
    DWORD dwMinorVersion = 0; 
    DWORD dwBuild = 0;

    if (!get_payload_dll(IDR_RCDATA1, &dwptr, &len)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "get_payload_dll() failed\n");
        return 1;
    }
    printf("payload head address = 0x%08X, length = 0x%08X\n", dwptr, len);

    pe = _load_and_map_rawdata(
            (LPVOID)dwptr,
            (LPVOID)NULL,
            &lpVirtualPage,
            &err);
    if (NULL == pe) {
        _print_last_error(GetLastError());
        fprintf(stderr, "_load_and_map_rawdata() failed\n");
        return 2;
    }
    printf("payload dll is extracted from 0x%08X\n", lpVirtualPage);

    if (!cheap2el_pseudo_load_address_resolver(pe, &arg)) {
        _print_last_error(arg.dwLastError);
        fprintf(stderr, "cheap2el_pseudo_load_address_resolver() failed\n");
        return 3;
    }

    // get exported function "get_version" pointer
    dwptr = cheap2el_get_export_rva_by_name(pe, "get_version");
    dwptr += pe->dwActualImageBase;
    pfunc = (DWORD (*)(void))(dwptr);

    // call "get_version" and display result
    dwVersion = pfunc();
    dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
    if (dwVersion < 0x80000000) {
        dwBuild = (DWORD)(HIWORD(dwVersion));
    }
    printf("Version is %d.%d (%d)\n", 
            dwMajorVersion, dwMinorVersion, dwBuild);

    GlobalFree(pe);
    if (!VirtualFree(lpVirtualPage, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "VirtualFree() failed\n");
        return 4;
    }

    return 0;
}
