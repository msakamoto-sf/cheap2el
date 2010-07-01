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
 * replace_impaddr : replace import addresses
 *
 * $Id$
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "cheap2el.h"

typedef int (WINAPI* PMessageBoxA)(HWND, LPCTSTR, LPCTSTR, UINT);
static PMessageBoxA pMessageBoxAOriginal = NULL;

static int WINAPI
MyMessageBoxA(
        HWND hWnd,
        LPCTSTR lpText,
        LPCTSTR lpCaption,
        UINT uType)
{
    return pMessageBoxAOriginal(hWnd, "hi-ho! :P", lpCaption, uType);
}

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
    fprintf(stderr, lpMsgBuf);
    LocalFree(lpMsgBuf);
}

// }}}
// {{{ _enum_and_replace_import_address_callback()

static BOOL
_enum_and_replace_import_address_callback(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    PIMAGE_THUNK_DATA IAT = NULL;
    DWORD *dwptr;
    DWORD dwbuf;
    DWORD dwOldProtect;
    int i;

    IAT = (PIMAGE_THUNK_DATA)(pe->dwActualImageBase + imp_desc->FirstThunk);
    for (i = 0; 0 != IAT->u1.Function; i++, IAT++) {
        dwbuf = (DWORD)(IAT->u1.Function);
        if ((DWORD)pMessageBoxAOriginal == dwbuf) {
            printf("\tMessageBoxA was detected at 0x%08X\n", (DWORD)IAT);
            printf("\t\tAddress = 0x%08X\n", IAT->u1.Function);
            dwptr = (DWORD*)(&(IAT->u1.Function));
            VirtualProtect(dwptr, sizeof(DWORD), 
                    PAGE_READWRITE, &dwOldProtect);
            *dwptr = (DWORD)MyMessageBoxA;
            VirtualProtect(dwptr, sizeof(FARPROC), 
                    dwOldProtect, &dwOldProtect);
            printf("\t\tRewrited Address = 0x%08X\n", IAT->u1.Function);
        }
    }
    return FALSE;
}

// }}}
// {{{ replace_import_addresses()

static void
replace_import_addresses(void)
{
    HANDLE hModuleSnap;
    MODULEENTRY32 me32;
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err = 0;
    LPVOID lpAppData = NULL;

    // retrieve loaded modules in current process
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (INVALID_HANDLE_VALUE == hModuleSnap) {
        _print_last_error(GetLastError());
        fprintf(stderr, "CreateToolhelp32Snapshot() failed.\n");
        return;
    }

    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "Module32First() failed.\n");
        CloseHandle(hModuleSnap);
        return;
    }

    do {
        printf("Searching Module ... [%s]\n", me32.szModule);
        pe = NULL; err = 0; lpAppData = NULL;
        pe = cheap2el_map_from_loaded_image(me32.modBaseAddr, &err);
        cheap2el_enumerate_import_directory(pe, 
                _enum_and_replace_import_address_callback, lpAppData);
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return;
}

// }}}

BOOL WINAPI DllMain(
        HINSTANCE hInst, DWORD dwReason, LPVOID lpvReserved)
{
    HMODULE hModule;
    DWORD dwPid = GetCurrentProcessId();

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            printf("payload.dll was attached to 0x%08X\n", dwPid);

            // store original function address
            hModule = LoadLibrary("user32.dll");
            pMessageBoxAOriginal = (PMessageBoxA)GetProcAddress(
                    hModule, "MessageBoxA");

            replace_import_addresses();
            break;
        case DLL_PROCESS_DETACH:
            printf("payload.dll was detached from 0x%08X\n", dwPid);
            break;
    }
    return TRUE;
}
