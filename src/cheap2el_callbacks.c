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
 * cheap2el : pre-defined callback and short-cut functions
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>

// {{{ cheap2el_callback_update_base_relocations()

BOOL
cheap2el_callback_update_base_relocations(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD dwbuf, diff;
    DWORD *dwptr;
    WORD wbuf, br_type, br_offset;
    int i;
    PWORD tofs = bre->TypeOffset;
    BOOL isActualUpper = pe->dwPseudoImageBase > pe->ntHeaders->OptionalHeader.ImageBase;

    // DWORD = "unsigned" long adjustment
    if (isActualUpper) {
        diff = pe->dwPseudoImageBase - pe->ntHeaders->OptionalHeader.ImageBase;
    } else {
        diff = pe->ntHeaders->OptionalHeader.ImageBase - pe->dwPseudoImageBase;
    }
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        wbuf = *tofs;
        // upper 4bit
        br_type = (0xF000 & wbuf) >> 12;
        br_offset = 0xFF & wbuf;
        switch (br_type) {
            case IMAGE_REL_BASED_HIGHLOW:
                break;
            case IMAGE_REL_BASED_ABSOLUTE:
            default:
                continue;
        }
        dwbuf = pe->dwActualImageBase + bre->BaseRelocation->VirtualAddress + br_offset;
        dwptr = (DWORD*)dwbuf;
        dwbuf = *dwptr;
        if (isActualUpper) {
            dwbuf += diff;
        } else {
            dwbuf -= diff;
        }
        *dwptr = dwbuf;
    }

    return FALSE;
}

// }}}
// {{{ cheap2el_callback_resolve_imports()

static BOOL
_cheap2el_callback_resolve_IAT(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg = 
        (PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG)lpApplicationData;
    int i;

    PDWORD dwptr;
    DWORD dwbuf;

    // effective symbol address
    LPVOID esa = NULL;
    if (0 == imp_entry->rvaOfImportByName) {
        // import by ordinal
        esa = GetProcAddress(
                arg->hModule, 
                MAKEINTRESOURCEA(imp_entry->ImportOrdinal)
                );
    } else {
        // import by name
        esa = GetProcAddress(
                arg->hModule, 
                imp_entry->ImportByName->Name
                );
    }
    if (NULL == esa) {
        arg->dwLastError = GetLastError();
        arg->lpErrInfo = (LPVOID)imp_entry;
        arg->err = CHEAP2EL_EC_GET_PROCADDRESS_FAILURE;
        // stop
        return TRUE;
    }
    dwptr = (PDWORD)(imp_entry->rvaOfEntryAddress + pe->dwActualImageBase);
    *dwptr = (DWORD)esa;

    return FALSE;
}

BOOL
cheap2el_callback_resolve_imports(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    LPCSTR modulename = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);
    PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg = 
        (PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG)lpApplicationData;

    arg->hModule = LoadLibraryA(modulename);
    if (NULL == arg->hModule) {
        arg->dwLastError = GetLastError();
        arg->lpErrInfo = (LPVOID)modulename;
        arg->err = CHEAP2EL_EC_LOAD_LIBRARY_FAILURE;
        return TRUE;
    }

    cheap2el_enumerate_import_tables(pe, 
            _cheap2el_callback_resolve_IAT, modulename, lpApplicationData);
    if (CHEAP2EL_EC_NONE != arg->err) {
        // stop
        return TRUE;
    }
    return FALSE;
}

// }}}
// {{{ cheap2el_pseudo_load_address_resolver()

BOOL
cheap2el_pseudo_load_address_resolver(
    PCHEAP2EL_PE_IMAGE pe,
    PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg
    )
{
    arg->hModule = NULL;
    arg->dwLastError = 0;
    arg->lpErrInfo = NULL;
    arg->err = CHEAP2EL_EC_NONE;

    // update base relocations
    cheap2el_enumerate_base_relocations(pe, 
            cheap2el_callback_update_base_relocations, (LPVOID)NULL);

    // update base relocations
    cheap2el_enumerate_import_directory(pe, 
            cheap2el_callback_resolve_imports, (LPVOID)(arg));

    if (0 != arg->dwLastError) {
        return FALSE;
    }
    return TRUE;
}

// }}}

