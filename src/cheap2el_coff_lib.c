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
 * cheap2el : COFF Library file functions
 *
 * $Id: cheap2el_coff_obj.c 33 2010-07-09 14:26:53Z sakamoto.gsyc.3s@gmail.com $
 */

#include "cheap2el.h"
#include <windows.h>

// {{{ cheap2el_coff_lib_map_from_memory()

PCHEAP2EL_COFF_LIB
cheap2el_coff_lib_map_from_memory(
        LPVOID lpvMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        )
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    PIMAGE_ARCHIVE_MEMBER_HEADER am_head = NULL;
    char *signature = NULL;
    DWORD dwptr1, dwptr2;

    if (NULL == lpvMemoryBuffer) {
        *err = CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER;
        return NULL;
    }

    lib = GlobalAlloc(GMEM_ZEROINIT, sizeof(CHEAP2EL_COFF_LIB));
    if (NULL == lib) {
        *err = CHEAP2EL_EC_MEMORY_ALLOC;
        return NULL;
    }

    lib->dwBase = (DWORD)lpvMemoryBuffer;
    signature = (char*)lpvMemoryBuffer;
    if (strcmp(IMAGE_ARCHIVE_START, signature)) {
        *err = CHEAP2EL_EC_NOT_LIB_SIGNATURE;
        return NULL;
    }
    dwptr1 = lib->dwBase + IMAGE_ARCHIVE_START_SIZE;
    am_head = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr1;
    return lib;
}

// }}}
// {{{ cheap2el_coff_lib_enumerate_relocations()

int
cheap2el_coff_lib_enumerate_relocations(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        CHEAP2EL_COFF_OBJ_ENUM_RELOCATION_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PIMAGE_RELOCATION reloc = NULL;
    DWORD dwptr = 0;

    if (NULL == cb) {
        return 0;
    }

    dwptr = coff->dwBase + sect->PointerToRelocations;
    reloc = (PIMAGE_RELOCATION)dwptr;
    for (result = 0;
            result != sect->NumberOfRelocations;
            result++, reloc++) {
        if (NULL != cb && 
                cb(coff, sect, reloc, result, lpApplicationData)) {
            result++;
            break;
        }
    }
    return result;
}

// }}}
// {{{ cheap2el_coff_lib_enumerate_symbols()

int
cheap2el_coff_lib_enumerate_symbols(
        PCHEAP2EL_COFF_OBJ coff,
        CHEAP2EL_COFF_OBJ_ENUM_SYMBOL_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int sym_cnt, result, i;
    PIMAGE_SYMBOL symbol = NULL;
    PIMAGE_AUX_SYMBOL aux_head = NULL;
    DWORD dwptr = 0, dwbuf = 0;
    DWORD dwStringTable;
    char sz_symname[9];
    char *symname;

    if (NULL == cb) {
        return 0;
    }

    dwptr = coff->dwBase + coff->fileHeader->PointerToSymbolTable;
    symbol = (PIMAGE_SYMBOL)dwptr;
    dwStringTable = dwptr + 
        sizeof(IMAGE_SYMBOL) * coff->fileHeader->NumberOfSymbols;
    sym_cnt = 0;
    result = 0;
    while (sym_cnt < coff->fileHeader->NumberOfSymbols) {
        aux_head = NULL;
        ZeroMemory(sz_symname, 9);
        if (0 != symbol->N.Name.Short) {
            strncpy(sz_symname, symbol->N.ShortName, 8);
            symname = sz_symname;
        } else {
            dwptr = symbol->N.Name.Long + dwStringTable;
            symname = (char*)dwptr;
        }
        if (0 != symbol->NumberOfAuxSymbols) {
            dwptr = (DWORD)symbol + sizeof(IMAGE_SYMBOL);
            aux_head = (PIMAGE_AUX_SYMBOL)dwptr;
        }
        if (NULL != cb && 
                cb(coff, symbol, symname, aux_head, result, lpApplicationData)) {
            result++;
            break;
        }
        result++;
        dwbuf = symbol->NumberOfAuxSymbols;
        symbol++;
        sym_cnt++;
        for (i = 0; i < dwbuf; i++, symbol++, sym_cnt++);
    }
    return result;
}

// }}}

