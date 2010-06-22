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
 * cheap2el : immplementation
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <string.h>

// {{{ cheap2el_get_sizeofimage_from_file()

BOOL
cheap2el_get_sizeofimage_from_file(
        LPVOID lpFileBuffer,
        DWORD *dwSizeOfImage,
        DWORD *dwSizeOfHeader,
        CHEAP2EL_ERROR_CODE *err
        )
{
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_NT_HEADERS nt_header = NULL;
    DWORD dwptr1 = 0;
    DWORD dwptr2 = 0;

    dos_header = (PIMAGE_DOS_HEADER)lpFileBuffer;
    if (IMAGE_DOS_SIGNATURE != dos_header->e_magic) {
        *err = CHEAP2EL_EC_NOT_DOS_HEADER;
        return FALSE;
    }
    dwptr1 = (DWORD)dos_header;
    dwptr2 = dwptr1 + dos_header->e_lfanew;
    nt_header = (PIMAGE_NT_HEADERS)(dwptr2);
    if (IMAGE_NT_SIGNATURE != nt_header->Signature) {
        *err = CHEAP2EL_EC_NOT_NT_HEADERS;
        return FALSE;
    }

    *dwSizeOfImage = nt_header->OptionalHeader.SizeOfImage;
    *dwSizeOfHeader = nt_header->OptionalHeader.SizeOfHeaders;
    return TRUE;
}

// }}}
// {{{ _cheap2el_copy_section_data()

static void
_cheap2el_copy_section_data(
        LPVOID lpBaseSrc,
        LPVOID lpBaseDst,
        PCHEAP2EL_PE_IMAGE pe)
{
    int i;
    DWORD src, dst;
    size_t sz;
    PIMAGE_SECTION_HEADER cursor = pe->sectionHeaders;

    for (i = 0; 
            i < pe->ntHeaders->FileHeader.NumberOfSections; 
            i++, cursor++) {
        src = (DWORD)(lpBaseSrc) + cursor->PointerToRawData;
        dst = (DWORD)(lpBaseDst) + cursor->VirtualAddress;
        sz = cursor->SizeOfRawData;
        CopyMemory((LPVOID)(dst), (LPVOID)(src), sz);
    }
}

// }}}
// {{{ _cheap2el_map_headers_from_memory()

static PCHEAP2EL_PE_IMAGE
_cheap2el_map_headers_from_memory(
        LPVOID lpMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        )
{
    DWORD dwptr1 = 0;
    DWORD dwptr2 = 0;

    PCHEAP2EL_PE_IMAGE pe = NULL;
    pe = GlobalAlloc(GMEM_ZEROINIT, sizeof(CHEAP2EL_PE_IMAGE));
    if (NULL == pe) {
        *err = CHEAP2EL_EC_MEMORY_ALLOC;
        return NULL;
    }

    pe->dwActualImageBase = (DWORD)lpMemoryBuffer;
    pe->dosHeader = (PIMAGE_DOS_HEADER)lpMemoryBuffer;
    dwptr1 = (DWORD)(pe->dosHeader);
    dwptr2 = dwptr1 + sizeof(IMAGE_DOS_HEADER);
    pe->lpDosStubAddress = (LPVOID)dwptr2;

    dwptr2 = dwptr1 + pe->dosHeader->e_lfanew;
    pe->ntHeaders = (PIMAGE_NT_HEADERS)dwptr2;
    pe->dwSizeOfDosStub = pe->dosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);

    dwptr2 = dwptr1 + pe->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    pe->sectionHeaders = (PIMAGE_SECTION_HEADER)dwptr2;

    return pe;
}

// }}}
// {{{ cheap2el_map_to_memory()

PCHEAP2EL_PE_IMAGE
cheap2el_map_to_memory(
        LPVOID lpFileBuffer,
        LPVOID lpMemoryBuffer,
        size_t nSizeOfMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        )
{
    DWORD dwSizeOfImage;
    DWORD dwSizeOfHeader;
    PCHEAP2EL_PE_IMAGE pe = NULL;

    if (NULL == lpMemoryBuffer) {
        *err = CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER;
        return NULL;
    }

    if (!cheap2el_get_sizeofimage_from_file(
                lpFileBuffer, &dwSizeOfImage, &dwSizeOfHeader, err)) {
        return NULL;
    }

    if (nSizeOfMemoryBuffer < dwSizeOfImage) {
        *err = CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER;
        return NULL;
    }

    CopyMemory(
            lpMemoryBuffer, 
            lpFileBuffer, 
            dwSizeOfHeader
            );

    pe = _cheap2el_map_headers_from_memory(lpMemoryBuffer, err);
    if (NULL == pe) {
        return NULL;
    }

    _cheap2el_copy_section_data(lpFileBuffer, lpMemoryBuffer, pe);

    return pe;
}

// }}}
// {{{ cheap2el_map_from_loaded_image()

PCHEAP2EL_PE_IMAGE
cheap2el_map_from_loaded_image(
        LPVOID lpMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        )
{
    DWORD dwSizeOfImage;
    DWORD dwSizeOfHeader;
    PCHEAP2EL_PE_IMAGE pe = NULL;

    if (NULL == lpMemoryBuffer) {
        *err = CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER;
        return NULL;
    }

    if (!cheap2el_get_sizeofimage_from_file(
                lpMemoryBuffer, &dwSizeOfImage, &dwSizeOfHeader, err)) {
        return NULL;
    }

    pe = _cheap2el_map_headers_from_memory(lpMemoryBuffer, err);
    if (NULL == pe) {
        return NULL;
    }

    return pe;
}

// }}}
// {{{ cheap2el_get_export_directory()

PIMAGE_EXPORT_DIRECTORY
cheap2el_get_export_directory(
        PCHEAP2EL_PE_IMAGE pe
        )
{
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    DWORD dwptr = 0;

    pdd = &(pe->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (0 == pdd->VirtualAddress) {
        return NULL;
    }

    dwptr = pe->dwActualImageBase + pdd->VirtualAddress;
    return (PIMAGE_EXPORT_DIRECTORY)(dwptr);
}

// }}}
// {{{ _cheap2el_export_is_forwarded()

static BOOL
_cheap2el_export_is_forwarded(
        PCHEAP2EL_PE_IMAGE pe, DWORD ed_rva, DWORD func_rva)
{
    int i;
    DWORD rva_min, rva_max;
    PIMAGE_SECTION_HEADER cursor = pe->sectionHeaders;

    for (i = 0; 
            i < pe->ntHeaders->FileHeader.NumberOfSections; 
            i++, cursor++) {
        // section rva range
        rva_min = cursor->VirtualAddress;
        rva_max = cursor->VirtualAddress + cursor->Misc.VirtualSize - 1;
        if ((rva_min <= ed_rva && ed_rva <= rva_max) &&
                (rva_min <= func_rva && func_rva <= rva_max)) {
            return TRUE;
        }
    }
    return FALSE;
}

// }}}
// {{{ cheap2el_enumerate_export_tables()

void
cheap2el_enumerate_export_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_EXPORT_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    PIMAGE_EXPORT_DIRECTORY ed;
    CHEAP2EL_EXPORT_ENTRY ee;
    DWORD *EFT;
    DWORD *ENT;
    WORD *EOT;
    int i, j;
    DWORD dwOrdinal;
    ed = cheap2el_get_export_directory(pe);
    if (NULL == ed) {
        return;
    }

    EFT = (DWORD*)(pe->dwActualImageBase + ed->AddressOfFunctions);
    ENT = (DWORD*)(pe->dwActualImageBase + ed->AddressOfNames);
    EOT = (WORD*)(pe->dwActualImageBase + ed->AddressOfNameOrdinals);
    for (i = 0; i < ed->NumberOfFunctions; i++) {
        ZeroMemory(&ee, sizeof(CHEAP2EL_EXPORT_ENTRY ));
        ee.order = i;
        ee.rvaOfFunction = EFT[i];
        ee.AddressOfFunction = (DWORD)(&(EFT[i]));

        if(_cheap2el_export_is_forwarded(
                pe, ((DWORD)ed - pe->dwActualImageBase), EFT[i])) {
            ee.isForwarded = TRUE;
            ee.ForwardedName = (LPCSTR)(EFT[i] + pe->dwActualImageBase);
        } else {
            ee.Function = (LPVOID)(EFT[i] + pe->dwActualImageBase);
        }

        for (j = 0; j < ed->NumberOfNames; j++) {
            dwOrdinal = EOT[j];
            if (i == dwOrdinal) {
                ee.hint = j;
                ee.AddressOfName = (DWORD)(&(ENT[j]));
                ee.AddressOfOrdinal = (DWORD)(&(EOT[j]));
                ee.rvaOfName = ENT[j];
                ee.Name = (LPCSTR)(ee.rvaOfName + pe->dwActualImageBase);
                ee.Ordinal = dwOrdinal + ed->Base;
                break;
            }
        }

        if (cb(pe, ed, &ee, lpApplicationData)) {
            return;
        }
    }
}

// }}}
// {{{ cheap2el_get_export_rva_by_name()

static BOOL
_cheap2el_get_export_rva_by_name_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    PCHEAP2EL_GET_EXPORT_RVA_BY_ARG arg = 
        (PCHEAP2EL_GET_EXPORT_RVA_BY_ARG)lpApplicationData;
    if (0 != ee->rvaOfName && !ee->isForwarded) {
        if (!strcmp(ee->Name, arg->By.Name)) {
            arg->rva = ee->rvaOfFunction;
            return TRUE;
        }
    }
    return FALSE;
}

DWORD
cheap2el_get_export_rva_by_name(PCHEAP2EL_PE_IMAGE pe, LPCSTR name)
{

    CHEAP2EL_GET_EXPORT_RVA_BY_ARG arg;
    arg.By.Name = name;
    arg.rva = 0;
    cheap2el_enumerate_export_tables(pe,
            _cheap2el_get_export_rva_by_name_cb,
            (LPVOID)(&arg)
            );
    return arg.rva;
}

// }}}
// {{{ cheap2el_get_export_rva_by_ordinal()

static BOOL
_cheap2el_get_export_rva_by_ordinal_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    PCHEAP2EL_GET_EXPORT_RVA_BY_ARG arg = 
        (PCHEAP2EL_GET_EXPORT_RVA_BY_ARG)lpApplicationData;
    if (0 != ee->rvaOfName && !ee->isForwarded) {
        if (ee->Ordinal == arg->By.Ordinal) {
            arg->rva = ee->rvaOfFunction;
            return TRUE;
        }
    }
    return FALSE;
}

DWORD
cheap2el_get_export_rva_by_ordinal(PCHEAP2EL_PE_IMAGE pe, DWORD ordinal)
{

    CHEAP2EL_GET_EXPORT_RVA_BY_ARG arg;
    arg.By.Ordinal = ordinal;
    arg.rva = 0;
    cheap2el_enumerate_export_tables(pe,
            _cheap2el_get_export_rva_by_ordinal_cb,
            (LPVOID)(&arg)
            );
    return arg.rva;
}

// }}}
// {{{ cheap2el_enumerate_import_directory()

int
cheap2el_enumerate_import_directory(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_IMPORT_DIRECTORY_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PIMAGE_IMPORT_DESCRIPTOR imp_desc;
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    DWORD dwptr = 0;

    pdd = &(pe->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (0 == pdd->VirtualAddress) {
        return 0;
    }

    dwptr = pe->dwActualImageBase + pdd->VirtualAddress;
    imp_desc = (PIMAGE_IMPORT_DESCRIPTOR)(dwptr);
    for (result = 0; 0 != imp_desc->FirstThunk; imp_desc++, result++) {
        if (NULL != cb && cb(pe, imp_desc, result, lpApplicationData)) {
            result++;
            break;
        }
    }
    return result;
}

// }}}



