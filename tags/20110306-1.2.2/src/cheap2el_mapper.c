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
 * cheap2el : Header, Section, DataDirectory memory map functions
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>

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
    pe->dwPseudoImageBase = (DWORD)lpMemoryBuffer;
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

