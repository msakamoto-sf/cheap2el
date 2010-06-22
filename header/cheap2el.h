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
 * header file for cheap2el
 *
 * $Id$
 */

#ifndef CHEAP2EL_H
#define CHEAP2EL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _CHEAP2EL_ERROR_CODE {
    CHEAP2EL_EC_NOT_DOS_HEADER = 0,
    CHEAP2EL_EC_NOT_NT_HEADERS,
    CHEAP2EL_EC_MEMORY_ALLOC,
    CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER
} CHEAP2EL_ERROR_CODE;

typedef struct _CHEAP2EL_PE_IMAGE {
    DWORD dwActualImageBase;
    PIMAGE_DOS_HEADER dosHeader;
    LPVOID lpDosStubAddress;
    DWORD dwSizeOfDosStub;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeaders;
} CHEAP2EL_PE_IMAGE, *PCHEAP2EL_PE_IMAGE;

BOOL
cheap2el_get_sizeofimage_from_file(
        LPVOID lpFileBuffer,
        DWORD *dwSizeOfImage,
        DWORD *dwSizeOfHeader,
        CHEAP2EL_ERROR_CODE *err
        );

PCHEAP2EL_PE_IMAGE
cheap2el_map_to_memory(
        LPVOID lpFileBuffer,
        LPVOID lpMemoryBuffer,
        size_t nSizeOfMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        );

PCHEAP2EL_PE_IMAGE
cheap2el_map_from_loaded_image(
        LPVOID lpMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        );

PIMAGE_EXPORT_DIRECTORY
cheap2el_get_export_directory(
        PCHEAP2EL_PE_IMAGE pe
        );

typedef struct _CHEAP2EL_EXPORT_ENTRY {
    int order;
    int hint;
    DWORD rvaOfFunction;
    DWORD rvaOfName;
    DWORD AddressOfFunction;
    DWORD AddressOfName;
    DWORD AddressOfOrdinal;
    LPVOID Function;
    LPCSTR Name;
    WORD Ordinal;
    BOOL isForwarded;
    LPCSTR ForwardedName;
} CHEAP2EL_EXPORT_ENTRY, *PCHEAP2EL_EXPORT_ENTRY;

typedef BOOL (*CHEAP2EL_ENUM_EXPORT_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        );

void
cheap2el_enumerate_export_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_EXPORT_CALLBACK cb,
        LPVOID lpApplicationData
        );

typedef struct _CHEAP2EL_GET_EXPORT_RVA_BY_ARG {
    union {
        LPCSTR Name;
        DWORD Ordinal;
    } By;
    DWORD rva;
} CHEAP2EL_GET_EXPORT_RVA_BY_ARG, *PCHEAP2EL_GET_EXPORT_RVA_BY_ARG;

DWORD
cheap2el_get_export_rva_by_name(
        PCHEAP2EL_PE_IMAGE pe, 
        LPCSTR name
        );

DWORD
cheap2el_get_export_rva_by_ordinal(
        PCHEAP2EL_PE_IMAGE pe, 
        DWORD ordinal
        );

typedef BOOL (*CHEAP2EL_ENUM_IMPORT_DIRECTORY_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_import_directory(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_IMPORT_DIRECTORY_CALLBACK cb,
        LPVOID lpApplicationData
        );

int
cheap2el_update_rebase_info(
        PCHEAP2EL_PE_IMAGE pei
        );

int
cheap2el_resolve_iat(
        PCHEAP2EL_PE_IMAGE pei
        );


#ifdef __cplusplus
}
#endif
#endif  /* CHEAP2EL_H */
