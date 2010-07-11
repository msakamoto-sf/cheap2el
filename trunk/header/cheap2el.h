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
#include <DelayImp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* architecture version */
#define CHEAP2EL_VERSION_MAJOR (1)
/* interface version */
#define CHEAP2EL_VERSION_MINOR (2)
/* implementation version */
#define CHEAP2EL_VERSION_RELEASE (1)

void
cheap2el_version(
        DWORD *major, 
        DWORD *minor, 
        DWORD *release
        );

typedef enum _CHEAP2EL_ERROR_CODE {
    CHEAP2EL_EC_NONE = 0,
    CHEAP2EL_EC_NOT_DOS_HEADER,
    CHEAP2EL_EC_NOT_NT_HEADERS,
    CHEAP2EL_EC_MEMORY_ALLOC,
    CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER,
    CHEAP2EL_EC_LOAD_LIBRARY_FAILURE,
    CHEAP2EL_EC_GET_PROCADDRESS_FAILURE,
    CHEAP2EL_EC_NOT_LIB_SIGNATURE
} CHEAP2EL_ERROR_CODE;

typedef struct _CHEAP2EL_PE_IMAGE {
    DWORD dwActualImageBase;
    DWORD dwPseudoImageBase;
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

typedef struct _CHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG {
        PIMAGE_IMPORT_DESCRIPTOR imp_desc;
        LPCSTR name;
} CHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG, 
    *PCHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG;

typedef struct _CHEAP2EL_IMPORT_ENTRY {
    int order;
    DWORD rvaOfEntryAddress;
    DWORD rvaOfImportByName;
    LPVOID EntryAddress;
    PIMAGE_IMPORT_BY_NAME ImportByName;
    DWORD ImportOrdinal;
    LPCSTR ModuleName;
} CHEAP2EL_IMPORT_ENTRY, *PCHEAP2EL_IMPORT_ENTRY;

typedef BOOL (*CHEAP2EL_ENUM_IMPORT_TABLES_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_import_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_IMPORT_TABLES_CALLBACK cb,
        LPCSTR modulename,
        LPVOID lpApplicationData
        );

typedef BOOL (*CHEAP2EL_ENUM_BOUND_IMPORTS_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid_head,
        PIMAGE_BOUND_FORWARDER_REF bfr_head,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_bound_imports(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_BOUND_IMPORTS_CALLBACK cb,
        LPVOID lpApplicationData
        );

typedef BOOL (*CHEAP2EL_ENUM_DELAY_LOAD_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_delay_load(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_DELAY_LOAD_CALLBACK cb,
        LPVOID lpApplicationData
        );

typedef struct _CHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG {
        PImgDelayDescr imp_dd;
        LPCSTR name;
} CHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG, 
    *PCHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG;

typedef BOOL (*CHEAP2EL_ENUM_DELAYLOAD_TABLES_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_delayload_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_DELAYLOAD_TABLES_CALLBACK cb,
        LPCSTR modulename,
        LPVOID lpApplicationData
        );

typedef struct _CHEAP2EL_BASERELOC_ENTRY {
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PWORD TypeOffset;
    int NumberOfTypeOffset;
} CHEAP2EL_BASERELOC_ENTRY, *PCHEAP2EL_BASERELOC_ENTRY;

typedef BOOL (*CHEAP2EL_ENUM_BASE_RELOCATIONS_CALLBACK)(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_enumerate_base_relocations(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_BASE_RELOCATIONS_CALLBACK cb,
        LPVOID lpApplicationData
        );

BOOL
cheap2el_callback_update_base_relocations(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        );

typedef struct _CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG {
    HANDLE hModule;
    DWORD dwLastError;
    LPVOID lpErrInfo;
    CHEAP2EL_ERROR_CODE err;
} CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG, 
    *PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG;

BOOL
cheap2el_callback_resolve_imports(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        );

BOOL
cheap2el_pseudo_load_address_resolver(
    PCHEAP2EL_PE_IMAGE pe,
    PCHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg
    );

typedef struct _CHEAP2EL_COFF_OBJ {
    DWORD dwBase;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_SECTION_HEADER sectionHeaders;
    PIMAGE_SYMBOL symbolTable;
} CHEAP2EL_COFF_OBJ, *PCHEAP2EL_COFF_OBJ;

PCHEAP2EL_COFF_OBJ
cheap2el_coff_obj_map_from_memory(
        LPVOID lpvMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        );

typedef BOOL (*CHEAP2EL_COFF_OBJ_ENUM_RELOCATION_CALLBACK)(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        PIMAGE_RELOCATION reloc,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_coff_obj_enumerate_relocations(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        CHEAP2EL_COFF_OBJ_ENUM_RELOCATION_CALLBACK cb,
        LPVOID lpApplicationData
        );

typedef BOOL (*CHEAP2EL_COFF_OBJ_ENUM_SYMBOL_CALLBACK)(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SYMBOL symbol,
        char *sz_symname,
        PIMAGE_AUX_SYMBOL aux_head,
        int order,
        LPVOID lpApplicationData
        );

int
cheap2el_coff_obj_enumerate_symbols(
        PCHEAP2EL_COFF_OBJ coff,
        CHEAP2EL_COFF_OBJ_ENUM_SYMBOL_CALLBACK cb,
        LPVOID lpApplicationData
        );

typedef struct _CHEAP2EL_COFF_LIB {
    DWORD dwBase;
    PIMAGE_ARCHIVE_MEMBER_HEADER head;
} CHEAP2EL_COFF_LIB, *PCHEAP2EL_COFF_LIB;

PCHEAP2EL_COFF_LIB
cheap2el_coff_lib_map_from_memory(
        LPVOID lpvMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        );

#ifdef __cplusplus
}
#endif
#endif  /* CHEAP2EL_H */
