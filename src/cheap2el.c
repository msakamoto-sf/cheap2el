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
// {{{ cheap2el_enumerate_import_tables()

static BOOL
_cheap2el_enumerate_import_tables_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);
    PCHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG cbarg = 
        (PCHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG)lpApplicationData;

    if (!stricmp(name, cbarg->name)) {
        cbarg->imp_desc = imp_desc;
        cbarg->name = name;
        return TRUE;
    }
    return FALSE;
}

int
cheap2el_enumerate_import_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_IMPORT_TABLES_CALLBACK cb,
        LPCSTR modulename,
        LPVOID lpApplicationData
        )
{
    CHEAP2EL_IMPORT_ENTRY ie;
    PIMAGE_THUNK_DATA IAT = NULL;
    PIMAGE_THUNK_DATA INT = NULL;
    PIMAGE_IMPORT_BY_NAME INTE = NULL;
    int i;

    CHEAP2EL_ENUMERATE_IMPORT_TABLES_CB_ARG cbarg;
    cbarg.imp_desc = NULL;
    cbarg.name = modulename;

    if (NULL == modulename) {
        return 0;
    }

    cheap2el_enumerate_import_directory(pe, 
            _cheap2el_enumerate_import_tables_cb, 
            (LPVOID)(&cbarg)
            );

    if (NULL == cbarg.imp_desc) {
        return 0;
    }

    ie.ModuleName = cbarg.name;

    IAT = (PIMAGE_THUNK_DATA)
        (cbarg.imp_desc->FirstThunk + pe->dwActualImageBase);
    if (0 != cbarg.imp_desc->OriginalFirstThunk) {
        INT = (PIMAGE_THUNK_DATA)
            (cbarg.imp_desc->OriginalFirstThunk + pe->dwActualImageBase);
    }

    for (i = 0; 0 != IAT->u1.Function; i++, IAT++) {
        ie.order = i;
        ie.rvaOfEntryAddress = (DWORD)IAT - pe->dwActualImageBase;
        ie.EntryAddress = (LPVOID)(IAT->u1.Function);
        ie.rvaOfImportByName = 0;
        ie.ImportByName = NULL;
        ie.ImportOrdinal = 0;
        if (0 != cbarg.imp_desc->OriginalFirstThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(INT->u1.Ordinal)) {
                // import by order
                ie.ImportOrdinal = IMAGE_ORDINAL(INT->u1.Ordinal);
            } else {
                // import by name
                ie.rvaOfImportByName = INT->u1.AddressOfData;
                ie.ImportByName = (PIMAGE_IMPORT_BY_NAME)(INT->u1.AddressOfData + pe->dwActualImageBase);
            }
            INT++;
        }

        if (NULL != cb && cb(pe, cbarg.imp_desc, &ie, lpApplicationData)) {
            i++;
            break;
        }
    }

    return i;
}

// }}}
// {{{ cheap2el_enumerate_bound_imports()

int
cheap2el_enumerate_bound_imports(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_BOUND_IMPORTS_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR bid;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR bid_head;
    PIMAGE_BOUND_FORWARDER_REF bfr_head;
    DWORD dwptr = 0;

    pdd = &(pe->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]);
    if (0 == pdd->VirtualAddress) {
        return 0;
    }

    dwptr = pe->dwActualImageBase + pdd->VirtualAddress;
    bid = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(dwptr);
    bid_head = bid;
    for (result = 0; 0 != bid->TimeDateStamp; bid++, result++) {
        bfr_head = NULL;
        if (0 < bid->NumberOfModuleForwarderRefs) {
            dwptr = (DWORD)bid + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
            bfr_head = (PIMAGE_BOUND_FORWARDER_REF)(dwptr);
        }
        if (NULL != cb && 
                cb(pe, bid_head, bfr_head, bid, result, lpApplicationData)) {
            result++;
            break;
        }
        if (0 < bid->NumberOfModuleForwarderRefs) {
            dwptr = (DWORD)bid;
            dwptr += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
            dwptr += (bid->NumberOfModuleForwarderRefs - 1) * sizeof(IMAGE_BOUND_FORWARDER_REF);
            bid = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(dwptr);
        }
    }
    return result;
}

// }}}
// {{{ cheap2el_enumerate_delay_load()

int
cheap2el_enumerate_delay_load(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_DELAY_LOAD_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PImgDelayDescr imp_dd;
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    DWORD dwptr = 0;

    pdd = &(pe->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
    if (0 == pdd->VirtualAddress) {
        return 0;
    }

    dwptr = pe->dwActualImageBase + pdd->VirtualAddress;
    imp_dd = (ImgDelayDescr*)(dwptr);
    for (result = 0; 0 != imp_dd->rvaHmod; imp_dd++, result++) {
        if (NULL != cb && cb(pe, imp_dd, result, lpApplicationData)) {
            result++;
            break;
        }
    }
    return result;
}

// }}}
// {{{ cheap2el_enumerate_delayload_tables()

static BOOL
_cheap2el_enumerate_delayload_tables_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        int order,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = (LPCSTR)(imp_dd->rvaDLLName + pe->dwActualImageBase);
    PCHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG cbarg = 
        (PCHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG)lpApplicationData;

    if (!stricmp(name, cbarg->name)) {
        cbarg->imp_dd = imp_dd;
        cbarg->name = name;
        return TRUE;
    }
    return FALSE;
}

int
cheap2el_enumerate_delayload_tables(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_DELAYLOAD_TABLES_CALLBACK cb,
        LPCSTR modulename,
        LPVOID lpApplicationData
        )
{
    CHEAP2EL_IMPORT_ENTRY ie;
    PIMAGE_THUNK_DATA IAT = NULL;
    PIMAGE_THUNK_DATA INT = NULL;
    PIMAGE_IMPORT_BY_NAME INTE = NULL;
    int i;

    CHEAP2EL_ENUMERATE_DELAYLOAD_TABLES_CB_ARG cbarg;
    cbarg.imp_dd = NULL;
    cbarg.name = modulename;

    if (NULL == modulename) {
        return 0;
    }

    cheap2el_enumerate_delay_load(pe, 
            _cheap2el_enumerate_delayload_tables_cb, 
            (LPVOID)(&cbarg)
            );

    if (NULL == cbarg.imp_dd) {
        return 0;
    }

    ie.ModuleName = cbarg.name;

    IAT = (PIMAGE_THUNK_DATA)
        (cbarg.imp_dd->rvaIAT + pe->dwActualImageBase);
    if (0 != cbarg.imp_dd->rvaINT) {
        INT = (PIMAGE_THUNK_DATA)
            (cbarg.imp_dd->rvaINT + pe->dwActualImageBase);
    }

    for (i = 0; 0 != IAT->u1.Function; i++, IAT++) {
        ie.order = i;
        ie.rvaOfEntryAddress = (DWORD)IAT - pe->dwActualImageBase;
        ie.EntryAddress = (LPVOID)(IAT->u1.Function);
        ie.rvaOfImportByName = 0;
        ie.ImportByName = NULL;
        ie.ImportOrdinal = 0;
        if (0 != cbarg.imp_dd->rvaINT) {
            if (IMAGE_SNAP_BY_ORDINAL(INT->u1.Ordinal)) {
                // import by order
                ie.ImportOrdinal = IMAGE_ORDINAL(INT->u1.Ordinal);
            } else {
                // import by name
                ie.rvaOfImportByName = INT->u1.AddressOfData;
                ie.ImportByName = (PIMAGE_IMPORT_BY_NAME)(INT->u1.AddressOfData + pe->dwActualImageBase);
            }
            INT++;
        }

        if (NULL != cb && cb(pe, cbarg.imp_dd, &ie, lpApplicationData)) {
            i++;
            break;
        }
    }

    return i;
}

// }}}
// {{{ cheap2el_enumerate_base_relocations()

int
cheap2el_enumerate_base_relocations(
        PCHEAP2EL_PE_IMAGE pe,
        CHEAP2EL_ENUM_BASE_RELOCATIONS_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    PIMAGE_BASE_RELOCATION br;
    CHEAP2EL_BASERELOC_ENTRY bre;
    DWORD br_head, br_tail;
    DWORD dwptr = 0;
    size_t sz_br = sizeof(IMAGE_BASE_RELOCATION);
    size_t sz_to = sizeof(WORD); // TypeOffset

    pdd = &(pe->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    if (0 == pdd->VirtualAddress) {
        return 0;
    }
    br_head = pe->dwActualImageBase + pdd->VirtualAddress;
    br_tail = br_head + pdd->Size;
    br = (PIMAGE_BASE_RELOCATION)(br_head);
    dwptr = br_head;
    for (result = 0; dwptr < br_tail; result++) {
        br = (PIMAGE_BASE_RELOCATION)(dwptr);
        bre.BaseRelocation = br;
        bre.TypeOffset = (PWORD)((DWORD)br + sz_br);
        // calculate number of TypeOffsets
        bre.NumberOfTypeOffset = (br->SizeOfBlock - sz_br) / sz_to;
        if (NULL != cb && 
                cb(pe, &bre, result, lpApplicationData)) {
            result++;
            break;
        }
        dwptr += br->SizeOfBlock;
    }
    return result;
}

// }}}
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
    BOOL isActualUpper = pe->dwActualImageBase > pe->ntHeaders->OptionalHeader.ImageBase;

    // DWORD = "unsigned" long adjustment
    if (isActualUpper) {
        diff = pe->dwActualImageBase - pe->ntHeaders->OptionalHeader.ImageBase;
    } else {
        diff = pe->ntHeaders->OptionalHeader.ImageBase - pe->dwActualImageBase;
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


