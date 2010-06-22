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
 * cheap2el : CUnit tests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"

// {{{ _hexdump()

static void
_hexdump(DWORD addr, int len)
{
    int i, r;
    unsigned char *p = (unsigned char*)addr;
    for (i = 0, r = 0; i < len; i++, r++, p++) {
        printf("%02X ", *p);
        if (15 == r) {
            printf("\n");
            r = -1;
        }
    }
}

// }}}
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
// {{{ _load_test_data()

static LPVOID
_load_test_data(LPCTSTR lpFileName)
{
    HANDLE hFile;
    DWORD datalen;
    DWORD readlen;
    LPVOID membuf = NULL;
    hFile = CreateFile(
            lpFileName, 
            GENERIC_READ, 
            0,
            NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        _print_last_error(GetLastError());
        return NULL;
    }
    datalen = GetFileSize(hFile, NULL);
    if (INVALID_FILE_SIZE == datalen) {
        _print_last_error(GetLastError());
        return NULL;
    }
    membuf = (LPVOID)GlobalAlloc(GMEM_ZEROINIT, datalen);
    if (NULL == membuf) {
        _print_last_error(GetLastError());
        return NULL;
    }
    if (!ReadFile(hFile, membuf, datalen, &readlen, NULL)) {
        GlobalFree(membuf);
        _print_last_error(GetLastError());
        return NULL;
    }
    CloseHandle(hFile);
    return membuf;
}

// }}}
// {{{ test_get_sizeofimage_from_file()

void test_get_sizeofimage_from_file(void)
{
    LPVOID lpFileBuffer = NULL;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;
    BOOL r;

    // {{{ pe_not_mz.dat

    lpFileBuffer = _load_test_data("pe_not_mz.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    r = cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    CU_ASSERT_FALSE(r);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_DOS_HEADER);
    GlobalFree(lpFileBuffer);

    // }}}
    // {{{ pe_not_nt.dat

    lpFileBuffer = _load_test_data("pe_not_nt.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    r = cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    CU_ASSERT_FALSE(r);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_NT_HEADERS);
    GlobalFree(lpFileBuffer);

    // }}}
    // {{{ pe_normal32.dat

    lpFileBuffer = _load_test_data("pe_normal32.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    r = cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    CU_ASSERT_TRUE(r);
    CU_ASSERT_EQUAL(sz_image, 0xD000);
    CU_ASSERT_EQUAL(sz_header, 0x400);
    GlobalFree(lpFileBuffer);

    // }}}
}

// }}}
// {{{ test_map_to_memory_failure()

void test_map_to_memory_failure(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    LPVOID lpFileBuffer = NULL;
    LPVOID lpMemoryBuffer = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;

    // {{{ lpMemoryBuffer == NULL

    lpFileBuffer = _load_test_data("pe_not_mz.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    pe = cheap2el_map_to_memory(
            lpFileBuffer, NULL, nLen, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER);
    GlobalFree(lpFileBuffer);

    // }}}

    nLen = 10;
    lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);

    // {{{ pe_not_mz.dat

    lpFileBuffer = _load_test_data("pe_not_mz.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_DOS_HEADER);
    GlobalFree(lpFileBuffer);

    // }}}
    // {{{ pe_not_nt.dat

    lpFileBuffer = _load_test_data("pe_not_nt.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_NT_HEADERS);
    GlobalFree(lpFileBuffer);

    // }}}

    GlobalFree(lpMemoryBuffer);

    // {{{ pe_normal32.dat : lack of memory

    lpFileBuffer = _load_test_data("pe_normal32.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    nLen = sz_image - 1;
    lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER);
    GlobalFree(lpFileBuffer);
    GlobalFree(lpMemoryBuffer);

    // }}}
}

// }}}
// {{{ test_map_to_memory_success()

void test_map_to_memory_success(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    LPVOID lpFileBuffer = NULL;
    LPVOID lpMemoryBuffer = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_NT_HEADERS nt_headers = NULL;
    PIMAGE_FILE_HEADER file_header = NULL;
    PIMAGE_OPTIONAL_HEADER opt_header = NULL;
    PIMAGE_DATA_DIRECTORY ddptr;
    PIMAGE_SECTION_HEADER cursor = NULL;

    // pe_normal32.dat : shoud result no error

    lpFileBuffer = _load_test_data("pe_normal32.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    nLen = sz_image;
    lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);
    CU_ASSERT_PTR_NOT_NULL(pe);

    CU_ASSERT_EQUAL(((DWORD)lpMemoryBuffer), pe->dwActualImageBase);
    CU_ASSERT_EQUAL(pe->dosHeader->e_magic, IMAGE_DOS_SIGNATURE);
    CU_ASSERT_EQUAL(pe->dosHeader->e_lfanew, 0xE0);
    CU_ASSERT_EQUAL(((DWORD)pe->lpDosStubAddress), 
            pe->dwActualImageBase + sizeof(IMAGE_DOS_HEADER));
    CU_ASSERT_EQUAL(pe->dwSizeOfDosStub, 0xA0);

    // IMAGE_NT_HEADERS
    nt_headers = pe->ntHeaders;
    CU_ASSERT_EQUAL(nt_headers->Signature, IMAGE_NT_SIGNATURE);
    CU_ASSERT_EQUAL(nt_headers->FileHeader.Machine, IMAGE_FILE_MACHINE_I386);

    // IMAGE_FILE_HEADER
    file_header = &(nt_headers->FileHeader);
    CU_ASSERT_EQUAL(file_header->NumberOfSections, 4);
    CU_ASSERT_EQUAL(file_header->SizeOfOptionalHeader, 0xE0);
    CU_ASSERT_EQUAL(file_header->Characteristics, 
            IMAGE_FILE_RELOCS_STRIPPED | 
            IMAGE_FILE_EXECUTABLE_IMAGE | 
            IMAGE_FILE_32BIT_MACHINE
            );

    // IMAGE_OPTIONAL_HEADER
    opt_header = &(nt_headers->OptionalHeader);
    CU_ASSERT_EQUAL(opt_header->Magic, IMAGE_NT_OPTIONAL_HDR_MAGIC);
    CU_ASSERT_EQUAL(opt_header->AddressOfEntryPoint, 0x1421);
    CU_ASSERT_EQUAL(opt_header->ImageBase, 0x400000);
    CU_ASSERT_EQUAL(opt_header->SectionAlignment, 0x1000);
    CU_ASSERT_EQUAL(opt_header->FileAlignment, 0x200);
    CU_ASSERT_EQUAL(opt_header->SizeOfImage, 0xD000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeaders, 0x400);
    CU_ASSERT_EQUAL(opt_header->Subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    // IMAGE_DATA_DIRECTORY
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x9594);
    CU_ASSERT_EQUAL(ddptr->Size, 0x3C);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0xC000);
    CU_ASSERT_EQUAL(ddptr->Size, 0xF0);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x9298);
    CU_ASSERT_EQUAL(ddptr->Size, 0x40);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x8000);
    CU_ASSERT_EQUAL(ddptr->Size, 0x118);

    // IMAGE_SECTION_HEADER
    //      #1
    cursor = &(pe->sectionHeaders[0]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".text");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x6404);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x1000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x6600);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x400);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_EXECUTE |
            IMAGE_SCN_MEM_READ
            );
    //      #2
    cursor = &(pe->sectionHeaders[1]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".rdata");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x1BD2);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x8000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x1C00);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x6A00);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
            );
    //      #3
    cursor = &(pe->sectionHeaders[2]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".data");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x1860);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0xA000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0xE00);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x8600);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE
            );
    //      #4
    cursor = &(pe->sectionHeaders[3]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".rsrc");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0xF0);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0xC000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x200);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x9400);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
            );

    GlobalFree(pe);
    GlobalFree(lpFileBuffer);
    GlobalFree(lpMemoryBuffer);
}

// }}}
// {{{ test_map_from_loaded_image_failure()

void test_map_from_loaded_image_failure(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    LPVOID lpFileBuffer = NULL;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;

    // {{{ lpMemoryBuffer == NULL

    pe = cheap2el_map_from_loaded_image(NULL, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER);
    GlobalFree(lpFileBuffer);

    // }}}
    // {{{ pe_not_mz.dat

    lpFileBuffer = _load_test_data("pe_not_mz.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    pe = cheap2el_map_from_loaded_image(lpFileBuffer, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_DOS_HEADER);
    GlobalFree(lpFileBuffer);

    // }}}
    // {{{ pe_not_nt.dat

    lpFileBuffer = _load_test_data("pe_not_nt.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    pe = cheap2el_map_from_loaded_image(lpFileBuffer, &err);
    CU_ASSERT_PTR_NULL(pe);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_NT_HEADERS);
    GlobalFree(lpFileBuffer);

    // }}}
}

// }}}
// {{{ test_map_from_loaded_image_success()

void test_map_from_loaded_image_success(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_NT_HEADERS nt_headers = NULL;
    PIMAGE_FILE_HEADER file_header = NULL;
    PIMAGE_OPTIONAL_HEADER opt_header = NULL;
    PIMAGE_DATA_DIRECTORY ddptr;
    PIMAGE_SECTION_HEADER cursor = NULL;
    HANDLE hModule = NULL;

    hModule = LoadLibrary("pe_normal32_entry.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    CU_ASSERT_PTR_NOT_NULL(pe);

    CU_ASSERT_EQUAL(((DWORD)hModule), pe->dwActualImageBase);
    CU_ASSERT_EQUAL(pe->dosHeader->e_magic, IMAGE_DOS_SIGNATURE);
    CU_ASSERT_EQUAL(pe->dosHeader->e_lfanew, 0xE8);
    CU_ASSERT_EQUAL(((DWORD)pe->lpDosStubAddress), 
            pe->dwActualImageBase + sizeof(IMAGE_DOS_HEADER));
    CU_ASSERT_EQUAL(pe->dwSizeOfDosStub, 0xA8);

    // IMAGE_NT_HEADERS
    nt_headers = pe->ntHeaders;
    CU_ASSERT_EQUAL(nt_headers->Signature, IMAGE_NT_SIGNATURE);
    CU_ASSERT_EQUAL(nt_headers->FileHeader.Machine, IMAGE_FILE_MACHINE_I386);

    // IMAGE_FILE_HEADER
    file_header = &(nt_headers->FileHeader);
    CU_ASSERT_EQUAL(file_header->NumberOfSections, 5);
    CU_ASSERT_EQUAL(file_header->SizeOfOptionalHeader, 0xE0);
    CU_ASSERT_EQUAL(file_header->Characteristics, 
            IMAGE_FILE_DLL | 
            IMAGE_FILE_EXECUTABLE_IMAGE | 
            IMAGE_FILE_32BIT_MACHINE
            );

    // IMAGE_OPTIONAL_HEADER
    opt_header = &(nt_headers->OptionalHeader);
    CU_ASSERT_EQUAL(opt_header->Magic, IMAGE_NT_OPTIONAL_HDR_MAGIC);
    CU_ASSERT_EQUAL(opt_header->AddressOfEntryPoint, 0x1343);
    CU_ASSERT_EQUAL(opt_header->ImageBase, 0x10000000);
    CU_ASSERT_EQUAL(opt_header->SectionAlignment, 0x1000);
    CU_ASSERT_EQUAL(opt_header->FileAlignment, 0x200);
    CU_ASSERT_EQUAL(opt_header->SizeOfImage, 0xE000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeaders, 0x400);
    CU_ASSERT_EQUAL(opt_header->Subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    // IMAGE_DATA_DIRECTORY
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x9AD0);
    CU_ASSERT_EQUAL(ddptr->Size, 0xCF);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x955C);
    CU_ASSERT_EQUAL(ddptr->Size, 0x28);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0xC000);
    CU_ASSERT_EQUAL(ddptr->Size, 0xA0);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0xD000);
    CU_ASSERT_EQUAL(ddptr->Size, 0x6F4);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x9268);
    CU_ASSERT_EQUAL(ddptr->Size, 0x40);
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x8000);
    CU_ASSERT_EQUAL(ddptr->Size, 0xF0);

    // IMAGE_SECTION_HEADER
    //      #1
    cursor = &(pe->sectionHeaders[0]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".text");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x6454);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x1000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x6600);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x400);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_EXECUTE |
            IMAGE_SCN_MEM_READ
            );
    //      #2
    cursor = &(pe->sectionHeaders[1]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".rdata");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x1B9F);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x8000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x1C00);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x6A00);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
            );
    //      #3
    cursor = &(pe->sectionHeaders[2]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".data");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x18BC);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0xA000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0xE00);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x8600);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE
            );
    //      #4
    cursor = &(pe->sectionHeaders[3]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".rsrc");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0xA0);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0xC000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x200);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x9400);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
            );
    //      #5
    cursor = &(pe->sectionHeaders[4]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".reloc");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0xC50);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0xD000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0xE00);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x9600);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_DISCARDABLE |
            IMAGE_SCN_MEM_READ
            );

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_get_export_directory_failure()

void test_get_export_directory_failure(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    LPVOID lpFileBuffer = NULL;
    LPVOID lpMemoryBuffer = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;

    lpFileBuffer = _load_test_data("pe_normal32.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    nLen = sz_image;
    lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);
    ed = cheap2el_get_export_directory(pe);
    CU_ASSERT_PTR_NULL(ed);

    GlobalFree(pe);
    GlobalFree(lpFileBuffer);
    GlobalFree(lpMemoryBuffer);
}

// }}}
// {{{ test_get_export_directory_success()

void test_get_export_directory_success(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;

    hModule = LoadLibrary("pe_normal32_entry.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }
    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    ed = cheap2el_get_export_directory(pe);

    CU_ASSERT_EQUAL(ed->Characteristics, 0x0);
    CU_ASSERT_EQUAL(ed->Base, 5);
    CU_ASSERT_EQUAL(ed->NumberOfFunctions, 11);
    CU_ASSERT_EQUAL(ed->NumberOfNames, 9);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_enumerate_export_tables_0()

static BOOL
_test_enumerate_export_tables_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_export_tables_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    LPVOID lpFileBuffer = NULL;
    LPVOID lpMemoryBuffer = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    DWORD indicator = 0;

    lpFileBuffer = _load_test_data("pe_normal32.dat");
    if (NULL == lpFileBuffer) {
        CU_FAIL("memory error");
        return;
    }
    cheap2el_get_sizeofimage_from_file(
            lpFileBuffer, &sz_image, &sz_header, &err);
    nLen = sz_image;
    lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);
    pe = cheap2el_map_to_memory(
            lpFileBuffer, lpMemoryBuffer, nLen, &err);

    cheap2el_enumerate_export_tables(pe, 
            _test_enumerate_export_tables_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(indicator);

    GlobalFree(pe);
    GlobalFree(lpFileBuffer);
    GlobalFree(lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_export_tables()

static BOOL
_test_enumerate_export_tables_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    CHEAP2EL_EXPORT_ENTRY expected[11] = {
        {0, 3, 0x00001050, 0x00009B7B, 0x10009AF8, 0x10009B30, 0x10009B4E, 
            (LPVOID)0x10001050, "func2", 0x00000005, 0, NULL},
        {1, 0, 0x00001060, 0x00000000, 0x10009AFC, 0x00000000, 0x00000000, 
            (LPVOID)0x10001060, NULL, 0x00000000, 0, NULL},
        {2, 4, 0x00001070, 0x00009B81, 0x10009B00, 0x10009B34, 0x10009B50, 
            (LPVOID)0x10001070, "func4", 0x00000007, 0, NULL},
        {3, 0, 0x00001080, 0x00000000, 0x10009B04, 0x00000000, 0x00000000, 
            (LPVOID)0x10001080, NULL, 0x00000000, 0, NULL},
        {4, 0, 0x00001020, 0x00009B6D, 0x10009B08, 0x10009B24, 0x10009B48, 
            (LPVOID)0x10001020, "bar", 0x00000009, 0, NULL},
        {5, 1, 0x00001000, 0x00009B71, 0x10009B0C, 0x10009B28, 0x10009B4A, 
            (LPVOID)0x10001000, "foo", 0x0000000A, 0, NULL},
        {6, 2, 0x00001040, 0x00009B75, 0x10009B10, 0x10009B2C, 0x10009B4C, 
            (LPVOID)0x10001040, "func1", 0x0000000B, 0, NULL},
        {7, 5, 0x00001090, 0x00009B87, 0x10009B14, 0x10009B38, 0x10009B52, 
            (LPVOID)0x10001090, "funcX", 0x0000000C, 0, NULL},
        {8, 6, 0x000010A0, 0x00009B8D, 0x10009B18, 0x10009B3C, 0x10009B54, 
            (LPVOID)0x100010A0, "funcY", 0x0000000D, 0, NULL},
        {9, 7, 0x0000A000, 0x00009B93, 0x10009B1C, 0x10009B40, 0x10009B56, 
            (LPVOID)0x1000A000, "varsA", 0x0000000E, 0, NULL},
        {10, 8, 0x0000A004, 0x00009B99, 0x10009B20, 0x10009B44, 0x10009B58, 
            (LPVOID)0x1000A004, "varsB", 0x0000000F, 0, NULL}
    };
    DWORD *p;
    int order;
    p = (DWORD*)lpApplicationData;
    *p = 1;

    order = ee->order;
    CU_ASSERT_EQUAL(ee->hint, expected[order].hint);
    CU_ASSERT_EQUAL(ee->rvaOfFunction, expected[order].rvaOfFunction);
    CU_ASSERT_EQUAL(ee->rvaOfName, expected[order].rvaOfName);
    CU_ASSERT_EQUAL(ee->AddressOfFunction, expected[order].AddressOfFunction);
    CU_ASSERT_EQUAL(ee->AddressOfName, expected[order].AddressOfName);
    CU_ASSERT_EQUAL(ee->AddressOfOrdinal, expected[order].AddressOfOrdinal);
    CU_ASSERT_EQUAL(ee->Function, expected[order].Function);
    if (0 != ee->rvaOfName) {
        CU_ASSERT_STRING_EQUAL(ee->Name, expected[order].Name);
    }
    CU_ASSERT_EQUAL(ee->Ordinal, expected[order].Ordinal);

    /*
    printf("{%d, %d, "
            "0x%08X, 0x%08X, "
            "0x%08X, 0x%08X, 0x%08X, " 
            "(LPVOID)0x%08X, \"%s\", 0x%08X, 0, NULL},\n", 
            ee->order, ee->hint, 
            ee->rvaOfFunction, ee->rvaOfName, 
            ee->AddressOfFunction, ee->AddressOfName, ee->AddressOfOrdinal, 
            ee->Function, ee->Name, ee->Ordinal
            );
    */
    return FALSE;
}

void test_enumerate_export_tables(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;
    DWORD indicator = 0;

    hModule = LoadLibrary("pe_normal32_entry.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    cheap2el_enumerate_export_tables(pe,
            _test_enumerate_export_tables_cb,
            (LPVOID)(&indicator)
            );

    CU_ASSERT_TRUE(indicator);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_enumerate_export_tables_forward()

static BOOL
_test_enumerate_export_tables_forward_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_EXPORT_DIRECTORY ed,
        PCHEAP2EL_EXPORT_ENTRY ee,
        LPVOID lpApplicationData
        )
{
    CHEAP2EL_EXPORT_ENTRY expected[] = {
        {0, 0, 0x00001000, 0x00009B16, 0x10009AF8, 0x10009B00, 0x10009B08, 
            (LPVOID)0x10001000, "funcA1", 0x00000001, 0, NULL},
        {1, 1, 0x00009B24, 0x00009B1D, 0x10009AFC, 0x10009B04, 0x10009B0A, 
            (LPVOID)0x00000000, "funcB1", 0x00000002, TRUE, "dll02.funcB2"},
    };
    DWORD *p;
    int order;
    p = (DWORD*)lpApplicationData;
    *p = 1;

    order = ee->order;
    CU_ASSERT_EQUAL(ee->hint, expected[order].hint);
    CU_ASSERT_EQUAL(ee->rvaOfFunction, expected[order].rvaOfFunction);
    CU_ASSERT_EQUAL(ee->rvaOfName, expected[order].rvaOfName);
    CU_ASSERT_EQUAL(ee->AddressOfFunction, expected[order].AddressOfFunction);
    CU_ASSERT_EQUAL(ee->AddressOfName, expected[order].AddressOfName);
    CU_ASSERT_EQUAL(ee->AddressOfOrdinal, expected[order].AddressOfOrdinal);
    CU_ASSERT_EQUAL(ee->Function, expected[order].Function);
    if (0 != ee->rvaOfName) {
        CU_ASSERT_STRING_EQUAL(ee->Name, expected[order].Name);
    }
    CU_ASSERT_EQUAL(ee->Ordinal, expected[order].Ordinal);
    CU_ASSERT_EQUAL(ee->isForwarded, expected[order].isForwarded);
    if (ee->isForwarded) {
        CU_ASSERT_STRING_EQUAL(ee->ForwardedName, expected[order].ForwardedName);
    }
    return FALSE;
}

void test_enumerate_export_tables_forward(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;
    DWORD indicator = 0;

    hModule = LoadLibrary("pe_normal32_forward.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    cheap2el_enumerate_export_tables(pe,
            _test_enumerate_export_tables_forward_cb,
            (LPVOID)(&indicator)
            );

    CU_ASSERT_TRUE(indicator);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_get_export_rva_by_name()

void test_get_export_rva_by_name(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;
    DWORD rva;

    hModule = LoadLibrary("pe_normal32_forward.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    rva = cheap2el_get_export_rva_by_name(pe, "funcA1");
    CU_ASSERT_EQUAL(rva, 0x1000);
    rva = cheap2el_get_export_rva_by_name(pe, "funcB1");
    CU_ASSERT_EQUAL(rva, 0);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_get_export_rva_by_ordinal1()

void test_get_export_rva_by_ordinal1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;
    DWORD rva;

    hModule = LoadLibrary("pe_normal32_forward.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    rva = cheap2el_get_export_rva_by_ordinal(pe, 1);
    CU_ASSERT_EQUAL(rva, 0x1000);
    rva = cheap2el_get_export_rva_by_ordinal(pe, 2);
    CU_ASSERT_EQUAL(rva, 0);

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_get_export_rva_by_ordinal2()

void test_get_export_rva_by_ordinal2(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    int i;

    struct { int o; DWORD a; } indicators[9] = {
        { 5, 0x1050},
        { 7, 0x1070},
        { 9, 0x1020},
        {10, 0x1000},
        {11, 0x1040},
        {12, 0x1090},
        {13, 0x10A0},
        {14, 0xA000},
        {15, 0xA004}
    };

    hModule = LoadLibrary("pe_normal32_entry.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    for (i = 0; i < 9; i++) {
        CU_ASSERT_EQUAL(
                cheap2el_get_export_rva_by_ordinal(pe, indicators[i].o),
                indicators[i].a);
    }

    GlobalFree(pe);
    FreeLibrary(hModule);
    return;
}

// }}}
// {{{ test_enumerate_import_directory_0()

static BOOL
_test_enumerate_import_directory_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_import_directory_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    DWORD indicator = 0;
    int result = 0;

    hModule = LoadLibrary("pe_normal32_0imps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_import_directory(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// }}}
// {{{ test_enumerate_import_directory_1()

static BOOL

_test_enumerate_import_directory_1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    BOOL *r = (BOOL*)lpApplicationData;
    LPCSTR name = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);

    CU_ASSERT_EQUAL(order, 0);
    CU_ASSERT_EQUAL(imp_desc->OriginalFirstThunk, 0x2030);
    CU_ASSERT_EQUAL(imp_desc->FirstThunk, 0x2000);
    CU_ASSERT_EQUAL(imp_desc->Name, 0x2040);
    CU_ASSERT_STRING_EQUAL(name, "KERNEL32.dll");

    return *r;
}

void test_enumerate_import_directory_1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    BOOL cbr;
    int result = 0;

    hModule = LoadLibrary("pe_normal32_1imps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    result = cheap2el_enumerate_import_directory(pe, NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// }}}
// {{{ test_enumerate_import_directory_N()

static BOOL

_test_enumerate_import_directory_N_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    LPCSTR name = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);
    static struct {DWORD oft; DWORD ft; DWORD n; LPCSTR dll;} results[] = {
        {0x00002084, 0x00002000, 0x000020AC, "KERNEL32.dll"},
        {0x0000208C, 0x00002008, 0x000020C8, "USER32.dll"},
        {0x00002094, 0x00002010, 0x000020DC, "pe_normal32_Nimps_stub1.dll"},
        {0x0000209C, 0x00002018, 0x00002100, "pe_normal32_Nimps_stub2.dll"}
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_EQUAL(imp_desc->OriginalFirstThunk, results[order].oft);
    CU_ASSERT_EQUAL(imp_desc->FirstThunk, results[order].ft);
    CU_ASSERT_EQUAL(imp_desc->Name, results[order].n);
    CU_ASSERT_STRING_EQUAL(name, results[order].dll);

    return FALSE;
}

void test_enumerate_import_directory_N(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    int appdata;
    int result = 0;

    hModule = LoadLibrary("pe_normal32_Nimps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 4);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (3rd entry)
    appdata = 2;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 3);

    // callback return true (4th entry)
    appdata = 3;
    result = cheap2el_enumerate_import_directory(pe, 
            _test_enumerate_import_directory_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 4);

    // no callback
    result = cheap2el_enumerate_import_directory(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 4);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// }}}

