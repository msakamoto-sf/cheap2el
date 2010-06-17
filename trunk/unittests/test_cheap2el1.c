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

