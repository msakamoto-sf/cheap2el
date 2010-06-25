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
// {{{ _load_and_map_test_data()

typedef struct _lam_arg {
    LPVOID lpFileBuffer;
    LPVOID lpMemoryBuffer;
} lam_arg, *plam_arg;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data(
        plam_arg arg, LPCSTR lpFileName, CHEAP2EL_ERROR_CODE *err)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;

    arg->lpFileBuffer = _load_test_data(lpFileName);
    if (NULL == arg->lpFileBuffer) {
        CU_FAIL("memory error");
        return NULL;
    }

    cheap2el_get_sizeofimage_from_file(
            arg->lpFileBuffer, &sz_image, &sz_header, err);
    nLen = sz_image;
    arg->lpMemoryBuffer = GlobalAlloc(GMEM_ZEROINIT, nLen);

    pe = cheap2el_map_to_memory(
            arg->lpFileBuffer, arg->lpMemoryBuffer, nLen, err);

    return pe;
}

// }}}
// {{{ _load_and_map_test_data2()

typedef struct _lam_arg2 {
    LPVOID lpFileBuffer;
    LPVOID lpVirtualPage;
} lam_arg2, *plam_arg2;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data2(LPVOID addr, plam_arg2 arg, LPCSTR lpFileName, CHEAP2EL_ERROR_CODE *err)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    size_t nLen = 0;
    DWORD sz_image, sz_header;

    arg->lpFileBuffer = _load_test_data(lpFileName);
    if (NULL == arg->lpFileBuffer) {
        CU_FAIL("memory error");
        return NULL;
    }

    cheap2el_get_sizeofimage_from_file(
            arg->lpFileBuffer, &sz_image, &sz_header, err);
    nLen = sz_image;
    arg->lpVirtualPage = VirtualAlloc(
            addr, nLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == arg->lpVirtualPage) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualAlloc() error");
        return NULL;
    }

    pe = cheap2el_map_to_memory(
            arg->lpFileBuffer, arg->lpVirtualPage, nLen, err);

    return pe;
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_mz.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_nt.dat");
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
    // {{{ pe_normal32_exe.dat

    lpFileBuffer = _load_test_data("datafiles\\pe_normal32_exe.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_mz.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_mz.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_nt.dat");
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

    // {{{ pe_normal32_exe.dat : lack of memory

    lpFileBuffer = _load_test_data("datafiles\\pe_normal32_exe.dat");
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

    // pe_normal32_exe.dat : shoud result no error

    lpFileBuffer = _load_test_data("datafiles\\pe_normal32_exe.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_mz.dat");
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

    lpFileBuffer = _load_test_data("datafiles\\pe_not_nt.dat");
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

    hModule = LoadLibrary("datafiles\\pe_normal32_with_entrypoint.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    CU_ASSERT_PTR_NOT_NULL(pe);

    CU_ASSERT_EQUAL(((DWORD)hModule), pe->dwActualImageBase);
    CU_ASSERT_EQUAL(pe->dosHeader->e_magic, IMAGE_DOS_SIGNATURE);
    CU_ASSERT_EQUAL(pe->dosHeader->e_lfanew, 0xC0);
    CU_ASSERT_EQUAL(((DWORD)pe->lpDosStubAddress), 
            pe->dwActualImageBase + sizeof(IMAGE_DOS_HEADER));
    CU_ASSERT_EQUAL(pe->dwSizeOfDosStub, 0x80);

    // IMAGE_NT_HEADERS
    nt_headers = pe->ntHeaders;
    CU_ASSERT_EQUAL(nt_headers->Signature, IMAGE_NT_SIGNATURE);
    CU_ASSERT_EQUAL(nt_headers->FileHeader.Machine, IMAGE_FILE_MACHINE_I386);

    // IMAGE_FILE_HEADER
    file_header = &(nt_headers->FileHeader);
    CU_ASSERT_EQUAL(file_header->NumberOfSections, 3);
    CU_ASSERT_EQUAL(file_header->SizeOfOptionalHeader, 0xE0);
    CU_ASSERT_EQUAL(file_header->Characteristics, 
            IMAGE_FILE_DLL | 
            IMAGE_FILE_EXECUTABLE_IMAGE | 
            IMAGE_FILE_32BIT_MACHINE
            );

    // IMAGE_OPTIONAL_HEADER
    opt_header = &(nt_headers->OptionalHeader);
    CU_ASSERT_EQUAL(opt_header->Magic, IMAGE_NT_OPTIONAL_HDR_MAGIC);
    CU_ASSERT_EQUAL(opt_header->AddressOfEntryPoint, 0x1090);
    CU_ASSERT_EQUAL(opt_header->ImageBase, 0x10000000);
    CU_ASSERT_EQUAL(opt_header->SectionAlignment, 0x1000);
    CU_ASSERT_EQUAL(opt_header->FileAlignment, 0x200);
    CU_ASSERT_EQUAL(opt_header->SizeOfImage, 0x4000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeaders, 0x400);
    CU_ASSERT_EQUAL(opt_header->Subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfStackCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapReserve, 0x100000);
    CU_ASSERT_EQUAL(opt_header->SizeOfHeapCommit, 0x1000);
    CU_ASSERT_EQUAL(opt_header->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    // IMAGE_DATA_DIRECTORY
    ddptr = &(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    CU_ASSERT_EQUAL(ddptr->VirtualAddress, 0x2000);
    CU_ASSERT_EQUAL(ddptr->Size, 0xDC);

    // IMAGE_SECTION_HEADER
    //      #1
    cursor = &(pe->sectionHeaders[0]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".text");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x9C);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x1000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x200);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x400);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_EXECUTE |
            IMAGE_SCN_MEM_READ
            );
    //      #2
    cursor = &(pe->sectionHeaders[1]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".rdata");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0xDC);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x2000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x200);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x600);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
            );
    //      #3
    cursor = &(pe->sectionHeaders[2]);
    CU_ASSERT_STRING_EQUAL(cursor->Name, ".data");
    CU_ASSERT_EQUAL(cursor->Misc.VirtualSize, 0x8);
    CU_ASSERT_EQUAL(cursor->VirtualAddress, 0x3000);
    CU_ASSERT_EQUAL(cursor->SizeOfRawData, 0x200);
    CU_ASSERT_EQUAL(cursor->PointerToRawData, 0x800);
    CU_ASSERT_EQUAL(cursor->Characteristics, 
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE
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
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_exe.dat", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    ed = cheap2el_get_export_directory(pe);
    CU_ASSERT_PTR_NULL(ed);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_get_export_directory_success1()

void test_get_export_directory_success1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    HANDLE hModule = NULL;

    hModule = LoadLibrary("datafiles\\pe_normal32_with_entrypoint.dll");
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
// {{{ test_get_export_directory_success2()

void test_get_export_directory_success2(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_with_entrypoint.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }
    ed = cheap2el_get_export_directory(pe);

    CU_ASSERT_EQUAL(ed->Characteristics, 0x0);
    CU_ASSERT_EQUAL(ed->Base, 5);
    CU_ASSERT_EQUAL(ed->NumberOfFunctions, 11);
    CU_ASSERT_EQUAL(ed->NumberOfNames, 9);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
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
    CHEAP2EL_ERROR_CODE err;
    PIMAGE_EXPORT_DIRECTORY ed = NULL;
    DWORD indicator = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_exe.dat", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }
    cheap2el_enumerate_export_tables(pe, 
            _test_enumerate_export_tables_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(indicator);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
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

    hModule = LoadLibrary("datafiles\\pe_normal32_with_entrypoint.dll");
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
        {0, 0, 0x00001000, 0x0000205E, 0x10002028, 0x10002034, 0x10002040, 
            (LPVOID)0x10001000, "funcA1", 0x00000001, 0, NULL},
        {1, 1, 0x0000206C, 0x00002065, 0x1000202C, 0x10002038, 0x10002042, 
            (LPVOID)0x00000000, "funcB1", 0x00000002, TRUE, "pe_normal32_forward_stub.funcB2"},
        {2, 2, 0x00001010, 0x0000208C, 0x10002030, 0x1000203C, 0x10002044, 
            (LPVOID)0x10001010, "funcC1", 0x00000003, 0, NULL},
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

    hModule = LoadLibrary("datafiles\\pe_normal32_forward.dll");
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

    hModule = LoadLibrary("datafiles\\pe_normal32_forward.dll");
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
    rva = cheap2el_get_export_rva_by_name(pe, "funcC1");
    CU_ASSERT_EQUAL(rva, 0x1010);

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

    hModule = LoadLibrary("datafiles\\pe_normal32_forward.dll");
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
    rva = cheap2el_get_export_rva_by_ordinal(pe, 3);
    CU_ASSERT_EQUAL(rva, 0x1010);

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
        { 5, 0x1030},
        { 7, 0x1050},
        { 9, 0x1010},
        {10, 0x1000},
        {11, 0x1020},
        {12, 0x1070},
        {13, 0x1080},
        {14, 0x3000},
        {15, 0x3004}
    };

    hModule = LoadLibrary("datafiles\\pe_normal32_with_entrypoint.dll");
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

    hModule = LoadLibrary("datafiles\\pe_normal32_0imps.dll");
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

    hModule = LoadLibrary("datafiles\\pe_normal32_1imps.dll");
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

    hModule = LoadLibrary("datafiles\\pe_normal32_Nimps.dll");
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
// {{{ test_enumerate_import_tables_0()

static BOOL
_test_enumerate_import_tables_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_import_tables_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    DWORD indicator = 0;
    int result = 0;

    hModule = LoadLibrary("datafiles\\pe_normal32_0imps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_0_cb, "foo.dll",
            (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_import_tables(pe, NULL, 
            "foo.dll", (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// }}}
// {{{ test_enumerate_import_tables_1()

static BOOL
_test_enumerate_import_tables_1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    BOOL *r = (BOOL*)lpApplicationData;
    LPCSTR name = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);

    CU_ASSERT_STRING_EQUAL(name, "KERNEL32.dll");
    CU_ASSERT_EQUAL(imp_entry->order, 0);
    CU_ASSERT_EQUAL(imp_entry->rvaOfEntryAddress, 0x2000);
    CU_ASSERT_EQUAL(imp_entry->rvaOfImportByName, 0x2038);
    CU_ASSERT_NOT_EQUAL(imp_entry->EntryAddress, 0);
    CU_ASSERT_EQUAL(imp_entry->ImportByName->Hint, 1057);
    CU_ASSERT_EQUAL((DWORD)(imp_entry->ImportByName->Name), 0x1000203A);
    CU_ASSERT_STRING_EQUAL((LPCSTR)imp_entry->ImportByName->Name, "Sleep");
    CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, 0);
    CU_ASSERT_STRING_EQUAL(imp_entry->ModuleName, "KERNEL32.dll");

/*
    printf("name = %s\n", name);
    printf("order = %d\n", imp_entry->order);
    printf("rvaOfEntryAddress = 0x%08X\n", imp_entry->rvaOfEntryAddress);
    printf("rvaOfImportByName = 0x%08X\n", imp_entry->rvaOfImportByName);
    printf("EntryAddress = 0x%08X\n", imp_entry->EntryAddress);
    printf("ImportByName.Hint = %d\n", imp_entry->ImportByName->Hint);
    printf("ImportByName.Name = 0x%08X\n", imp_entry->ImportByName->Name);
    printf("ImportByName.Name = %s\n", (LPCSTR)imp_entry->ImportByName->Name);
    printf("ImportOrdinal = %d\n", imp_entry->ImportOrdinal);
    printf("ModuleName = %s\n", imp_entry->ModuleName);
*/
    return *r;
}

void test_enumerate_import_tables_1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    BOOL cbr;
    int result = 0;

    hModule = LoadLibrary("datafiles\\pe_normal32_1imps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);

    // dll not found
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_1_cb, 
            "notfound", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 0);

    // dll not found
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_1_cb, 
            NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 0);

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_1_cb, 
            "kernel32.DLL", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_1_cb, 
            "KERNEL32.dll", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    cbr = FALSE;
    result = cheap2el_enumerate_import_tables(pe, 
            NULL, "kernel32.DLL", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// }}}
// {{{ test_enumerate_import_tables_M()

static HANDLE hModule_pe_normal32_Mimps;
static HANDLE hModule_pe_normal32_Mimps_stub;

#define modname ("pe_normal32_Mimps_stub.dll")

static BOOL
_test_enumerate_import_tables_M_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = (LPCSTR)(imp_desc->Name + pe->dwActualImageBase);
    int *when_return_true  = (int*)lpApplicationData;
    int i;
    static struct {
        WORD rvaOfEntryAddress;
        WORD rvaOfImportByName;
        WORD Hint;
        WORD rvaOfName;
        LPCSTR Name;
        WORD ImportOrdinal;
        LPCSTR ModuleName;
    } results[] = {
        {0x2000, 0x2070, 5, 0x2072, "funcX", 0, modname},
        {0x2004, 0x0000, 0, 0x0, NULL, 6, modname},
        {0x2008, 0x0000, 0, 0x0, NULL, 5, modname},
        {0x200C, 0x2078, 2, 0x207A, "func1", 0, modname},
        {0x2010, 0x2080, 7, 0x2082, "varsA", 0, modname},
        {0x2014, 0x2088, 8, 0x208A, "varsB", 0, modname},
        {0x2018, 0x2090, 0, 0x2092, "bar", 0, modname},
        {0x201C, 0x2096, 1, 0x2098, "foo", 0, modname}
    };

    if (imp_entry->order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_STRING_EQUAL(name, modname);
    i = imp_entry->order;
    CU_ASSERT_EQUAL(imp_entry->rvaOfEntryAddress, 
            results[i].rvaOfEntryAddress);
    CU_ASSERT_EQUAL(imp_entry->rvaOfImportByName, 
            results[i].rvaOfImportByName);
    CU_ASSERT_NOT_EQUAL(imp_entry->EntryAddress, 0);
    if (0 == imp_entry->rvaOfImportByName) {
        CU_ASSERT_EQUAL(imp_entry->ImportByName, NULL);
        CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, results[i].ImportOrdinal);
    } else {
        CU_ASSERT_EQUAL(imp_entry->ImportByName->Hint, 
                results[i].Hint);
        CU_ASSERT_EQUAL((DWORD)(imp_entry->ImportByName->Name), 
                results[i].rvaOfName + (DWORD)hModule_pe_normal32_Mimps);
        CU_ASSERT_STRING_EQUAL((LPCSTR)imp_entry->ImportByName->Name, 
                results[i].Name);
        CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, 0);
    }
    CU_ASSERT_STRING_EQUAL(imp_entry->ModuleName, modname);

/*
    printf("{%d, 0x%08X, 0x%08X, ",
            imp_entry->order,
            imp_entry->rvaOfEntryAddress,
            imp_entry->rvaOfImportByName
          );
    if (0 != imp_entry->rvaOfImportByName) {
        printf("%d, 0x%08X, \"%s\", %d, ", 
                imp_entry->ImportByName->Hint, 
                imp_entry->ImportByName->Name, 
                (LPCSTR)imp_entry->ImportByName->Name, 
                imp_entry->ImportOrdinal
              );
    } else {
        printf("0, 0x0, NULL, %d, ", imp_entry->ImportOrdinal);
    }
    printf("\"%s\"}, \n", imp_entry->ModuleName);
*/

    return FALSE;
}

void test_enumerate_import_tables_M(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    HANDLE hModule = NULL;
    int appdata;
    int result = 0;

    hModule = LoadLibrary("datafiles\\pe_normal32_Mimps.dll");
    if (NULL == hModule) {
        _print_last_error(GetLastError());
        CU_FAIL("DLL Load error");
        return;
    }

    pe = cheap2el_map_from_loaded_image((LPVOID)hModule, &err);

    hModule_pe_normal32_Mimps = hModule;
    hModule_pe_normal32_Mimps_stub = GetModuleHandle("pe_normal32_Mimps_stub.dll");

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_M_cb, 
            "pe_normal32_Mimps_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 8);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_M_cb, 
            "pe_normal32_Mimps_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (3rd entry)
    appdata = 2;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_M_cb, 
            "pe_normal32_Mimps_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 3);

    // callback return true (7th entry)
    appdata = 7;
    result = cheap2el_enumerate_import_tables(pe, 
            _test_enumerate_import_tables_M_cb, 
            "pe_normal32_Mimps_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 8);

    // no callback
    result = cheap2el_enumerate_import_tables(pe, 
            NULL, "pe_normal32_Mimps_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 8);

    GlobalFree(pe);
    FreeLibrary(hModule);
}

// reset local macro
#undef modname

// }}}
// {{{ test_enumerate_bound_imports_0()

static BOOL
_test_enumerate_bound_imports_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid_head,
        PIMAGE_BOUND_FORWARDER_REF bfr_head,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_bound_imports_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_0imps.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_bound_imports(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_bound_imports_1()

static BOOL
_test_enumerate_bound_imports_1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid_head,
        PIMAGE_BOUND_FORWARDER_REF bfr_head,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid,
        int order,
        LPVOID lpApplicationData
        )
{
    BOOL *r = (BOOL*)lpApplicationData;
    LPCSTR name = (LPCSTR)((DWORD)(bid_head) + bid->OffsetModuleName);
    CU_ASSERT_NOT_EQUAL(bid->TimeDateStamp, 0);
    CU_ASSERT_EQUAL(bid->OffsetModuleName, 0x10);
    CU_ASSERT_EQUAL(bid->NumberOfModuleForwarderRefs, 0);
    CU_ASSERT_PTR_NULL(bfr_head);
/*
    printf("TimeDateStamp = 0x%08X\n", bid->TimeDateStamp);
    printf("OffsetModuleName = 0x%08X\n", bid->OffsetModuleName);
    printf("OffsetModuleName = %s\n", name);
    printf("NumberOfModuleForwarderRefs = 0x%08X\n", bid->NumberOfModuleForwarderRefs);
    */
    return *r;
}

void test_enumerate_bound_imports_1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    BOOL cbr;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_1binds.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    cbr = FALSE;
    result = cheap2el_enumerate_bound_imports(pe, NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_bound_imports_N()
/*
static HANDLE hModule_pe_normal32_Mimps;
static HANDLE hModule_pe_normal32_Mimps_stub;

#define modname ("pe_normal32_Mimps_stub.dll")
*/
static BOOL
_test_enumerate_bound_imports_N_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid_head,
        PIMAGE_BOUND_FORWARDER_REF bfr_head,
        PIMAGE_BOUND_IMPORT_DESCRIPTOR bid,
        int order,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = NULL;
    PIMAGE_BOUND_FORWARDER_REF bfr;
    int *when_return_true  = (int*)lpApplicationData;
    int i;
    static struct { WORD OMN; WORD NOMFR; LPCSTR name; } rbid[] = {
        {0x0060, 0x0000, "pe_normal32_Nbinds_stubA0.dll"},
        {0x007E, 0x0001, "pe_normal32_Nbinds_stubB0.dll"},
        {0x00BA, 0x0002, "pe_normal32_Nbinds_stubC0.dll"},
        {0x0114, 0x0003, "pe_normal32_Nbinds_stubD0.dll"},
        {0x018C, 0x0000, "pe_normal32_Nbinds_stubE0.dll"}
    };
    static struct { WORD OMN; LPCSTR name; } rbfr[5][3] = {
        // A0
        { {0, NULL}, {0, NULL}, {0, NULL} },
        // B0
        { {0x009C, "pe_normal32_Nbinds_stubB1.DLL"}, {0, NULL}, {0, NULL} },
        // C0
        {
            {0x00D8, "pe_normal32_Nbinds_stubC2.DLL"},
            {0x00F6, "pe_normal32_Nbinds_stubC1.DLL"},
            {0, NULL}
        },
        // D0
        {
            {0x0132, "pe_normal32_Nbinds_stubD2.DLL"},
            {0x0150, "pe_normal32_Nbinds_stubD1.DLL"},
            {0x016E, "pe_normal32_Nbinds_stubD3.DLL"}
        },
        // E0
        { {0, NULL}, {0, NULL}, {0, NULL} }
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    name = (LPCSTR)((DWORD)(bid_head) + bid->OffsetModuleName);
    CU_ASSERT_NOT_EQUAL(bid->TimeDateStamp, 0);
    CU_ASSERT_EQUAL(bid->OffsetModuleName, rbid[order].OMN);
    CU_ASSERT_EQUAL(bid->NumberOfModuleForwarderRefs, rbid[order].NOMFR);
    CU_ASSERT_STRING_EQUAL(name, rbid[order].name);
    if (0 == rbid[order].NOMFR) {
        CU_ASSERT_PTR_NULL(bfr_head);
    } else {
        for (i = 0, bfr = bfr_head; 
            i < rbid[order].NOMFR; 
            i++, bfr++) {
            CU_ASSERT_NOT_EQUAL(bfr->TimeDateStamp, 0);
            CU_ASSERT_EQUAL(bfr->OffsetModuleName, rbfr[order][i].OMN);
            name = (LPCSTR)((DWORD)(bid_head) + bfr->OffsetModuleName);
            CU_ASSERT_STRING_EQUAL(name, rbfr[order][i].name);
        }
    }
/*
    name = (LPCSTR)((DWORD)(bid_head) + bid->OffsetModuleName);
    printf("{0x%04X, 0x%04X, \"%s\"},\n", 
            bid->OffsetModuleName,
            bid->NumberOfModuleForwarderRefs,
            name
            );
    for (i = 0, bfr = bfr_head; 
            i < bid->NumberOfModuleForwarderRefs; 
            i++, bfr++) {
        name = (LPCSTR)((DWORD)(bid_head) + bfr->OffsetModuleName);
        printf("\t{0x%04X, \"%s\"},\n", 
                bfr->OffsetModuleName,
                name
              );
    }
*/
    return FALSE;
}

void test_enumerate_bound_imports_N(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int appdata;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_Nbinds.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 5);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (3rd entry)
    appdata = 2;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 3);

    // callback return true (5th entry)
    appdata = 4;
    result = cheap2el_enumerate_bound_imports(pe, 
            _test_enumerate_bound_imports_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 5);

    // no callback
    result = cheap2el_enumerate_bound_imports(pe, NULL, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 5);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delay_load_0()

static BOOL
_test_enumerate_delay_load_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        ImgDelayDescr *imp_dd,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_delay_load_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_0imps.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_delay_load(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delay_load_1()

static BOOL
_test_enumerate_delay_load_1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        int order,
        LPVOID lpApplicationData
        )
{
    BOOL *r = (BOOL*)lpApplicationData;

    LPCSTR name = (LPCSTR)(imp_dd->rvaDLLName + pe->dwActualImageBase);

    CU_ASSERT_EQUAL(order, 0);
    CU_ASSERT_EQUAL(imp_dd->rvaDLLName, 0x00002020);
    CU_ASSERT_STRING_EQUAL(name, "USER32.dll");
    CU_ASSERT_EQUAL(imp_dd->grAttrs, dlattrRva);
    CU_ASSERT_EQUAL(imp_dd->rvaHmod, 0x00003010);
    CU_ASSERT_EQUAL(imp_dd->rvaIAT, 0x00003008);
    CU_ASSERT_EQUAL(imp_dd->rvaINT, 0x0000206C);
    CU_ASSERT_EQUAL(imp_dd->rvaBoundIAT, 0x00002084);
    CU_ASSERT_EQUAL(imp_dd->rvaUnloadIAT, 0x00000000);
    CU_ASSERT_EQUAL(imp_dd->dwTimeStamp, 0x00000000);

/*
    printf("rvaDLLName = %s (0x%08X)\n", name, imp_dd->rvaDLLName);
    printf("grAttrs = 0x%08X\n", imp_dd->grAttrs);
    printf("rvaHmod = 0x%08X\n", imp_dd->rvaHmod);
    printf("rvaIAT = 0x%08X", imp_dd->rvaIAT);
    printf("rvaINT = 0x%08X", imp_dd->rvaINT);
    printf("rvaBoundIAT = 0x%08X", imp_dd->rvaBoundIAT);
    printf("rvaUnloadIAT = 0x%08X", imp_dd->rvaUnloadIAT);
    printf("dwTimeStamp = 0x%08X", imp_dd->dwTimeStamp);
*/

    return *r;
}

void test_enumerate_delay_load_1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    BOOL cbr;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_delay1.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    result = cheap2el_enumerate_delay_load(pe, NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delay_load_N1()

static BOOL
_test_enumerate_delay_load_N1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    LPCSTR name = (LPCSTR)(imp_dd->rvaDLLName + pe->dwActualImageBase);
    static struct {
        LPCSTR name;
        DWORD rvaDLLName;
        DWORD grAttrs;
        DWORD rvaHmod;
        DWORD rvaIAT;
        DWORD rvaINT;
        DWORD rvaBoundIAT;
        DWORD rvaUnloadIAT;
        DWORD dwTimeStamp;
    } rdd[] = {
        {"pe_normal32_delayN1_stub1.dll", 0x00002020, 0x00000001, 0x00003010, 0x00003000, 0x000020C0, 0x000020E0, 0x00000000, 0x00000000},
        {"pe_normal32_delayN1_stub2.dll", 0x00002040, 0x00000001, 0x00003014, 0x00003008, 0x000020C8, 0x000020E8, 0x00000000, 0x00000000}
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_EQUAL(imp_dd->rvaDLLName, rdd[order].rvaDLLName);
    CU_ASSERT_STRING_EQUAL(name, rdd[order].name);
    CU_ASSERT_EQUAL(imp_dd->grAttrs, rdd[order].grAttrs);
    CU_ASSERT_EQUAL(imp_dd->rvaHmod, rdd[order].rvaHmod);
    CU_ASSERT_EQUAL(imp_dd->rvaIAT, rdd[order].rvaIAT);
    CU_ASSERT_EQUAL(imp_dd->rvaINT, rdd[order].rvaINT);
    CU_ASSERT_EQUAL(imp_dd->rvaBoundIAT, rdd[order].rvaBoundIAT);
    CU_ASSERT_EQUAL(imp_dd->rvaUnloadIAT, rdd[order].rvaUnloadIAT);
    CU_ASSERT_EQUAL(imp_dd->dwTimeStamp, rdd[order].dwTimeStamp);

/*
    printf("{\"%s\", 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X},\n", 
            name,
            imp_dd->rvaDLLName,
            imp_dd->grAttrs,
            imp_dd->rvaHmod,
            imp_dd->rvaIAT,
            imp_dd->rvaINT,
            imp_dd->rvaBoundIAT,
            imp_dd->rvaUnloadIAT,
            imp_dd->dwTimeStamp
          );
*/

    return FALSE;
}

void test_enumerate_delay_load_N1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int appdata;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_delayN1.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_N1_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_N1_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (2nd entry)
    appdata = 1;
    result = cheap2el_enumerate_delay_load(pe, 
            _test_enumerate_delay_load_N1_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // no callback
    result = cheap2el_enumerate_delay_load(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delayload_tables_0()

static BOOL
_test_enumerate_delayload_tables_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_delayload_tables_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_0imps.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_0_cb, 
            "foo.dll", (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_delayload_tables(pe, NULL, "foo.dll", (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delayload_tables_N1()

static BOOL
_test_enumerate_delayload_tables_N1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = (LPCSTR)(imp_dd->rvaDLLName + pe->dwActualImageBase);
    BOOL *r = (BOOL*)lpApplicationData;

    CU_ASSERT_STRING_EQUAL(name, "USER32.dll");
    CU_ASSERT_EQUAL(imp_entry->order, 0);
    CU_ASSERT_EQUAL(imp_entry->rvaOfEntryAddress, 0x3008);
    CU_ASSERT_EQUAL(imp_entry->rvaOfImportByName, 0x2074);
    CU_ASSERT_EQUAL((DWORD)imp_entry->EntryAddress, 0x10001019);
    CU_ASSERT_EQUAL(imp_entry->ImportByName->Hint, 0);
    CU_ASSERT_STRING_EQUAL((LPCSTR)imp_entry->ImportByName->Name, "MessageBoxA");
    CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, 0);
    CU_ASSERT_STRING_EQUAL(imp_entry->ModuleName, "USER32.dll");

/*
    printf("name = %s\n", name);
    printf("order = %d\n", imp_entry->order);
    printf("rvaOfEntryAddress = 0x%08X\n", imp_entry->rvaOfEntryAddress);
    printf("rvaOfImportByName = 0x%08X\n", imp_entry->rvaOfImportByName);
    printf("EntryAddress = 0x%08X\n", imp_entry->EntryAddress);
    printf("ImportByName.Hint = %d\n", imp_entry->ImportByName->Hint);
    printf("ImportByName.Name = 0x%08X\n", imp_entry->ImportByName->Name);
    printf("ImportByName.Name = %s\n", (LPCSTR)imp_entry->ImportByName->Name);
    printf("ImportOrdinal = %d\n", imp_entry->ImportOrdinal);
    printf("ModuleName = %s\n", imp_entry->ModuleName);
*/
    return *r;
}

void test_enumerate_delayload_tables_N1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    BOOL cbr;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_delay1.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // dll not found
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_N1_cb, 
            "notfound", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 0);

    // dll not found
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_N1_cb, 
            NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 0);

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_N1_cb, 
            "user32.DLL", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_N1_cb, 
            "user32.DLL", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    cbr = FALSE;
    result = cheap2el_enumerate_delayload_tables(pe, 
            NULL, "user32.DLL", (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_delayload_tables_NM()

#define modname ("pe_normal32_delayNM_stub.dll")

static BOOL
_test_enumerate_delayload_tables_NM_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PImgDelayDescr imp_dd,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    LPCSTR name = (LPCSTR)(imp_dd->rvaDLLName + pe->dwActualImageBase);
    int *when_return_true  = (int*)lpApplicationData;
    int i;
    static struct {
        WORD rvaOfEntryAddress;
        WORD rvaOfImportByName;
        WORD Hint;
        LPCSTR Name;
        WORD ImportOrdinal;
        LPCSTR ModuleName;
    } results[] = {
        {0x3000, 0x0000, 0, NULL, 6, modname},
        {0x3004, 0x0000, 0, NULL, 5, modname},
        {0x3008, 0x20A4, 0, "func1", 0, modname},
        {0x300C, 0x20AC, 0, "bar", 0, modname},
        {0x3010, 0x20B2, 0, "foo", 0, modname},
        {0x3014, 0x209C, 0, "funcX", 0, modname}
    };

    if (imp_entry->order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_STRING_EQUAL(name, modname);
    i = imp_entry->order;
    CU_ASSERT_EQUAL(imp_entry->rvaOfEntryAddress, 
            results[i].rvaOfEntryAddress);
    CU_ASSERT_EQUAL(imp_entry->rvaOfImportByName, 
            results[i].rvaOfImportByName);
    CU_ASSERT_NOT_EQUAL(imp_entry->EntryAddress, 0);
    if (0 == imp_entry->rvaOfImportByName) {
        CU_ASSERT_EQUAL(imp_entry->ImportByName, NULL);
        CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, results[i].ImportOrdinal);
    } else {
        CU_ASSERT_EQUAL(imp_entry->ImportByName->Hint, 
                results[i].Hint);
        CU_ASSERT_STRING_EQUAL((LPCSTR)imp_entry->ImportByName->Name, 
                results[i].Name);
        CU_ASSERT_EQUAL(imp_entry->ImportOrdinal, 0);
    }
    CU_ASSERT_STRING_EQUAL(imp_entry->ModuleName, modname);

/*
    printf("{%d, 0x%08X, 0x%08X, ",
            imp_entry->order,
            imp_entry->rvaOfEntryAddress,
            imp_entry->rvaOfImportByName
          );
    if (0 != imp_entry->rvaOfImportByName) {
        printf("%d, 0x%08X, \"%s\", %d, ", 
                imp_entry->ImportByName->Hint, 
                imp_entry->ImportByName->Name, 
                (LPCSTR)imp_entry->ImportByName->Name, 
                imp_entry->ImportOrdinal
              );
    } else {
        printf("0, 0x0, NULL, %d, ", imp_entry->ImportOrdinal);
    }
    printf("\"%s\"}, \n", imp_entry->ModuleName);
*/

    return FALSE;
}

void test_enumerate_delayload_tables_NM(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int appdata;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_delayNM.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_NM_cb, 
            "pe_normal32_delayNM_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 6);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_NM_cb, 
            "pe_normal32_delayNM_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (3rd entry)
    appdata = 2;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_NM_cb, 
            "pe_normal32_delayNM_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 3);

    // callback return true (6th entry)
    appdata = 5;
    result = cheap2el_enumerate_delayload_tables(pe, 
            _test_enumerate_delayload_tables_NM_cb, 
            "pe_normal32_delayNM_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 6);

    // no callback
    result = cheap2el_enumerate_delayload_tables(pe, 
            NULL, "pe_normal32_delayNM_stub.dll", (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 6);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// reset local macro
#undef modname

// }}}
// {{{ test_enumerate_base_relocations_0()

static BOOL
_test_enumerate_base_relocations_0_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

void test_enumerate_base_relocations_0(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_0imps.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_0_cb, (LPVOID)(&indicator));

    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // no callback
    result = cheap2el_enumerate_base_relocations(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_base_relocations_1()

static BOOL
_test_enumerate_base_relocations_1_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    BOOL *r = (BOOL*)lpApplicationData;
    PWORD tofs = NULL;
    DWORD dwptr;
    int i;

    CU_ASSERT_EQUAL(bre->BaseRelocation->VirtualAddress, 0x1000);
    CU_ASSERT_EQUAL(bre->BaseRelocation->SizeOfBlock, 0xC);
    dwptr = (DWORD)bre->BaseRelocation;
    dwptr += sizeof(IMAGE_BASE_RELOCATION);
    CU_ASSERT_EQUAL(bre->TypeOffset, (PWORD)dwptr);
    CU_ASSERT_EQUAL(bre->NumberOfTypeOffset, 0x2);
    tofs = bre->TypeOffset;
    CU_ASSERT_EQUAL(tofs[0], 0x3009);
    CU_ASSERT_EQUAL(tofs[1], 0x0);

/*
    printf("PIMAGE_BASE_RELOCATION = 0x%08X\n", bre->BaseRelocation);
    printf("VirtualAddress = 0x%08X\n", bre->BaseRelocation->VirtualAddress);
    printf("SizeOfBlock = 0x%08X\n", bre->BaseRelocation->SizeOfBlock);
    printf("TypeOffset = 0x%08X\n", bre->TypeOffset);
    printf("NumberOfTypeOffset = 0x%08X\n", bre->NumberOfTypeOffset);
    tofs = bre->TypeOffset;
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        printf("\tTypeOffset[%d] = 0x%04X\n", i, *tofs);
    }
*/

    return *r;
}

void test_enumerate_base_relocations_1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    BOOL cbr;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_reloc1.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    cbr = FALSE;
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true
    cbr = TRUE;
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_1_cb, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    // no callback
    result = cheap2el_enumerate_base_relocations(pe, NULL, (LPVOID)(&cbr));
    CU_ASSERT_EQUAL(result, 1);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_enumerate_base_relocations_N()

static BOOL
_test_enumerate_base_relocations_N_cb(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    PWORD tofs = NULL;
    DWORD dwptr;
    int i;
    static struct { DWORD va; DWORD sob; int num; } rbre[] = {
        {0x00001000, 0x00000010, 4},
        {0x00003000, 0x0000000C, 2},
    };
    static WORD rtofs[2][4] = {
        {0x3019, 0x3026, 0x302B, 0x3033},
        {0x3000, 0x0000, 0, 0}
    };
    if (order == *when_return_true) {
        return TRUE;
    }
    CU_ASSERT_EQUAL(bre->BaseRelocation->VirtualAddress, rbre[order].va);
    CU_ASSERT_EQUAL(bre->BaseRelocation->SizeOfBlock, rbre[order].sob);
    CU_ASSERT_EQUAL(bre->NumberOfTypeOffset, rbre[order].num);
    dwptr = (DWORD)bre->BaseRelocation;
    dwptr += sizeof(IMAGE_BASE_RELOCATION);
    CU_ASSERT_EQUAL(bre->TypeOffset, (PWORD)dwptr);
    tofs = bre->TypeOffset;
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        CU_ASSERT_EQUAL(*tofs, rtofs[order][i]);
    }

/*
    printf("{0x%08X, 0x%08X, %d},\n",
            bre->BaseRelocation->VirtualAddress,
            bre->BaseRelocation->SizeOfBlock,
            bre->NumberOfTypeOffset);
    tofs = bre->TypeOffset;
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        printf("\t{%d, 0x%04X},\n", i, *tofs);
    }
*/
    return FALSE;
}

void test_enumerate_base_relocations_N(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int appdata;
    int result = 0;
    lam_arg buffers;

    pe = _load_and_map_test_data(&buffers, "datafiles\\pe_normal32_relocN.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data() failed.");
        return;
    }

    // callback return false
    appdata = -1;
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (2nd entry)
    appdata = 1;
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_enumerate_base_relocations_N_cb, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // no callback
    result = cheap2el_enumerate_base_relocations(pe, NULL, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    GlobalFree(pe);
    GlobalFree(buffers.lpFileBuffer);
    GlobalFree(buffers.lpMemoryBuffer);
}

// }}}
// {{{ test_callback_update_base_relocations1()

static BOOL
_test_callback_update_base_relocations_cb1(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    PWORD tofs = NULL;
    DWORD dwbuf;
    PDWORD dwptr;
    WORD wbuf, br_type, br_offset;
    int i;
    // effective addresses
    static DWORD ea[2][4] = {
        {0x05002000, 0x05003004, 0x05003008, 0x05002008},
        {0x05001000, 0, 0, 0}
    };

    tofs = bre->TypeOffset;
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        wbuf = *tofs;
        br_type = (0xF000 & wbuf) >> 12;
        br_offset = 0xFF & wbuf;
        if (IMAGE_REL_BASED_HIGHLOW != br_type) {
            continue;
        }
        dwbuf = pe->dwActualImageBase + bre->BaseRelocation->VirtualAddress + br_offset;
        dwptr = (PDWORD)dwbuf;
        dwbuf = *dwptr;
        /*
        printf("[%d][%d] = actual:0x%08X/expected:0x%08X\n", 
                order, i, dwbuf, ea[order][i]);
        */
        CU_ASSERT_EQUAL(dwbuf, ea[order][i]);
    }

    return FALSE;
}

void test_callback_update_base_relocations1(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int result = 0;
    lam_arg2 buffers;

    pe = _load_and_map_test_data2((LPVOID)0x05000000, &buffers, 
            "datafiles\\pe_normal32_relocN.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data2() failed.");
        return;
    }

    // update base relocations
    result = cheap2el_enumerate_base_relocations(pe, 
            cheap2el_callback_update_base_relocations, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    // confirm updated addresses
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_callback_update_base_relocations_cb1, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    GlobalFree(pe);
    if (!VirtualFree(buffers.lpVirtualPage, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualFree() error");
    }
    GlobalFree(buffers.lpFileBuffer);
}

// }}}
// {{{ test_callback_update_base_relocations2()

static BOOL
_test_callback_update_base_relocations_cb2(
        PCHEAP2EL_PE_IMAGE pe,
        PCHEAP2EL_BASERELOC_ENTRY bre,
        int order,
        LPVOID lpApplicationData
        )
{
    PWORD tofs = NULL;
    DWORD dwbuf;
    PDWORD dwptr;
    WORD wbuf, br_type, br_offset;
    int i;
    // effective addresses
    static DWORD ea[2][4] = {
        {0x20002000, 0x20003004, 0x20003008, 0x20002008},
        {0x20001000, 0, 0, 0}
    };

    tofs = bre->TypeOffset;
    for (i = 0; i < bre->NumberOfTypeOffset; i++, tofs++) {
        wbuf = *tofs;
        br_type = (0xF000 & wbuf) >> 12;
        br_offset = 0xFF & wbuf;
        if (IMAGE_REL_BASED_HIGHLOW != br_type) {
            continue;
        }
        dwbuf = pe->dwActualImageBase + bre->BaseRelocation->VirtualAddress + br_offset;
        dwptr = (PDWORD)dwbuf;
        dwbuf = *dwptr;
        /*
        printf("[%d][%d] = actual:0x%08X/expected:0x%08X\n", 
                order, i, dwbuf, ea[order][i]);
        */
        CU_ASSERT_EQUAL(dwbuf, ea[order][i]);
    }

    return FALSE;
}

void test_callback_update_base_relocations2(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    int result = 0;
    lam_arg2 buffers;

    pe = _load_and_map_test_data2((LPVOID)0x20000000, &buffers, 
            "datafiles\\pe_normal32_relocN.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data2() failed.");
        return;
    }

    // update base relocations
    result = cheap2el_enumerate_base_relocations(pe, 
            cheap2el_callback_update_base_relocations, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    // confirm updated addresses
    result = cheap2el_enumerate_base_relocations(pe, 
            _test_callback_update_base_relocations_cb2, (LPVOID)NULL);
    CU_ASSERT_EQUAL(result, 2);

    GlobalFree(pe);
    if (!VirtualFree(buffers.lpVirtualPage, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualFree() error");
    }
    GlobalFree(buffers.lpFileBuffer);
}

// }}}
// {{{ test_callback_resolve_imports()

// {{{ _test_callback_resolve_imports_cbA()
static BOOL
_test_callback_resolve_imports_cbA(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    static DWORD expected[] = {0x000020C4, 0x000020CC, 0x80000002};
    BOOL bConfirm = *(BOOL*)lpApplicationData;
    int i = imp_entry->order;
    if (bConfirm) {
        CU_ASSERT_NOT_EQUAL((DWORD)(imp_entry->EntryAddress), expected[i]);
    } else {
        CU_ASSERT_EQUAL((DWORD)(imp_entry->EntryAddress), expected[i]);
    }
    //printf("EntryAddress = 0x%08X\n", imp_entry->EntryAddress);

    return FALSE;
}

// }}}

// {{{ _test_callback_resolve_imports_cbB()

static BOOL
_test_callback_resolve_imports_cbB(
        PCHEAP2EL_PE_IMAGE pe,
        PIMAGE_IMPORT_DESCRIPTOR imp_desc,
        PCHEAP2EL_IMPORT_ENTRY imp_entry,
        LPVOID lpApplicationData
        )
{
    static DWORD expected[] = {0x80000002, 0x000020F0, 0x000020F8};
    BOOL bConfirm = *(BOOL*)lpApplicationData;
    int i = imp_entry->order;
    if (bConfirm) {
        CU_ASSERT_NOT_EQUAL((DWORD)(imp_entry->EntryAddress), expected[i]);
    } else {
        CU_ASSERT_EQUAL((DWORD)(imp_entry->EntryAddress), expected[i]);
    }
    //printf("EntryAddress = 0x%08X\n", imp_entry->EntryAddress);

    return FALSE;
}

// }}}

void test_callback_resolve_imports(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG appdata;
    int result = 0;
    BOOL bConfirm = FALSE;
    lam_arg2 buffers;

    pe = _load_and_map_test_data2(NULL, &buffers, 
            "datafiles\\pe_normal32_iat.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data2() failed.");
        return;
    }

    appdata.hModule = NULL;
    appdata.dwLastError = 0;
    appdata.lpErrInfo = NULL;
    appdata.err = CHEAP2EL_EC_NONE;

    // confirm original iat addresses
    cheap2el_enumerate_import_tables(pe, 
            _test_callback_resolve_imports_cbA, 
            "pe_normal32_iat_stubA.dll", (LPVOID)(&bConfirm));
    cheap2el_enumerate_import_tables(pe, 
            _test_callback_resolve_imports_cbB, 
            "pe_normal32_iat_stubB.dll", (LPVOID)(&bConfirm));

    // update base relocations
    result = cheap2el_enumerate_import_directory(pe, 
            cheap2el_callback_resolve_imports, (LPVOID)(&appdata));
    if (0 != appdata.dwLastError) {
        _print_last_error(appdata.dwLastError);
    }
    CU_ASSERT_EQUAL(appdata.dwLastError, 0);
    CU_ASSERT_EQUAL(appdata.lpErrInfo, NULL);
    CU_ASSERT_EQUAL(appdata.err, 0);
    CU_ASSERT_EQUAL(result, 4);

    // confirm updated iat addresses
    bConfirm = TRUE;
    cheap2el_enumerate_import_tables(pe, 
            _test_callback_resolve_imports_cbA, 
            "pe_normal32_iat_stubA.dll", (LPVOID)(&bConfirm));
    cheap2el_enumerate_import_tables(pe, 
            _test_callback_resolve_imports_cbB, 
            "pe_normal32_iat_stubB.dll", (LPVOID)(&bConfirm));

    GlobalFree(pe);
    if (!VirtualFree(buffers.lpVirtualPage, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualFree() error");
    }
    GlobalFree(buffers.lpFileBuffer);
}

// }}}
// {{{ test_pseudo_load()

void test_pseudo_load(void)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG arg;
    lam_arg2 buffers;
    DWORD dwptr;
    int (*pfunc)(int, int);
    BOOL (APIENTRY *dllMain)(HANDLE, DWORD, LPVOID);
    int (*pfunc2)(UINT, LPTSTR, int);
    char str_res_buf[1024];
    int str_res_buf_sz = sizeof(str_res_buf)/sizeof(str_res_buf[0]);

    pe = _load_and_map_test_data2(NULL, &buffers, 
            "datafiles\\pe_normal32_iat.dll", &err);
    if (NULL == pe) {
        CU_FAIL("_load_and_map_test_data2() failed.");
        return;
    }

    CU_ASSERT_TRUE(cheap2el_pseudo_load_address_resolver(pe, &arg));
    if (0 != arg.dwLastError) {
        _print_last_error(arg.dwLastError);
    }
    CU_ASSERT_EQUAL(arg.dwLastError, 0);
    CU_ASSERT_EQUAL(arg.lpErrInfo, NULL);
    CU_ASSERT_EQUAL(arg.err, 0);

    // manually call DllMain()
    dwptr = pe->ntHeaders->OptionalHeader.AddressOfEntryPoint + 
        pe->dwActualImageBase;
    dllMain = (BOOL (APIENTRY*)(HANDLE, DWORD, LPVOID))(dwptr);
    CU_ASSERT_TRUE(dllMain(
                (HANDLE)pe->dwActualImageBase, 
                DLL_PROCESS_ATTACH, 
                (LPVOID)NULL));

    dwptr = cheap2el_get_export_rva_by_name(pe, "func1") + pe->dwActualImageBase;
    pfunc = (int (*)(int, int))(dwptr);
    CU_ASSERT_EQUAL(pfunc(1, 2), 106);

    dwptr = cheap2el_get_export_rva_by_name(pe, "func2") + pe->dwActualImageBase;
    pfunc = (int (*)(int, int))(dwptr);
    CU_ASSERT_EQUAL(pfunc(1, 2), 210);

    dwptr = cheap2el_get_export_rva_by_name(pe, "MyLoadString") + pe->dwActualImageBase;
    pfunc2 = (int (*)(UINT, LPTSTR, int))(dwptr);
    CU_ASSERT_TRUE(pfunc2(40000, str_res_buf, str_res_buf_sz));
    CU_ASSERT_STRING_EQUAL(str_res_buf, "English Text.");

    GlobalFree(pe);
    if (!VirtualFree(buffers.lpVirtualPage, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        CU_FAIL("VirtualFree() error");
    }
    GlobalFree(buffers.lpFileBuffer);
}

// }}}
// {{{ test_version()

void test_version(void)
{
    DWORD major, minor, rel;
    cheap2el_version(&major, &minor, &rel);
    CU_ASSERT_EQUAL(major, CHEAP2EL_VERSION_MAJOR);
    CU_ASSERT_EQUAL(minor, CHEAP2EL_VERSION_MINOR);
    CU_ASSERT_EQUAL(rel, CHEAP2EL_VERSION_RELEASE);
}

// }}}

