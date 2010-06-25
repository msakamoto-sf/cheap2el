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
 * cheap2el : pre-defined callbacks and short-cut function unittests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"
#include "test_00_util.h"

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

