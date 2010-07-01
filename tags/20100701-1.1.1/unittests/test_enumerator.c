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
 * cheap2el : DataDirectory enumerate function unittests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"
#include "test_00_util.h"

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

