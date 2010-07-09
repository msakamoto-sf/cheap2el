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
 * cheap2el : COFF Object function unittests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"
#include "test_00_util.h"

// {{{ test_coff_obj_map_from_memory()

void test_coff_obj_map_from_memory(void)
{
    PCHEAP2EL_COFF_OBJ coff = NULL;
    LPVOID lpvBuffer = NULL;
    CHEAP2EL_ERROR_CODE err;

    // lpMemoryBuffer == NULL
    coff = cheap2el_coff_obj_map_from_memory(NULL, &err);
    CU_ASSERT_PTR_NULL(coff);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER);

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_coff01.obj");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    err = 0;
    coff = cheap2el_coff_obj_map_from_memory(lpvBuffer, &err);
    CU_ASSERT_PTR_NOT_NULL(coff);
    CU_ASSERT_EQUAL(err, 0);

    CU_ASSERT_EQUAL(coff->dwBase, (DWORD)lpvBuffer);
    CU_ASSERT_EQUAL((DWORD)(coff->fileHeader), coff->dwBase);
    CU_ASSERT_EQUAL((DWORD)(coff->sectionHeaders), coff->dwBase + sizeof(IMAGE_FILE_HEADER));
    CU_ASSERT_EQUAL((DWORD)(coff->symbolTable), coff->dwBase + coff->fileHeader->PointerToSymbolTable);
/*
    printf("dwBase = 0x%08X\n", coff->dwBase);
    printf("fileHeader = 0x%08X\n", coff->fileHeader);
    printf("sectionHeaders = 0x%08X\n", coff->sectionHeaders);
    printf("symbolTable = 0x%08X\n", coff->symbolTable);
*/

    CU_ASSERT_EQUAL(0x014C, coff->fileHeader->Machine);
    CU_ASSERT_EQUAL(0x5, coff->fileHeader->NumberOfSections);
    CU_ASSERT_NOT_EQUAL(0x0, coff->fileHeader->TimeDateStamp);
    CU_ASSERT_EQUAL(0x037B, coff->fileHeader->PointerToSymbolTable);
    CU_ASSERT_EQUAL(0x19, coff->fileHeader->NumberOfSymbols);
    CU_ASSERT_EQUAL(0x0, coff->fileHeader->SizeOfOptionalHeader);
    CU_ASSERT_EQUAL(0x0, coff->fileHeader->Characteristics);
/*
    printf("Machine = 0x%04X\n", coff->fileHeader->Machine);
    printf("NumberOfSections = 0x%04X\n", coff->fileHeader->NumberOfSections);
    printf("TimeDateStamp = 0x%08X\n", coff->fileHeader->TimeDateStamp);
    printf("PointerToSymbolTable = 0x%08X\n", coff->fileHeader->PointerToSymbolTable);
    printf("NumberOfSymbols = 0x%08X\n", coff->fileHeader->NumberOfSymbols);
    printf("SizeOfOptionalHeader = 0x%04X\n", coff->fileHeader->SizeOfOptionalHeader);
    printf("Characteristics = 0x%04X\n", coff->fileHeader->Characteristics);
*/

    GlobalFree(coff);
    GlobalFree(lpvBuffer);
}

// }}}
// {{{ test_coff_obj_walkthrough_sections()

void test_coff_obj_walkthrough_sections(void)
{
    PCHEAP2EL_COFF_OBJ coff = NULL;
    LPVOID lpvBuffer = NULL;
    PIMAGE_SECTION_HEADER head;
    CHEAP2EL_ERROR_CODE err;
    int i;

    struct {
        char *name;
        DWORD size;
        DWORD ptr_raw;
        DWORD ptr_rel;
        WORD num_rel;
        DWORD character;
    } expected[5] = {
        {".drectve", 0x0000008A, 0x000000DC, 0x00000000, 0x0000, 0x00100A00},
        {".debug$S", 0x000000A0, 0x00000166, 0x00000000, 0x0000, 0x42100040},
        {".data",    0x00000018, 0x00000206, 0x00000000, 0x0000, 0xC0300040},
        {".text",    0x000000DB, 0x0000021E, 0x000002F9, 0x000D, 0x60500020},
        {".bss",     0x00000004, 0x00000000, 0x00000000, 0x0000, 0xC0300080}
    };

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_coff01.obj");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    err = 0;
    coff = cheap2el_coff_obj_map_from_memory(lpvBuffer, &err);
    head = coff->sectionHeaders;
    for (i = 0; i < coff->fileHeader->NumberOfSections; i++, head++) {
        CU_ASSERT_EQUAL(0x0, head->Misc.VirtualSize);
        CU_ASSERT_EQUAL(0x0, head->VirtualAddress);
        CU_ASSERT_EQUAL(0x0, head->PointerToLinenumbers);
        CU_ASSERT_EQUAL(0x0, head->NumberOfLinenumbers);
        CU_ASSERT_STRING_EQUAL(expected[i].name, head->Name);
        CU_ASSERT_EQUAL(expected[i].size, head->SizeOfRawData);
        CU_ASSERT_EQUAL(expected[i].ptr_raw, head->PointerToRawData);
        CU_ASSERT_EQUAL(expected[i].ptr_rel, head->PointerToRelocations);
        CU_ASSERT_EQUAL(expected[i].num_rel, head->NumberOfRelocations);
        CU_ASSERT_EQUAL(expected[i].character, head->Characteristics);
/*
        printf("[%d] = %s\n", i, head->Name);
        printf("[%d]VirtualSize = 0x%08X\n", i, head->Misc.VirtualSize);
        printf("[%d]VirtualAddress = 0x%08X\n", i, head->VirtualAddress);
        printf("[%d]SizeOfRawData = 0x%08X\n", i, head->SizeOfRawData);
        printf("[%d]PointerToRawData = 0x%08X\n", i, head->PointerToRawData);
        printf("[%d]PointerToRelocations = 0x%08X\n", i, head->PointerToRelocations);
        printf("[%d]PointerToLinenumbers = 0x%08X\n", i, head->PointerToLinenumbers);
        printf("[%d]NumberOfRelocations = 0x%04X\n", i, head->NumberOfRelocations);
        printf("[%d]NumberOfLinenumbers = 0x%04X\n", i, head->NumberOfLinenumbers);
        printf("[%d]Characteristics = 0x%08X\n", i, head->Characteristics);
*/
    }

    GlobalFree(coff);
    GlobalFree(lpvBuffer);
}

// }}}
// {{{ test_coff_obj_enumerate_relocations()

static BOOL
_test_coff_obj_enumerate_relocations_cb0(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        PIMAGE_RELOCATION reloc,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

static BOOL
_test_coff_obj_enumerate_relocations_cbN(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        PIMAGE_RELOCATION reloc,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    struct {
        DWORD va;
        DWORD sti;
        WORD t;
    } expected[13] = {
        {0x0000002B, 0x00000010, 0x0014},
        {0x00000055, 0x00000006, 0x0006},
        {0x0000005C, 0x00000009, 0x0006},
        {0x00000062, 0x00000018, 0x0014},
        {0x0000006E, 0x00000017, 0x0006},
        {0x00000074, 0x00000014, 0x0006},
        {0x0000007A, 0x00000017, 0x0006},
        {0x00000086, 0x0000000E, 0x0014},
        {0x00000093, 0x0000000B, 0x0006},
        {0x00000098, 0x0000000A, 0x0006},
        {0x000000A0, 0x00000013, 0x0006},
        {0x000000BD, 0x0000000F, 0x0014},
        {0x000000CF, 0x00000011, 0x0014},
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_EQUAL(reloc->VirtualAddress, expected[order].va);
    CU_ASSERT_EQUAL(reloc->SymbolTableIndex, expected[order].sti);
    CU_ASSERT_EQUAL(reloc->Type, expected[order].t);

/*
    printf("{0x%08X, 0x%08X, 0x%04X}, \n", 
            reloc->VirtualAddress, 
            reloc->SymbolTableIndex, 
            reloc->Type);
*/
    return FALSE;
}

void test_coff_obj_enumerate_relocations(void)
{
    PCHEAP2EL_COFF_OBJ coff = NULL;
    LPVOID lpvBuffer = NULL;
    PIMAGE_SECTION_HEADER head;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    int i, result = 0, appdata;

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_coff01.obj");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    err = 0;
    coff = cheap2el_coff_obj_map_from_memory(lpvBuffer, &err);

    // no relocations (.data section)
    head = coff->sectionHeaders;
    for (i = 0; i < coff->fileHeader->NumberOfSections; i++, head++) {
        if (!strcmp(".data", head->Name)) {
            break;
        }
    }
    result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
            _test_coff_obj_enumerate_relocations_cb0, (LPVOID)(&indicator));
    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // more relocations (.text section)
    head = coff->sectionHeaders;
    for (i = 0; i < coff->fileHeader->NumberOfSections; i++, head++) {
        if (!strcmp(".text", head->Name)) {
            break;
        }
    }

    // callback return false
    appdata = -1;
    result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
            _test_coff_obj_enumerate_relocations_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 13);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
            _test_coff_obj_enumerate_relocations_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (2nd entry)
    appdata = 1;
    result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
            _test_coff_obj_enumerate_relocations_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // no callback
    result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
            NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(coff);
    GlobalFree(lpvBuffer);
}

// }}}
// {{{ test_coff_obj_enumerate_symbols()

static BOOL
_test_coff_obj_enumerate_symbols_cb0(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SYMBOL symbol,
        char *symname,
        PIMAGE_AUX_SYMBOL aux_head,
        int order,
        LPVOID lpApplicationData
        )
{
    DWORD *p;
    p = (DWORD*)lpApplicationData;
    *p = 1;
    return FALSE;
}

static BOOL
_test_coff_obj_enumerate_symbols_cbN(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SYMBOL symbol,
        char *symname,
        PIMAGE_AUX_SYMBOL aux_head,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    struct {
        char *name;
        DWORD v;
        SHORT sect;
        WORD t;
        BYTE stc;
        BYTE auxn;
    } expected[20] = {
        {"@comp.id", 0x00837809, -1, 0x0000, 0x3, 0x0},
        {"@feat.00", 0x00000001, -1, 0x0000, 0x3, 0x0},
        {".drectve", 0x00000000, 1, 0x0000, 0x3, 0x1},
        {".debug$S", 0x00000000, 2, 0x0000, 0x3, 0x1},
        {"_vari02", 0x00000004, 0, 0x0000, 0x2, 0x0},
        {".data", 0x00000000, 3, 0x0000, 0x3, 0x1},
        {"_vari01", 0x00000000, 3, 0x0000, 0x2, 0x0},
        {"_msg", 0x00000004, 3, 0x0000, 0x2, 0x0},
        {"$SG77044", 0x00000014, 3, 0x0000, 0x3, 0x0},
        {".text", 0x00000000, 4, 0x0000, 0x3, 0x1},
        {"_func01dlle", 0x00000000, 4, 0x0020, 0x2, 0x0},
        {"_func01", 0x00000010, 4, 0x0020, 0x2, 0x0},
        {"_func01e", 0x00000000, 0, 0x0020, 0x2, 0x0},
        {"_func02", 0x00000040, 4, 0x0020, 0x2, 0x0},
        {"_func04", 0x00000050, 4, 0x0020, 0x2, 0x0},
        {"__imp__MessageBoxA@16", 0x00000000, 0, 0x0000, 0x2, 0x0},
        {"_vari01e", 0x00000000, 0, 0x0000, 0x2, 0x0},
        {".bss", 0x00000000, 5, 0x0000, 0x3, 0x1},
        {"_vari03", 0x00000000, 5, 0x0000, 0x3, 0x0},
        {"_func03", 0x000000B0, 4, 0x0020, 0x3, 0x0},
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_STRING_EQUAL(symname, expected[order].name);
    CU_ASSERT_EQUAL(symbol->Value, expected[order].v);
    CU_ASSERT_EQUAL(symbol->SectionNumber, expected[order].sect);
    CU_ASSERT_EQUAL(symbol->Type, expected[order].t);
    CU_ASSERT_EQUAL(symbol->StorageClass, expected[order].stc);
    CU_ASSERT_EQUAL(symbol->NumberOfAuxSymbols, expected[order].auxn);
    if (0 < symbol->NumberOfAuxSymbols) {
        CU_ASSERT_PTR_NOT_NULL(aux_head);
    }
/*
    printf("----------------------------[%d]\n", order);
    printf("name = %s\n", symname);
    printf("Value = 0x%08X\n", symbol->Value);
    printf("SectionNumber = %d\n", symbol->SectionNumber);
    printf("Type = 0x%04X\n", symbol->Type);
    printf("StorageClass = 0x%X\n", symbol->StorageClass);
    printf("NumberOfAuxSymbols = 0x%X\n", symbol->NumberOfAuxSymbols);
    printf("aux_head = 0x%08X\n", aux_head);
    printf("[%d] {\"%s\", 0x%08X, %d, 0x%04X, 0x%X, 0x%X}, \n",
            order, symname, symbol->Value, symbol->SectionNumber, 
            symbol->Type, symbol->StorageClass, symbol->NumberOfAuxSymbols);
*/
    return FALSE;
}

void test_coff_obj_enumerate_symbols(void)
{
    PCHEAP2EL_COFF_OBJ coff = NULL;
    LPVOID lpvBuffer = NULL;
    PIMAGE_SECTION_HEADER head;
    CHEAP2EL_ERROR_CODE err;
    DWORD indicator = 0;
    DWORD dwbuf;
    int i, result = 0, appdata;

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_coff01.obj");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    err = 0;
    coff = cheap2el_coff_obj_map_from_memory(lpvBuffer, &err);

    // no relocations (.data section)
    dwbuf = coff->fileHeader->NumberOfSymbols;
    coff->fileHeader->NumberOfSymbols = 0;
    result = cheap2el_coff_obj_enumerate_symbols(coff, 
            _test_coff_obj_enumerate_symbols_cb0, (LPVOID)(&indicator));
    CU_ASSERT_FALSE(result);
    CU_ASSERT_FALSE(indicator);

    // more relocations (.text section)
    coff->fileHeader->NumberOfSymbols = dwbuf;

    // callback return false
    appdata = -1;
    result = cheap2el_coff_obj_enumerate_symbols(coff, 
            _test_coff_obj_enumerate_symbols_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 20);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_coff_obj_enumerate_symbols(coff, 
            _test_coff_obj_enumerate_symbols_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (2nd entry)
    appdata = 1;
    result = cheap2el_coff_obj_enumerate_symbols(coff, 
            _test_coff_obj_enumerate_symbols_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // no callback
    result = cheap2el_coff_obj_enumerate_symbols(coff, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(coff);
    GlobalFree(lpvBuffer);
}

// }}}

