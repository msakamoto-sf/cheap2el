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
 * cheap2el : COFF LIB function unittests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"
#include "test_00_util.h"

// {{{ test_coff_lib_get_am_size()

void test_coff_lib_get_am_size(void)
{
    IMAGE_ARCHIVE_MEMBER_HEADER amhs[] = {
        {
            "/               ", // BYTE Name[16]
            "1278833156  ",    // BYTE Date[12]
            "      ", // BYTE UserID[6]
            "      ", // BYTE GroupID[6]
            "0       ", // BYTE Mode[8]
            "0         ", // BYTE Size[10]
            "`\x0A" // BYTE EndHeader[2]
        },
        {
            "/               ", // BYTE Name[16]
            "1278833156  ",    // BYTE Date[12]
            "      ", // BYTE UserID[6]
            "      ", // BYTE GroupID[6]
            "0       ", // BYTE Mode[8]
            "1         ", // BYTE Size[10]
            "`\x0A" // BYTE EndHeader[2]
        },
        {
            "/               ", // BYTE Name[16]
            "1278833156  ",    // BYTE Date[12]
            "      ", // BYTE UserID[6]
            "      ", // BYTE GroupID[6]
            "0       ", // BYTE Mode[8]
            "99999999  ", // BYTE Size[10]
            "`\x0A" // BYTE EndHeader[2]
        },
        {
            "/               ", // BYTE Name[16]
            "1278833156  ",    // BYTE Date[12]
            "      ", // BYTE UserID[6]
            "      ", // BYTE GroupID[6]
            "0       ", // BYTE Mode[8]
            "999A9999  ", // BYTE Size[10]
            "`\x0A" // BYTE EndHeader[2]
        }
    };

    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_am_size(&amhs[0]), 0);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_am_size(&amhs[1]), 1);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_am_size(&amhs[2]), 99999999);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_am_size(&amhs[3]), 999);
}

// }}}
// {{{ test_coff_lib_get_longname_offset()

void test_coff_lib_get_longname_offset(void)
{
    char *data[] = {
        CHEAP2EL_COFF_LIB_AM_SPSTR "0",
        CHEAP2EL_COFF_LIB_AM_SPSTR "1",
        CHEAP2EL_COFF_LIB_AM_SPSTR "123",
        "1234" CHEAP2EL_COFF_LIB_AM_SPSTR
    };

    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_longname_offset(data[0]), 0);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_longname_offset(data[1]), 1);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_longname_offset(data[2]), 123);
    CU_ASSERT_EQUAL(
            cheap2el_coff_lib_get_longname_offset(data[3]), 0);
}

// }}}
// {{{ test_coff_lib_map_from_memory()

void test_coff_lib_map_from_memory(void)
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    LPVOID lpvBuffer = NULL;
    CHEAP2EL_ERROR_CODE err;

    // lpMemoryBuffer == NULL
    lib = cheap2el_coff_lib_map_from_memory(NULL, &err);
    CU_ASSERT_PTR_NULL(lib);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER);

    // not coff library file
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_coff01.obj");
    lib = cheap2el_coff_lib_map_from_memory(lpvBuffer, &err);
    CU_ASSERT_PTR_NULL(lib);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_LIB_SIGNATURE);
    GlobalFree(lpvBuffer);

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_lib01.lib");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    lib = NULL; err = 0;
    lib = cheap2el_coff_lib_map_from_memory(lpvBuffer, &err);
    CU_ASSERT_PTR_NOT_NULL(lib);
    CU_ASSERT_EQUAL(err, 0);

    CU_ASSERT_EQUAL(lib->dwBase, (DWORD)lpvBuffer);
    CU_ASSERT_EQUAL((DWORD)(lib->amh_linker1), 
            lib->dwBase + IMAGE_ARCHIVE_START_SIZE);

    CU_ASSERT_EQUAL(lib->linker2.NumberOfMembers, 4);
    CU_ASSERT_EQUAL(lib->linker2.NumberOfSymbols, 8);

    GlobalFree(lib);
    GlobalFree(lpvBuffer);
}

// }}}
// {{{ test_coff_lib_map_from_memory_3h()

void test_coff_lib_map_from_memory_3h(void)
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    CHEAP2EL_ERROR_CODE err = 0;
    char *data[] = {
        "!<arch>\x0A"
            "!"
            "               1278833156              0       0         `\x0A",
        "!<arch>\x0A"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "               1278833156              0       1         `\x0A"
            "1\x0A"
            "!"
            "               1278833156              0       0         `\x0A",
        "!<arch>\x0A"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "               1278833156              0       1         `\x0A"
            "1\x0A"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "               1278833156              0       8         `\x0A"
            "\x00\x00\x00\x00" "\x00\x00\x00\x00"
            "!"
            "               1278833156              0       0         `\x0A",
        "!<arch>\x0A"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "               A                       0       1         `\x0A"
            "a\x0A"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "               B                       0       8         `\x0A"
            "\x00\x00\x00\x00" "\x00\x00\x00\x00"
            CHEAP2EL_COFF_LIB_AM_SPSTR
            CHEAP2EL_COFF_LIB_AM_SPSTR
            "              C                       0       3         `\x0A"
            "def\x0A"
            "/"
            "0              D                       0       0         `\x0A",
        ""
    };

    lib = NULL; err = 0;
    lib = cheap2el_coff_lib_map_from_memory(data[0], &err);
    CU_ASSERT_PTR_NULL(lib);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_VALID_COFF_LIB);

    lib = NULL; err = 0;
    lib = cheap2el_coff_lib_map_from_memory(data[1], &err);
    CU_ASSERT_PTR_NULL(lib);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_VALID_COFF_LIB);

    lib = NULL; err = 0;
    lib = cheap2el_coff_lib_map_from_memory(data[2], &err);
    CU_ASSERT_PTR_NULL(lib);
    CU_ASSERT_EQUAL(err, CHEAP2EL_EC_NOT_VALID_COFF_LIB);

    lib = NULL; err = 0;
    lib = cheap2el_coff_lib_map_from_memory(data[3], &err);
    CU_ASSERT_PTR_NOT_NULL(lib);
    CU_ASSERT_EQUAL('A', lib->amh_linker1->Date[0]);
    CU_ASSERT_EQUAL('B', lib->amh_linker2->Date[0]);
    CU_ASSERT_EQUAL('C', lib->amh_longname->Date[0]);
    CU_ASSERT_EQUAL('D', lib->amh_objects->Date[0]);
    CU_ASSERT_FALSE(memcmp("a", lib->am_linker1, 1));
    CU_ASSERT_FALSE(memcmp("\x00\x00", lib->am_linker2, 2));
    CU_ASSERT_FALSE(memcmp("def", lib->am_longname, 3));
}

// }}}
// {{{ test_coff_lib_enumerate_members()

static BOOL
_test_coff_lib_enumerate_members_cbN(
        PCHEAP2EL_COFF_LIB lib,
        PIMAGE_ARCHIVE_MEMBER_HEADER amh,
        char *sz_longname,
        LPVOID member,
        size_t size,
        int order,
        LPVOID lpApplicationData
        )
{
    int *when_return_true  = (int*)lpApplicationData;
    struct {
        BYTE on[16];
        char *ln;
        int sz;
    } expected[] = {
        {"a.obj/          ", "a.obj", 710},
        {"/0              ", "source_foo123.obj", 650},
        {"/18             ", "source_foo12.obj", 640},
        {"source_foo1.obj/", "source_foo1.obj", 640}
    };

    if (order == *when_return_true) {
        return TRUE;
    }

    CU_ASSERT_FALSE(memcmp(amh->Name, expected[order].on, 1));
    CU_ASSERT_STRING_EQUAL(sz_longname, expected[order].ln);
    CU_ASSERT_EQUAL(size, expected[order].sz);
    return FALSE;
}

void test_coff_lib_enumerate_members(void)
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    LPVOID lpvBuffer = NULL;
    CHEAP2EL_ERROR_CODE err;
    int i, result = 0, appdata;

    // loadding and mapping test data
    lpvBuffer = _load_test_data("datafiles\\pe_normal32_lib01.lib");
    if (NULL == lpvBuffer) {
        CU_FAIL("load error");
        return;
    }
    err = 0;
    lib = cheap2el_coff_lib_map_from_memory(lpvBuffer, &err);

    // callback return false
    appdata = -1;
    result = cheap2el_coff_lib_enumerate_members(lib,
            _test_coff_lib_enumerate_members_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 4);

    // callback return true (1st entry)
    appdata = 0;
    result = cheap2el_coff_lib_enumerate_members(lib,
            _test_coff_lib_enumerate_members_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 1);

    // callback return true (2nd entry)
    appdata = 1;
    result = cheap2el_coff_lib_enumerate_members(lib,
            _test_coff_lib_enumerate_members_cbN, (LPVOID)(&appdata));
    CU_ASSERT_EQUAL(result, 2);

    // no callback
    result = cheap2el_coff_lib_enumerate_members(lib, NULL, (LPVOID)NULL);
    CU_ASSERT_FALSE(result);

    GlobalFree(lib);
    GlobalFree(lpvBuffer);
}

// }}}

/**
 * Local Variables:
 * mode: php
 * coding: iso-8859-1
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * indent-tabs-mode: nil
 * End:
 * vim: set expandtab tabstop=4 shiftwidth=4:
 */
