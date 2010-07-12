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
 * cheap2el : CUnit tests main
 *
 * $Id$
 */

#include <stdio.h>

#include "Basic.h"

// {{{ CU_TestInfo tests_mapper[] and externs

extern void test_get_sizeofimage_from_file(void);
extern void test_map_to_memory_failure(void);
extern void test_map_to_memory_success(void);
extern void test_map_from_loaded_image_failure(void);
extern void test_map_from_loaded_image_success(void);
extern void test_get_export_directory_failure(void);
extern void test_get_export_directory_success1(void);
extern void test_get_export_directory_success2(void);

CU_TestInfo tests_mapper[] = {
    {"test_get_sizeofimage_from_file", test_get_sizeofimage_from_file},
    {"test_map_to_memory_failure", test_map_to_memory_failure},
    {"test_map_to_memory_success", test_map_to_memory_success},
    {"test_map_from_loaded_image_failure", test_map_from_loaded_image_failure},
    {"test_map_from_loaded_image_success", test_map_from_loaded_image_success},
    {"test_get_export_directory_failure", test_get_export_directory_failure},
    {"test_get_export_directory_success1", test_get_export_directory_success1},
    {"test_get_export_directory_success2", test_get_export_directory_success2},
    CU_TEST_INFO_NULL,
};

// }}}
// {{{ CU_TestInfo tests_enumerator[] and externs

extern void test_enumerate_export_tables_0(void);
extern void test_enumerate_export_tables(void);
extern void test_enumerate_export_tables_forward(void);
extern void test_get_export_rva_by_name(void);
extern void test_get_export_rva_by_ordinal1(void);
extern void test_get_export_rva_by_ordinal2(void);
extern void test_enumerate_import_directory_0(void);
extern void test_enumerate_import_directory_1(void);
extern void test_enumerate_import_directory_N(void);
extern void test_enumerate_import_tables_0(void);
extern void test_enumerate_import_tables_1(void);
extern void test_enumerate_import_tables_M(void);
extern void test_enumerate_bound_imports_0(void);
extern void test_enumerate_bound_imports_1(void);
extern void test_enumerate_bound_imports_N(void);
extern void test_enumerate_delay_load_0(void);
extern void test_enumerate_delay_load_1(void);
extern void test_enumerate_delay_load_N1(void);
extern void test_enumerate_delayload_tables_0(void);
extern void test_enumerate_delayload_tables_N1(void);
extern void test_enumerate_delayload_tables_NM(void);
extern void test_enumerate_base_relocations_0(void);
extern void test_enumerate_base_relocations_1(void);
extern void test_enumerate_base_relocations_N(void);

CU_TestInfo tests_enumerator[] = {
    {"test_enumerate_export_tables_0", test_enumerate_export_tables_0},
    {"test_enumerate_export_tables_forward", test_enumerate_export_tables_forward},
    {"test_get_export_rva_by_name", test_get_export_rva_by_name},
    {"test_get_export_rva_by_ordinal1", test_get_export_rva_by_ordinal1},
    {"test_get_export_rva_by_ordinal2", test_get_export_rva_by_ordinal2},
    {"test_enumerate_import_directory_0", test_enumerate_import_directory_0},
    {"test_enumerate_import_directory_1", test_enumerate_import_directory_1},
    {"test_enumerate_import_directory_N", test_enumerate_import_directory_N},
    {"test_enumerate_import_tables_0", test_enumerate_import_tables_0},
    {"test_enumerate_import_tables_1", test_enumerate_import_tables_1},
    {"test_enumerate_import_tables_M", test_enumerate_import_tables_M},
    {"test_enumerate_bound_imports_0", test_enumerate_bound_imports_0},
    {"test_enumerate_bound_imports_1", test_enumerate_bound_imports_1},
    {"test_enumerate_bound_imports_N", test_enumerate_bound_imports_N},
    {"test_enumerate_delay_load_0", test_enumerate_delay_load_0},
    {"test_enumerate_delay_load_1", test_enumerate_delay_load_1},
    {"test_enumerate_delay_load_N1", test_enumerate_delay_load_N1},
    {"test_enumerate_delayload_tables_0", test_enumerate_delayload_tables_0},
    {"test_enumerate_delayload_tables_N1", test_enumerate_delayload_tables_N1},
    {"test_enumerate_delayload_tables_NM", test_enumerate_delayload_tables_NM},
    {"test_enumerate_base_relocations_0", test_enumerate_base_relocations_0},
    {"test_enumerate_base_relocations_1", test_enumerate_base_relocations_1},
    {"test_enumerate_base_relocations_N", test_enumerate_base_relocations_N},
    CU_TEST_INFO_NULL,
};

// }}}
// {{{ CU_TestInfo tests_callbacks[] and externs

extern void test_callback_update_base_relocations1(void);
extern void test_callback_update_base_relocations2(void);
extern void test_callback_update_base_relocations3(void);
extern void test_callback_resolve_imports(void);
extern void test_pseudo_load(void);

CU_TestInfo tests_callbacks[] = {
    {"test_callback_update_base_relocations1", test_callback_update_base_relocations1},
    {"test_callback_update_base_relocations2", test_callback_update_base_relocations2},
    {"test_callback_update_base_relocations3", test_callback_update_base_relocations3},
    {"test_callback_resolve_imports", test_callback_resolve_imports},
    {"test_pseudo_load", test_pseudo_load},
    CU_TEST_INFO_NULL,
};

// }}}
// {{{ CU_TestInfo tests_version[] and externs

extern void test_version(void);

CU_TestInfo tests_version[] = {
    {"test_version", test_version},
    CU_TEST_INFO_NULL,
};

// }}}
// {{{ CU_TestInfo tests_coff_obj[] and externs

extern void test_coff_obj_map_from_memory(void);
extern void test_coff_obj_walkthrough_sections(void);
extern void test_coff_obj_enumerate_relocations(void);
extern void test_coff_obj_enumerate_symbols(void);

CU_TestInfo tests_coff_obj[] = {
    {"test_coff_obj_map_from_memory", test_coff_obj_map_from_memory},
    {"test_coff_obj_walkthrough_sections", test_coff_obj_walkthrough_sections},
    {"test_coff_obj_enumerate_relocations", test_coff_obj_enumerate_relocations},
    {"test_coff_obj_enumerate_symbols", test_coff_obj_enumerate_symbols},
    CU_TEST_INFO_NULL,
};

// }}}
// {{{ CU_TestInfo tests_coff_lib[] and externs

extern void test_coff_lib_get_am_size(void);
extern void test_coff_lib_get_longname_offset(void);
extern void test_coff_lib_map_from_memory(void);
extern void test_coff_lib_map_from_memory_3h(void);
extern void test_coff_lib_map_nolongname(void);
extern void test_coff_lib_enumerate_members(void);
extern void test_coff_lib_enumerate_symbolsN(void);

CU_TestInfo tests_coff_lib[] = {
    {"test_coff_lib_get_am_size", test_coff_lib_get_am_size},
    {"test_coff_lib_get_longname_offset", test_coff_lib_get_longname_offset},
    {"test_coff_lib_map_from_memory", test_coff_lib_map_from_memory},
    {"test_coff_lib_map_from_memory_3h", test_coff_lib_map_from_memory_3h},
    {"test_coff_lib_map_nolongname", test_coff_lib_map_nolongname},
    {"test_coff_lib_enumerate_members", test_coff_lib_enumerate_members},
    {"test_coff_lib_enumerate_symbolsN", test_coff_lib_enumerate_symbolsN},
    CU_TEST_INFO_NULL,
};

// }}}

CU_SuiteInfo suites[] = {
    {"cheap2el_mapper", NULL, NULL, tests_mapper},
    {"cheap2el_enumerator", NULL, NULL, tests_enumerator},
    {"cheap2el_callbacks", NULL, NULL, tests_callbacks},
    {"cheap2el_version", NULL, NULL, tests_version},
    {"cheap2el_coff_obj", NULL, NULL, tests_coff_obj},
    {"cheap2el_coff_lib", NULL, NULL, tests_coff_lib},
    CU_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
    CU_ErrorCode cuerr;

    cuerr = CU_initialize_registry();
    if (cuerr) {
        fprintf(stderr, "test registry initialization failed - %s\n", 
                CU_get_error_msg());
        exit(-1);
    }
    cuerr = CU_register_suites(suites);
    if (CUE_SUCCESS != cuerr) {
        fprintf(stderr, "suite registration failed - %s\n", 
                CU_get_error_msg());
        exit(-1);
    }
    CU_basic_set_mode(CU_BRM_NORMAL);
    CU_set_error_action(CUEA_FAIL);
    printf("\nTests completed with return value %d.\n", CU_basic_run_tests());
    CU_cleanup_registry();
    return 0;
}

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
