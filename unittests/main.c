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

extern void test_get_sizeofimage_from_file(void);
extern void test_map_to_memory_failure(void);
extern void test_map_to_memory_success(void);
extern void test_map_from_loaded_image_failure(void);
extern void test_map_from_loaded_image_success(void);

CU_TestInfo test_array1[] = {
    {"test_get_sizeofimage_from_file", test_get_sizeofimage_from_file},
    {"test_map_to_memory_failure", test_map_to_memory_failure},
    {"test_map_to_memory_success", test_map_to_memory_success},
    {"test_map_from_loaded_image_failure", test_map_from_loaded_image_failure},
    {"test_map_from_loaded_image_success", test_map_from_loaded_image_success},
    CU_TEST_INFO_NULL,
};

CU_SuiteInfo suites[] = {
    {"suite1", NULL, NULL, test_array1},
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
