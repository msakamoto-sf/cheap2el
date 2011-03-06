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
 * cheap2el : version function unittests
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>
#include "CUnit.h"
#include "test_00_util.h"

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

