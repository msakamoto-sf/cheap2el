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
 * replace_impaddr : target program for replacing "MessageBoxA" import address
 *
 * $Id$
 */

#include <windows.h>
#include <stdio.h>

int __declspec(dllimport) func1(int a);
int __declspec(dllimport) WINAPI func2(HWND, LPCTSTR, LPCTSTR, UINT);

int main(int argc, char *argv[])
{
    MessageBoxA(NULL, "This is Original MessageBoxA()", "target.exe", MB_OK);

    printf("\nKick hookctrl.exe and click 'Hook On', then, hit return key.\n");
    getchar();

    printf("\nAre you ready ? okay, hit return key.\n");
    getchar();

    // stub call
    MessageBoxA(NULL, "This is Original MessageBoxA()", "target.exe", MB_OK);

    printf("func1(100) = %d\n", func1(100));
    printf("MessageBoxA() = %d\n", 
            MessageBoxA(NULL, "message text", "caption", MB_OKCANCEL));

    printf("func2() = %d\n", 
            func2(NULL, "message text", "caption", MB_OKCANCEL));

    return 0;
}

