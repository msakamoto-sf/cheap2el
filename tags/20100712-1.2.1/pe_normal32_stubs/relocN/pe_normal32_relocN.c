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
 * cheap2el : stub dll (N relocations) for cunit testing
 *
 * $Id$
 */

#include <windows.h>

int callback1(int a) { return a + 1; }

typedef int (*MYCB)(int a);

MYCB my_callback = callback1;

void __declspec(dllexport) func1(DWORD sleep_ms)
{
	Sleep(sleep_ms);
	return;
}

void __declspec(dllexport) func2()
{
	MessageBoxA(NULL, "foo", "bar", MB_OK);
	return;
}
