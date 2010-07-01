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
 * cheap2el : stub dll (without entry, 1imps) for cunit testing
 *
 * $Id$
 */

#include <windows.h>

int __declspec(dllimport) func1(int a);
int __declspec(dllimport) func2(int a);

void __declspec(dllexport) funcA(DWORD sleep_ms)
{
	Sleep(sleep_ms + func1(sleep_ms));
	return;
}

void __declspec(dllexport) funcB(int a)
{
	int b = func2(a);
	MessageBox(NULL, "foo", "bar", MB_OK);
	return;
}
