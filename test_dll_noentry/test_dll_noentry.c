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
 * cheap2el : stub dll (without entry point) for cunit testing
 *
 * $Id$
 */

#include <windows.h>

int __declspec(dllexport) varsA = 100;
int varsB = 200;

int __declspec(dllexport) foo(int a, int b)
{
	return a + b;
}

int __declspec(dllexport) bar(int a, int b)
{
	return a * b;
}

#define MAKE_FUNCX(N) int func##N(int a, int b) { return a + b + N; }

MAKE_FUNCX(1)
MAKE_FUNCX(2)
MAKE_FUNCX(3)
MAKE_FUNCX(4)
MAKE_FUNCX(5)
MAKE_FUNCX(6)
MAKE_FUNCX(7)
