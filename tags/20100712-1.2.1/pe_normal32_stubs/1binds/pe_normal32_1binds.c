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
 * cheap2el : stub dll (1 binds main dll) main
 *
 * $Id$
 */

__declspec(dllimport) int funcA(int a, int b);
__declspec(dllimport) int funcB(int a, int b);

int __declspec(dllexport) myfunc(void)
{
	int a = funcA(1, 2);
	int b = funcB(1, 2);
	return a + b;
}
