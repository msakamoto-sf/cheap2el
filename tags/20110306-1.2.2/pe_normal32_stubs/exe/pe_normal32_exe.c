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
 * cheap2el : stub exe for cunit testing
 *
 * $Id$
 */

#include <windows.h>

#include "resource.h"

#define MYWNDCLSNAME "MyWindowClass"

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(
	HINSTANCE hInst, 
	HINSTANCE hPrevInst, 
	LPSTR lpCmdLine, 
	int nCmdShow)
{
	WNDCLASS wndcls;
	HWND hWnd;
	MSG msg;
	ZeroMemory(&wndcls, sizeof(wndcls));
	wndcls.lpfnWndProc = WndProc;
	wndcls.hInstance = hInst;
	wndcls.hIcon = LoadIcon(0, IDI_APPLICATION);
	wndcls.hCursor = LoadCursor(0, IDC_ARROW);
	wndcls.hbrBackground = (HBRUSH)COLOR_BACKGROUND;
	
	// menu resource
	wndcls.lpszMenuName =  MAKEINTRESOURCE(IDR_MENU1);

	wndcls.lpszClassName = MYWNDCLSNAME;
	if (0 == RegisterClass(&wndcls)) {
		return -1;
	}
	
	hWnd = CreateWindow(
		MYWNDCLSNAME, 
		"My Window", 
		WS_OVERLAPPEDWINDOW, 
		CW_USEDEFAULT, CW_USEDEFAULT, 
		CW_USEDEFAULT, CW_USEDEFAULT, 
		0, 0, hInst, NULL);
	if (0 == hWnd) {
		return -2;
	}
	
	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	
	while (GetMessage(&msg, 0, 0, 0)) {
		DispatchMessage(&msg);
	}
	
	return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDM_FILE_OPEN:
			MessageBox(hWnd, "Open", "File Menu", MB_OK);
			break;
		case IDM_FILE_SAVE:
			MessageBox(hWnd, "Save", "File Menu", MB_OK);
			break;
		case IDM_FILE_EXIT:
			MessageBox(hWnd, "Exit", "File Menu", MB_OK);
			PostQuitMessage(0);
			break;
		case IDM_HELP_VERSION:
			MessageBox(hWnd, "Version", "Help Menu", MB_OK);
			break;
		} 
		return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}
