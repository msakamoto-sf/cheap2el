cheap2el - cheap pe library

cheap2el is tiny library for exploring Windows PE(Portable Executable) format
files in C/C++ programming language.

//-----------------------------------------------------------------------------
// MAIN FEATURES
//-----------------------------------------------------------------------------

- enumerating headers.
- enumerating import tables(IAT/INT).
-- include bound imports, delay imports.
- enumerating export tables(EAT/ENT).
- dll pseudo loading.


//-----------------------------------------------------------------------------
// HOW TO BUILD
//-----------------------------------------------------------------------------

a) open your visual studio command prompt.
b) cd to this directory.
c) do "nmake -f Makefile.mk"

If all works fine, "cheap2el.lib" will be found in this directory.

All unittest and samples are compiled, and tested on...
  Compiled Platform : Pentium4, Windows XP SP3 (Japanese)
  SDK : Microsoft Visual C++ 2008 Express Edition SP1 - Japanese
  Compiler & Linker versions :
  > cl
  Microsoft(R) 32-bit C/C++ Optimizing Compiler Version 15.00.30729.01 for 80x86
  Copyright (C) Microsoft Corporation.  All rights reserved.
  > link
  Microsoft (R) Incremental Linker Version 9.00.30729.01
  Copyright (C) Microsoft Corporation.  All rights reserved.


//-----------------------------------------------------------------------------
// HOW TO USE
//-----------------------------------------------------------------------------

a) Add include path to "cheap2el.h" in your project's compiler option.
b) Add library path to "cheap2el.lib" in your project's linker option.
c) Read unittest source code to understand cheap2el api usage.


//-----------------------------------------------------------------------------
// SPECIAL THANKS
//-----------------------------------------------------------------------------

MSDN Magazine/MSJ articles written by Matt Pietrek:
- February 2002 Vol 17 No. 2
  Inside Windows: An In-Depth Look into the Win32 Portable Executable File Format (Part I)
- March 2002 Vol 17 No. 3
  Inside Windows: An In-Depth Look into the Win32 Portable Executable File Format (Part II)

Japanese PE format web resource:
http://hp.vector.co.jp/authors/VA050396/index.html


Copyright 2010 sakamoto.gsyc.3s@gmail.com
