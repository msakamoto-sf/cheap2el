# cheap2el - cheap pe library #

cheap2el is tiny library for exploring Windows PE(Portable Executable) format files in C/C++ programming language.

## MAIN FEATURES ##

  * enumerating headers.
  * enumerating import tables(IAT/INT), including bound imports, delay imports.
  * enumerating export tables(EAT/ENT).
  * dll pseudo loading.
  * enumerating COFF Object file sections, relocations, symbols.
  * enumerating COFF LIB file archive members, linker members.

## HOW TO BUILD ##

  1. open your visual studio command prompt.
  2. cd to top of source directory.
  3. do
     1. `nmake cheap2el` (for cheap2el.lib) -> if build success, "cheap2el.lib" will be created in top of source directory.
     2. `nmake test` (for unittests) 
     3. `nmake samples` (for samples)
     4. `nmake clean` (remove all obj, exe, dlls)


All unittest and samples are compiled, and tested on...
```
OS  : Windows 10 Pro (64bit, Japanese)

SDK : Microsoft Visual Studio 2017 Community Edition + Windows SDK 10.0.16299.0

Build : from x86 Native Tools Command Prompt

Compiler & Linker Version :
> cl
Microsoft(R) C/C++ Optimizing Compiler Version 19.13.26131.1 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

> link
Microsoft (R) Incremental Linker Version 14.13.26131.1
Copyright (C) Microsoft Corporation.  All rights reserved.
```

## HOW TO USE ##

  * Add include path to "cheap2el.h" in your project's compiler option.
  * Add library path to "cheap2el.lib" in your project's linker option.
  * Read unittest source code to understand cheap2el api usage.

## SPECIAL THANKS ##

MSDN Magazine/MSJ articles written by Matt Pietrek:
  * February 2002 Vol 17 No. 2, "Inside Windows: An In-Depth Look into the Win32 Portable Executable File Format (Part I)"
  * March 2002 Vol 17 No. 3, "Inside Windows: An In-Depth Look into the Win32 Portable Executable File Format (Part II)"

Japanese PE format web resource:
  * http://hp.vector.co.jp/authors/VA050396/index.html

c-unit:
  * http://code.google.com/p/c-unit/