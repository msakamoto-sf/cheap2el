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
  1. cd to top of source directory.
  1. do `nmake` (library only) or `nmake test` (library and unittests)

If all works fine, "cheap2el.lib" will be found in top of source directory.

**REQUIREMENTS FOR unittests BUILD**
  * c-unit header and .lib file
  * setup CUNIT\_INCPATH and CUNIT\_LIBPATH environment variables.
```
ex)
 > SET CUNIT_INCPATH=(c-unit header directory)
 > SET CUNIT_LIBPATH=(c-unit static library directory)
```

All unittest and samples are compiled, and tested on...
```
OS  : Windows XP SP3 (x86 32bit, Japanese)
      Windows 7 SP1 (x86 32bit, Japanese)

SDK : Microsoft Visual C++ 2008 Express Edition SP1 - Japanese
      Microsoft Visual C++ 2010 Express Edition - Japanese

Compiler & Linker Version :
 [VC++2008 Express Edition SP1]
 Microsoft(R) 32-bit C/C++ Optimizing Compiler Version 15.00.30729.01 for 80x86
 Microsoft (R) Incremental Linker Version 9.00.30729.01
 [VC++2010 Express Edition]
 Microsoft(R) 32-bit C/C++ Optimizing Compiler Version 16.00.30319.01 for 80x86
 Microsoft (R) Incremental Linker Version 10.00.30319.01
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