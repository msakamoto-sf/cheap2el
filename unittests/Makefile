# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : unittests
# $Id$
#

PROJNAME=main
TARGET=$(PROJNAME).exe
#OBJS=test_00_main.obj \
#     test_00_util.obj \
#     test_mapper.obj \
#     test_enumerator.obj \
#     test_callbacks.obj \
#     test_version.obj \
#     test_coff_obj.obj \
#     test_coff_lib.obj
OBJS=test_00_util.obj \
     test_version.obj

!include <..\common.mk>

CFLAGS=$(CFLAGS) /EHsc /I ..\header /I .\googletest-release-1.8.0\include
CPPFLAGS=$(CFLAGS)
## "/SUBSYSTEM" is needed, because main() entry point is not exist *.obj, but gtest_main.lib, so linker can't detect subsystem from *.obj.
LFLAGS=$(LFLAGS) /LIBPATH:.\googletest-release-1.8.0\x86-release-no-md /SUBSYSTEM:CONSOLE

$(TARGET):$(OBJS) ..\cheap2el.lib
    link $(LFLAGS) /OUT:$(TARGET) $(OBJS) gtest.lib gtest_main.lib ..\cheap2el.lib

clean:
	del *.obj
	del *.exe
