# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : unittests
# $Id$
#

PROJNAME=main
TARGET=$(PROJNAME).exe
OBJS=test_00_main.obj \
     test_00_util.obj \
     test_mapper.obj \
     test_enumerator.obj \
     test_callbacks.obj \
     test_version.obj \
     test_coff_obj.obj \
     test_coff_lib.obj

!include <..\common.mk>

CFLAGS=$(CFLAGS) /I ..\header /I .\c-unit-1.1.1\CUnit\Headers
LFLAGS=$(LFLAGS) /LIBPATH:.\c-unit-1.1.1

$(TARGET):$(OBJS) ..\cheap2el.lib
	$(CC) $(CFLAGS) /Fe$(TARGET) $(OBJS) libcunit.lib ..\cheap2el.lib /link $(LFLAGS)

clean:
	del *.obj
	del *.exe
