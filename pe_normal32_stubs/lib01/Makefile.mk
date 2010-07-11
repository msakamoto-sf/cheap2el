# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : coff .lib file for testing
# $Id$
#

!include <..\..\common.mk>

PROJNAME=pe_normal32_lib01

OBJS=source_foo1.obj \
     source_foo12.obj \
     source_foo123.obj \
     a.obj

$(PROJNAME).lib:$(OBJS)
	lib /nologo /out:$(PROJNAME).lib $(OBJS)

#pe_normal32_coff01.obj:pe_normal32_coff01.c

clean:
	del *.obj *.lib
