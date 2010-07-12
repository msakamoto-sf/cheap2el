# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : coff .lib file for testing (no public symbols)
# $Id$
#

!include <..\..\common.mk>

PROJNAME=pe_normal32_lib00

OBJS=a.obj

$(PROJNAME).lib:$(OBJS)
	lib /nologo /out:$(PROJNAME).lib $(OBJS)

clean:
	del *.obj *.lib
