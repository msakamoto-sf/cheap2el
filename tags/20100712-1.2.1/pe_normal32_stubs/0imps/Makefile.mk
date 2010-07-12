# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (without entry point, border tests) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_0imps
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(SRCS)
	$(CC) $(CFLAGS) /LD $(SRCS) /link /noentry

$(OBJS):$(SRCS)

clean:
	del *.dll *.exp *.lib *.obj
