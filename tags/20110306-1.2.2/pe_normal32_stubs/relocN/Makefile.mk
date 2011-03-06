# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (N relocations) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_relocN
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(SRCS)
	$(CC) $(CFLAGS) /LD $(SRCS) kernel32.lib user32.lib /link /noentry

$(OBJS):$(SRCS)

clean:
	del *.dll *.exp *.lib *.obj
