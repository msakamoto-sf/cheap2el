# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (1 delay load) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_delay1
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(SRCS)
	$(CC) $(CFLAGS) /LD $(SRCS) user32.lib kernel32.lib delayimp.lib /link /DELAYLOAD:user32.dll /noentry

$(OBJS):$(SRCS)

clean:
	del *.dll *.exp *.lib *.obj
