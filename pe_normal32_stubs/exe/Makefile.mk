# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub exe for cunit testing
# $Id$
#


PROJNAME=pe_normal32_exe
TARGET=$(PROJNAME).exe
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj
RESOURCES=$(PROJNAME).res
RCFILES=$(PROJNAME).rc

!include <..\..\common.mk>

$(TARGET):$(SRCS) $(RESOURCES)
	$(CC) $(CFLAGS) $(SRCS) user32.lib $(RESOURCES)

$(OBJS):$(SRCS)

$(RESOURCES):$(RCFILES)

clean:
	del *.exe *.obj *.res
