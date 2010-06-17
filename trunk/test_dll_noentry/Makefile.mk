# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (without entry point) for cunit testing
# $Id$
#

PROJNAME=test_dll_noentry
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj
RESOURCES=$(PROJNAME).res
RCFILES=$(PROJNAME).rc

!include <..\common.mk>

main.exe:$(TARGET) main.c
	$(CC) $(CFLAGS) main.c $(PROJNAME).lib user32.lib

$(TARGET):$(SRCS) $(RESOURCES)
	$(CC) $(CFLAGS) /LD $(SRCS) user32.lib $(RESOURCES) /link /def:$(PROJNAME).def /noentry

$(OBJS):$(SRCS)

$(RESOURCES):$(RCFILES)

clean:
	del main.exe main.obj
	del $(TARGET) $(PROJNAME).exp $(PROJNAME).lib
	del $(RESOURCES)
	del $(OBJS)