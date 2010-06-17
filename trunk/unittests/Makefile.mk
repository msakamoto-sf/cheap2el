# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : unittests
# $Id$
#

PROJNAME=main
TARGET=$(PROJNAME).exe
SRCS=$(PROJNAME).c  test_cheap2el1.c
OBJS=$(PROJNAME).obj test_cheap2el1.obj

!include <..\common.mk>

CFLAGS=$(CFLAGS) /I ..\header

$(TARGET):$(OBJS) ..\cheap2el.lib
	$(CC) $(CFLAGS) /Fe$(PROJNAME).exe $(OBJS) libcunit.lib ..\cheap2el.lib /link $(LFLAGS)

$(OBJS):$(SRCS)

clean:
	del *.obj
	del *.exe
