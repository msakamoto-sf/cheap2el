# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : library
# $Id$
#

TARGET=..\cheap2el.lib
SRCS=cheap2el.c
OBJS=cheap2el.obj

!include <..\common.mk>

CFLAGS=$(CFLAGS) /I ..\header

$(TARGET):$(OBJS)
	lib /out:$(TARGET) $?

$(OBJS):$(SRCS)

clean:
	del *.obj
	del $(TARGET)
