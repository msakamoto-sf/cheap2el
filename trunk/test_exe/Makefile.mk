# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : test_exe stub exe makefile
# $Id$
#

TARGET=test_exe.exe
SRCS=test_exe.c
OBJS=test_exe.obj
RESOURCES=test_exe.res
RCFILES=test_exe.rc

!include <..\common.mk>

$(TARGET):$(SRCS) $(RESOURCES)
	$(CC) $(CFLAGS) $(SRCS) user32.lib $(RESOURCES)

$(OBJS):$(SRCS)

$(RESOURCES):$(RCFILES)

clean:
	del $(TARGET)
	del $(RESOURCES)
	del $(OBJS)