# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (without entry point, border tests) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_Nimps
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(OBJS) pe_normal32_Nimps_stub1.dll pe_normal32_Nimps_stub2.dll
	$(CC) $(CFLAGS) /LD $(SRCS) kernel32.lib user32.lib pe_normal32_Nimps_stub1.lib pe_normal32_Nimps_stub2.lib /link /noentry

pe_normal32_Nimps_stub1.dll:
	$(CC) $(CFLAGS) /LD pe_normal32_Nimps_stub1.c /link /noentry

pe_normal32_Nimps_stub2.dll:
	$(CC) $(CFLAGS) /LD pe_normal32_Nimps_stub2.c /link /noentry

$(OBJS):$(SRCS)

clean:
	del *.dll *.exp *.lib *.obj
