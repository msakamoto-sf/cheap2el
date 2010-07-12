# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (forward) for cunit testing
# $Id$
#

MAIN=pe_normal32_forward
STUB=pe_normal32_forward_stub

!include <..\..\common.mk>

$(MAIN).dll:force-builds
	$(CC) $(CFLAGS) /LD $(STUB).c /link /noentry
	$(CC) $(CFLAGS) /LD $(MAIN).c $(STUB).lib \
		/link \
		/def:$(MAIN).def \
		/noentry

force-builds:

clean:
	del *.dll *.exp *.lib *.obj
