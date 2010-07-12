# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (M imports) for cunit testing
# $Id$
#

PROJNAME1=pe_normal32_Mimps
PROJNAME2=pe_normal32_Mimps_stub

!include <..\..\common.mk>

$(PROJNAME1).dll:$(PROJNAME1).obj $(PROJNAME2).dll
	$(CC) $(CFLAGS) /LD $(PROJNAME1).c $(PROJNAME2).lib /link /noentry

$(PROJNAME2).dll:$(PROJNAME2).obj
	$(CC) $(CFLAGS) /LD $(PROJNAME2).c /link /def:$(PROJNAME2).def /noentry

$(PROJNAME1).obj:$(PROJNAME1).c

$(PROJNAME2).obj:$(PROJNAME2).c

clean:
	del *.dll *.exp *.lib *.obj
