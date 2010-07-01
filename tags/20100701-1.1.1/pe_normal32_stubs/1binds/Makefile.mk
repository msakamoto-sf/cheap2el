# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (1 binds) for cunit testing
# $Id$
#

PROJNAME1=pe_normal32_1binds
PROJNAME2=pe_normal32_1binds_stub

!include <..\..\common.mk>

$(PROJNAME1).dll:$(PROJNAME1).obj $(PROJNAME2).dll
	$(CC) $(CFLAGS) /LD $(PROJNAME1).c $(PROJNAME2).lib /link /noentry
	EDITBIN /BIND:PATH=. $(PROJNAME1).dll

$(PROJNAME2).dll:$(PROJNAME2).obj
	$(CC) $(CFLAGS) /LD $(PROJNAME2).c /link /noentry

$(PROJNAME1).obj:$(PROJNAME1).c

$(PROJNAME2).obj:$(PROJNAME2).c

clean:
	del *.dll *.exp *.lib *.obj
