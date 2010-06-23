# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (M imports) for cunit testing
# $Id$
#

MAIN=pe_normal32_Nbinds
STUB=pe_normal32_Nbinds_stub

!include <..\..\common.mk>

$(MAIN).dll:force-builds
	$(CC) $(CFLAGS) /LD $(STUB)A0.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)B1.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)B0.c $(STUB)B1.lib /link /def:$(STUB)B0.def /noentry
	$(CC) $(CFLAGS) /LD $(STUB)C1.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)C2.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)C0.c $(STUB)C1.lib $(STUB)C2.lib /link /def:$(STUB)C0.def /noentry
	$(CC) $(CFLAGS) /LD $(STUB)D1.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)D2.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)D3.c /link /noentry
	$(CC) $(CFLAGS) /LD $(STUB)D0.c $(STUB)D1.lib $(STUB)D2.lib $(STUB)D3.lib /link /def:$(STUB)D0.def /noentry
	$(CC) $(CFLAGS) /LD $(STUB)E0.c /link /noentry
	$(CC) $(CFLAGS) /LD $(MAIN).c $(STUB)A0.lib $(STUB)B0.lib $(STUB)C0.lib $(STUB)D0.lib $(STUB)E0.lib /link /noentry
	EDITBIN /BIND:PATH=. $(MAIN).dll

force-builds:

clean:
	del *.dll *.exp *.lib *.obj
