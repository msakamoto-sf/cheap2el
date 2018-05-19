# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : root Makefile
# $Id$
#

MAKEOPTS=-nologo

cheap2el:force-builds
	cd src && $(MAKE) $(MAKEOPTS) && cd ..

clean:force-builds
	cd src && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd unittests && $(MAKE) $(MAKEOPTS) clean && cd ..

test:force-builds
!IF DEFINED(CUNIT_INCPATH) && DEFINED(CUNIT_LIBPATH)
	cd src && $(MAKE) $(MAKEOPTS) && cd ..
	set PATH=%PATH%;.\\datafiles
	cd unittests && $(MAKE) $(MAKEOPTS) && main.exe && cd ..
!ELSE
!MESSAGE NOTE: "test" target is ignored, because
!MESSAGE CUNIT_INCPATH or CUNIT_LIBPATH environment value is not defined.
!ENDIF

force-builds:
