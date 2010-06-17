# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : root Makefile
# $Id$
#

MAKEOPTS=-f Makefile.mk

cheap2el:force-builds
	cd src && $(MAKE) $(MAKEOPTS) && cd ..

clean:force-builds
	cd src && $(MAKE) $(MAKEOPTS) clean && cd ..

all-clean:clean
	cd unittests && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd test_exe && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd test_dll_entry && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd test_dll_noentry && $(MAKE) $(MAKEOPTS) clean && cd ..

test:force-builds
	cd src && $(MAKE) $(MAKEOPTS) && cd ..
	cd unittests && $(MAKE) $(MAKEOPTS) && main.exe && cd ..

stub:force-builds
	cd test_exe && $(MAKE) $(MAKEOPTS) && cd ..
	cd test_dll_entry && $(MAKE) $(MAKEOPTS) && cd ..
	cd test_dll_noentry && $(MAKE) $(MAKEOPTS) && cd ..

force-builds:
