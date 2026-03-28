LIBPATH =../../
BOARD=vc707
BUILDTOOLS=$(LIBPATH)/buildtools/

BLIBPATH=$(LIBPATH)/../bluelib/src/

CUSTOMBSV=-D INSTREAMS=2 -D OUTSTREAMS=2 -p +:$(BLIBPATH)/ -p +:PacketParser -p +:Shift_Or -p +:FPSM -p +:HeaderMatcher -p +:NFPSM -no-warn-action-shadowing +RTS -K256M -RTS
CUSTOMCPP_BSIM= $(BLIBPATH)/bdpi.cpp
CUSTOMCPPFLAGS=-Wno-strict-aliasing -Wno-uninitialized

include $(BUILDTOOLS)/Makefile.base
