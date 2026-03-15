LIBPATH =../../
BOARD=vc707
BUILDTOOLS=$(LIBPATH)/buildtools/

BLIBPATH=$(LIBPATH)/../bluelib/src/

CUSTOMBSV=-D INSTREAMS=2 -D OUTSTREAMS=2 -p +:$(BLIBPATH)/ -p +:PacketParser -p +:Shift_Or -p +:FPSM -p +:HeaderMatcher -no-warn-action-shadowing +RTS -K256M -RTS
CUSTOMCPP_BSIM= $(BLIBPATH)/bdpi.cpp
CUSTOMCPPFLAGS=-Wno-strict-aliasing -Wno-uninitialized

include $(BUILDTOOLS)/Makefile.base

BSCFLAGS_PARSER_TEST = -bdir ./test_parser/obj -vdir ./test_parser/obj -simdir ./test_parser/obj -info-dir ./test_parser -fdir ./test_parser -D BSIM

BSCFLAGS_FPSM_TEST = -bdir ./test_fpsm/obj -vdir ./test_fpsm/obj -simdir ./test_fpsm/obj -info-dir ./test_fpsm -fdir ./test_fpsm -D BSIM

test: PacketParser/PacketParser.bsv
	mkdir -p test_parser/obj
	bsc $(BSCFLAGS) $(BSCFLAGS_PARSER_TEST) -p +:$(LIBPATH)/src $(CUSTOMBSV) -sim -u -g mkPacketParserTest PacketParser/PacketParser.bsv
	bsc $(BSCFLAGS) $(BSCFLAGS_PARSER_TEST) -sim -e mkPacketParserTest -o test_parser/obj/parser_test test_parser/obj/*.ba
	./test_parser/obj/parser_test

test_fpsm: FPSM/TestSimpleFPSM_Fixed.bsv FPSM/SimpleFPSM.bsv
	@echo "========================================="
	@echo "Testing FPSM (Fast Pattern String Matcher)"
	@echo "========================================="
	mkdir -p test_fpsm/obj
	bsc $(BSCFLAGS) $(BSCFLAGS_FPSM_TEST) -p +:$(LIBPATH)/src $(CUSTOMBSV) -sim -u -g mkTestSimpleFPSM_Fixed FPSM/TestSimpleFPSM_Fixed.bsv
	bsc $(BSCFLAGS) $(BSCFLAGS_FPSM_TEST) -sim -e mkTestSimpleFPSM_Fixed -o test_fpsm/obj/fpsm_test test_fpsm/obj/*.ba
	@echo ""
	@echo "Running FPSM test..."
	@echo "========================================="
	./test_fpsm/obj/fpsm_test
	@echo "========================================="
	@echo "FPSM test complete!"
