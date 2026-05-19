VER         := 0.3.0
CC          ?= cc
AR          ?= ar
DESTDIR     ?=

# ---- Tcl 9 detection ------------------------------------------------------
# Picks the first tclConfig.sh whose TCL_VERSION starts with "9.".
# Override with TCLCONFIG=/path/to/tclConfig.sh, or set TCL_INCLUDE /
# TCL_STUB_LIB directly. Embedding hosts (e.g. zippy) typically pass
# TCL_PREFIX=<dir> where <dir>/include and <dir>/lib hold the Tcl 9 headers
# and libtclstub.
TCL_CANDIDATES := \
  /usr/local/lib/tclConfig.sh \
  /usr/lib/tclConfig.sh \
  /usr/lib64/tclConfig.sh \
  /usr/lib/tcl9.0/tclConfig.sh \
  /opt/homebrew/lib/tclConfig.sh
TCLCONFIG ?= $(shell for f in $(TCL_CANDIDATES); do \
  [ -f "$$f" ] || continue; \
  v=$$(. "$$f" 2>/dev/null; echo $$TCL_VERSION); \
  if [ "$${v#9.}" != "$$v" ]; then echo "$$f"; exit 0; fi; \
done)

ifdef TCL_PREFIX
  TCL_INCLUDE  ?= -I$(TCL_PREFIX)/include -I$(TCL_PREFIX)/include/tcl9.0
  TCL_STUB_LIB ?= -L$(TCL_PREFIX)/lib -ltclstub
else ifneq ($(wildcard $(TCLCONFIG)),)
  TCL_INCLUDE  ?= $(shell . $(TCLCONFIG); echo $$TCL_INCLUDE_SPEC)
  TCL_STUB_LIB ?= $(shell . $(TCLCONFIG); echo $$TCL_STUB_LIB_SPEC)
endif

# ---- mbedcrypto -----------------------------------------------------------
# Picomemo's shim pulls in mbedtls headers and links libmbedcrypto. Override
# with MBED_PREFIX=<dir> (expects <dir>/include and <dir>/lib), or set
# MBED_INCLUDE / MBED_LIB directly. Defaults to pkg-config if available, then
# the system include/lib paths.
ifdef MBED_PREFIX
  MBED_INCLUDE ?= -I$(MBED_PREFIX)/include
  MBED_LIB     ?= -L$(MBED_PREFIX)/lib -lmbedcrypto
else
  MBED_INCLUDE ?= $(shell pkg-config --cflags mbedcrypto 2>/dev/null)
  MBED_LIB     ?= $(shell pkg-config --libs mbedcrypto 2>/dev/null || echo -lmbedcrypto)
endif

# ---- Sources --------------------------------------------------------------
PICO_DIR    := picomemo
PICO_SRCS   := $(PICO_DIR)/omemo.c $(PICO_DIR)/hacl.c
SHIM_SRC    := omemo_tcl.c
SRCS        := $(SHIM_SRC) $(PICO_SRCS)

WARN_FLAGS  := -Wall -Wno-pointer-sign -Wno-unused-function
COMMON_CF   := $(WARN_FLAGS) -I$(PICO_DIR) $(TCL_INCLUDE) $(MBED_INCLUDE) \
               -DUSE_TCL_STUBS -DPACKAGE_VERSION=\"$(VER)\" $(CFLAGS)

PIC_CF      := $(COMMON_CF) -fPIC
STATIC_CF   := $(COMMON_CF)

OUT_SO      := libtcl9omemo$(VER).so
OUT_A       := libtcl9omemo$(VER).a
PKGINDEX    := pkgIndex.tcl

SO_LDFLAGS  := -shared $(TCL_STUB_LIB) $(MBED_LIB) $(LDFLAGS)

PIC_OBJS    := $(patsubst %.c,build/pic/%.o,$(notdir $(SRCS)))
STATIC_OBJS := $(patsubst %.c,build/static/%.o,$(notdir $(SRCS)))

vpath %.c . $(PICO_DIR)

.PHONY: all test clean config
all: $(OUT_SO) $(OUT_A) $(PKGINDEX)

build/pic build/static:
	mkdir -p $@

build/pic/%.o: %.c | build/pic
	$(CC) $(PIC_CF) -c $< -o $@

build/static/%.o: %.c | build/static
	$(CC) $(STATIC_CF) -c $< -o $@

$(OUT_SO): $(PIC_OBJS)
	$(CC) -o $@ $^ $(SO_LDFLAGS)

$(OUT_A): $(STATIC_OBJS)
	$(AR) rcs $@ $^

$(PKGINDEX): pkgIndex.tcl.in
	sed 's/@VERSION@/$(VER)/g' $< > $@

# Tests need a tclsh that does NOT have omemo statically baked in, otherwise
# `package require omemo` returns the bundled copy and never loads our .so.
# Override TCLSH=... to point to a clean Tcl 9 install if your default
# tclsh9.0 has omemo linked in.
TCLSH ?= tclsh9.0

test: all
	cd tests && $(TCLSH) test_omemo.tcl

clean:
	rm -rf build $(OUT_SO) $(OUT_A) $(PKGINDEX) tests/*.db

config:
	@echo "VER:          $(VER)"
	@echo "CC:           $(CC)"
	@echo "TCLCONFIG:    $(TCLCONFIG)"
	@echo "TCL_INCLUDE:  $(TCL_INCLUDE)"
	@echo "TCL_STUB_LIB: $(TCL_STUB_LIB)"
	@echo "MBED_INCLUDE: $(MBED_INCLUDE)"
	@echo "MBED_LIB:     $(MBED_LIB)"
	@echo "TCLSH:        $(TCLSH)"
