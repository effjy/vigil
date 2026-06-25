# ============================================================
# vigil — post-quantum file-integrity monitor
#
#   make                  build ./vigil
#   make check            build + run the end-to-end test
#   sudo make install     install vigil to $(PREFIX)/bin   (default /usr/local)
#   sudo make uninstall   remove it again
#   make clean            remove build artifacts
#
# Override the install location with PREFIX=… (e.g. make install PREFIX=$HOME/.local)
# and stage into a package root with DESTDIR=…
# ============================================================

BIN     := vigil
VERSION := 1.0.8
AUTHOR  := Jean-Francois Lachance-Caumartin

PREFIX  ?= /usr/local
DESTDIR ?=
BINDIR   := $(DESTDIR)$(PREFIX)/bin
DATADIR  := $(DESTDIR)$(PREFIX)/share
MANDIR   := $(DATADIR)/man/man1

CXX      ?= g++
CC       ?= cc

PKG_CONFIG ?= pkg-config
DEPS        := liboqs openssl libargon2
PKG_CFLAGS  := $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LIBS    := $(shell $(PKG_CONFIG) --libs $(DEPS))
# Bake the liboqs lib dir into an rpath so the binary runs without the caller
# having to set LD_LIBRARY_PATH (liboqs commonly lives in /usr/local/lib).
comma       := ,
OQS_LIBDIR  := $(shell $(PKG_CONFIG) --variable=libdir liboqs)
RPATH       := $(if $(OQS_LIBDIR),-Wl$(comma)-rpath$(comma)$(OQS_LIBDIR))

WARN     := -Wall -Wextra -Wshadow -Wpointer-arith
HARDEN   := -D_FORTIFY_SOURCE=2 -fstack-protector-strong
COMMON   := -O2 -g $(WARN) $(HARDEN) -D_FILE_OFFSET_BITS=64 \
            -DVIGIL_VERSION=\"$(VERSION)\"

CXXFLAGS ?=
CXXFLAGS += -std=c++17 $(COMMON) -Isrc $(PKG_CFLAGS)
CFLAGS   ?=
CFLAGS   += -std=c11 $(COMMON) -Isrc
LDLIBS   += $(PKG_LIBS) -lpthread
LDFLAGS  += $(RPATH)

CXX_SRCS := src/util.cpp src/hash.cpp src/pqsig.cpp src/keystore.cpp \
            src/scan.cpp src/baseline.cpp src/watch.cpp src/main.cpp
C_SRCS   := src/sha3.c
OBJS     := $(CXX_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

UNITDIR ?= $(DESTDIR)/etc/systemd/system

.PHONY: all check clean install uninstall install-systemd uninstall-systemd

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

check: $(BIN)
	./tests/run.sh

install: $(BIN)
	@install -d "$(BINDIR)"
	install -m 0755 $(BIN) "$(BINDIR)/$(BIN)"
	@install -d "$(MANDIR)"
	@if [ -f docs/vigil.1 ]; then install -m 0644 docs/vigil.1 "$(MANDIR)/vigil.1"; fi
	@echo "installed $(BIN) to $(BINDIR)/$(BIN)"

uninstall:
	rm -f "$(BINDIR)/$(BIN)" "$(MANDIR)/vigil.1"
	@echo "removed $(BIN) from $(BINDIR)"

# Install the systemd units (templated per tree, e.g. vigil-check@etc). You
# still create /etc/vigil/<instance>.conf yourself; see systemd/example.conf.
install-systemd:
	@install -d "$(UNITDIR)"
	install -m 0644 systemd/vigil-check@.service "$(UNITDIR)/vigil-check@.service"
	install -m 0644 systemd/vigil-check@.timer   "$(UNITDIR)/vigil-check@.timer"
	install -m 0644 systemd/vigil-watch@.service "$(UNITDIR)/vigil-watch@.service"
	@echo "installed systemd units to $(UNITDIR)"
	@echo "next: create /etc/vigil/<name>.conf (see systemd/example.conf), then"
	@echo "      systemctl enable --now vigil-check@<name>.timer"

uninstall-systemd:
	rm -f "$(UNITDIR)/vigil-check@.service" "$(UNITDIR)/vigil-check@.timer" \
	      "$(UNITDIR)/vigil-watch@.service"
	@echo "removed systemd units from $(UNITDIR)"

clean:
	rm -f $(OBJS) $(BIN)
