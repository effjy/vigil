# ============================================================
# vigil — post-quantum file-integrity monitor (CLI + GTK4 GUI)
#
#   make                  build ./vigil and ./vigil-gui
#   make check            build CLI + run the end-to-end test
#   sudo make install     install both binaries, icon and desktop entry
#   sudo make uninstall   remove them again
#   make clean            remove build artifacts
#
# `vigil` is the command-line tool; `vigil-gui` is the graphical front-end that
# drives it (and is what the application-menu launcher runs). Override the
# install location with PREFIX=… and stage into a package root with DESTDIR=…
# ============================================================

BIN     := vigil
GUI     := vigil-gui
VERSION := 1.0.8
AUTHOR  := Jean-Francois Lachance-Caumartin

PREFIX  ?= /usr/local
DESTDIR ?=
BINDIR   := $(DESTDIR)$(PREFIX)/bin
DATADIR  := $(DESTDIR)$(PREFIX)/share
MANDIR   := $(DATADIR)/man/man1
APPDIR   := $(DATADIR)/applications
ICONDIR  := $(DATADIR)/icons/hicolor/256x256/apps
SVGDIR   := $(DATADIR)/icons/hicolor/scalable/apps

CXX      ?= g++
CC       ?= cc

PKG_CONFIG ?= pkg-config
DEPS        := liboqs openssl libargon2
PKG_CFLAGS  := $(shell $(PKG_CONFIG) --cflags $(DEPS))
PKG_LIBS    := $(shell $(PKG_CONFIG) --libs $(DEPS))
GTK_CFLAGS  := $(shell $(PKG_CONFIG) --cflags gtk4)
GTK_LIBS    := $(shell $(PKG_CONFIG) --libs gtk4)
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

# --- CLI (vigil) -------------------------------------------------------------
CLI_CXX_SRCS := src/util.cpp src/hash.cpp src/pqsig.cpp src/keystore.cpp \
                src/scan.cpp src/baseline.cpp src/watch.cpp src/main.cpp
C_SRCS       := src/sha3.c
CLI_OBJS     := $(CLI_CXX_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

# --- GUI (vigil-gui) ---------------------------------------------------------
# The GUI is a self-contained front-end that shells out to the `vigil` binary,
# so it only needs GTK4 (+ GLib/GIO, which GTK pulls in) — none of the crypto.
GUI_SRCS := src/gui.cpp src/tray.cpp

UNITDIR ?= $(DESTDIR)/etc/systemd/system

.PHONY: all check clean install uninstall install-systemd uninstall-systemd

all: $(BIN) $(GUI)

# --- CLI build ---------------------------------------------------------------
$(BIN): $(CLI_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(CLI_OBJS) $(LDFLAGS) $(LDLIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# --- GUI build (compiled directly; keeps GTK flags off the CLI objects) ------
$(GUI): $(GUI_SRCS) src/tray.h
	$(CXX) -std=c++17 $(COMMON) -Isrc $(GTK_CFLAGS) -o $@ $(GUI_SRCS) $(GTK_LIBS)

check: $(BIN)
	./tests/run.sh

install: all
	@install -d "$(BINDIR)"
	install -m 0755 $(BIN) "$(BINDIR)/$(BIN)"
	install -m 0755 $(GUI) "$(BINDIR)/$(GUI)"
	@install -d "$(MANDIR)"
	@if [ -f docs/vigil.1 ]; then install -m 0644 docs/vigil.1 "$(MANDIR)/vigil.1"; fi
	@echo "Installing icon and desktop entry..."
	@install -d "$(APPDIR)" "$(ICONDIR)" "$(SVGDIR)"
	install -m 0644 vigil.desktop  "$(APPDIR)/vigil.desktop"
	install -m 0644 icons/vigil.png "$(ICONDIR)/vigil.png"
	install -m 0644 icons/vigil.svg "$(SVGDIR)/vigil.svg"
	-gtk-update-icon-cache -f -t "$(DATADIR)/icons/hicolor" 2>/dev/null || true
	-update-desktop-database "$(APPDIR)" 2>/dev/null || true
	@echo "installed $(BIN) and $(GUI) to $(DESTDIR)$(PREFIX)/bin"
	@echo "launch 'Vigil' from your application menu, or run 'vigil-gui'"

uninstall:
	rm -f "$(BINDIR)/$(BIN)" "$(BINDIR)/$(GUI)" "$(MANDIR)/vigil.1"
	rm -f "$(APPDIR)/vigil.desktop"
	rm -f "$(ICONDIR)/vigil.png" "$(SVGDIR)/vigil.svg"
	-gtk-update-icon-cache -f -t "$(DATADIR)/icons/hicolor" 2>/dev/null || true
	-update-desktop-database "$(APPDIR)" 2>/dev/null || true
	@echo "removed $(BIN) and $(GUI) from $(DESTDIR)$(PREFIX)/bin"

# Install the systemd units (templated per tree, e.g. vigil-check@etc). You
# still create /etc/vigil/<instance>.conf yourself; see systemd/example.conf.
install-systemd:
	@install -d "$(UNITDIR)"
	install -m 0644 systemd/vigil-check@.service "$(UNITDIR)/vigil-check@.service"
	install -m 0644 systemd/vigil-check@.timer   "$(UNITDIR)/vigil-check@.timer"
	install -m 0644 systemd/vigil-watch@.service "$(UNITDIR)/vigil-watch@.service"
	@echo "installed systemd units to $(UNITDIR)"

uninstall-systemd:
	rm -f "$(UNITDIR)/vigil-check@.service" "$(UNITDIR)/vigil-check@.timer" \
	      "$(UNITDIR)/vigil-watch@.service"
	@echo "removed systemd units from $(UNITDIR)"

clean:
	rm -f $(CLI_OBJS) $(BIN) $(GUI)
