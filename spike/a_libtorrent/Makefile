# Spike A: needs libtorrent-rasterbar >= 2.0 and pkg-config.
# Not built by the top-level Makefile; this is a measurement tool.
CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -g
PKG_CONFIG ?= pkg-config

LT_CFLAGS := $(shell $(PKG_CONFIG) --cflags libtorrent-rasterbar 2>/dev/null)
LT_LIBS := $(shell $(PKG_CONFIG) --libs libtorrent-rasterbar 2>/dev/null)

.PHONY: all clean check

all: spike_a

check:
	@if [ -z "$(LT_LIBS)" ]; then \
		echo "libtorrent-rasterbar not found via pkg-config; install it first" >&2; exit 1; fi

spike_a: main.cpp check
	$(CXX) $(CXXFLAGS) $(LT_CFLAGS) main.cpp -o $@ $(LT_LIBS)

clean:
	rm -f spike_a
