CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow
CPPFLAGS ?= -Isrc
LDLIBS ?= -lssl -lcrypto -pthread

SOURCES := src/proxy.cpp src/http.cpp src/tls.cpp src/acl.cpp src/util.cpp

.PHONY: all clean test

all: bin/myproxy

bin:
	mkdir -p bin

bin/myproxy: $(SOURCES) | bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) -o $@ $(LDLIBS)

clean:
	rm -f bin/myproxy

test: all
	python3 tests/integration.py
