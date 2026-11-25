# Portable Makefile: no cmake, no network at build time, static libsodium.
# Run scripts/fetch-deps.sh once first.
CXX ?= c++
AR ?= ar
LINKER ?= $(CXX)
LDFLAGS ?=
CXXFLAGS ?= -std=c++17 -O2 -g
WARN ?= -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
DEPS ?= .deps
THREAD_FLAGS := -pthread
EXTRA_LIBS ?=
CPPFLAGS += -Iinclude -Ithird_party -I$(DEPS)/include
LDLIBS += $(DEPS)/lib/libsodium.a $(THREAD_FLAGS) $(EXTRA_LIBS)
BUILD := build
FUZZ_BUILD := build-fuzz

LIB_SRC := $(wildcard src/*.cpp)
LIB_OBJ := $(patsubst src/%.cpp,$(BUILD)/%.o,$(LIB_SRC))
HEADERS := $(wildcard include/skipta/*.hpp)
TEST_SRC := $(wildcard tests/*.cpp)
TEST_OBJ := $(patsubst tests/%.cpp,$(BUILD)/tests/%.o,$(TEST_SRC))

.PHONY: all test vectors clean check-deps fuzz fuzz-build

all: $(BUILD)/libskipta.a $(BUILD)/gen_vectors $(BUILD)/run_tests $(BUILD)/skipta

check-deps:
	@test -f $(DEPS)/lib/libsodium.a || { \
		echo "missing $(DEPS)/lib/libsodium.a - run scripts/fetch-deps.sh" >&2; exit 1; }

$(BUILD)/%.o: src/%.cpp $(HEADERS) | check-deps
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(WARN) $(CPPFLAGS) $(THREAD_FLAGS) -c $< -o $@

$(BUILD)/libskipta.a: $(LIB_OBJ)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BUILD)/cli_main.o: cli/main.cpp $(HEADERS) | check-deps
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(WARN) $(CPPFLAGS) $(THREAD_FLAGS) -c $< -o $@

$(BUILD)/skipta: $(BUILD)/cli_main.o $(BUILD)/libskipta.a
	$(LINKER) $(LDFLAGS) $(CXXFLAGS) $(THREAD_FLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/gen_vectors_main.o: tools/gen_vectors.cpp $(HEADERS) | check-deps
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(WARN) $(CPPFLAGS) $(THREAD_FLAGS) -c $< -o $@

$(BUILD)/gen_vectors: $(BUILD)/gen_vectors_main.o $(BUILD)/libskipta.a
	$(LINKER) $(LDFLAGS) $(CXXFLAGS) $(THREAD_FLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/tests/%.o: tests/%.cpp $(HEADERS) | check-deps
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(WARN) $(CPPFLAGS) $(THREAD_FLAGS) -Ithird_party \
		-DTESTVECTORS_DIR='"$(CURDIR)/testvectors"' -c $< -o $@

$(BUILD)/run_tests: $(TEST_OBJ) $(BUILD)/libskipta.a
	$(LINKER) $(LDFLAGS) $(CXXFLAGS) $(THREAD_FLAGS) $^ $(LDLIBS) -o $@

test: $(BUILD)/run_tests
	./$(BUILD)/run_tests

vectors: $(BUILD)/gen_vectors
	./$(BUILD)/gen_vectors testvectors/format-v1.json

# Sanitizer fuzz target. Deliberately outside `all` and `test`: it builds every
# source again with ASan/UBSan and runs for a large iteration count.
FUZZ_FLAGS := -std=c++17 -O1 -g -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS \
	-fsanitize=address,undefined -fno-sanitize-recover=all
FUZZ_SRC := $(wildcard src/*.cpp) fuzz/fuzz_main.cpp

fuzz-build: $(FUZZ_BUILD)/fuzz

$(FUZZ_BUILD)/fuzz: $(FUZZ_SRC) $(HEADERS) | check-deps
	@mkdir -p $(dir $@)
	$(CXX) $(FUZZ_FLAGS) $(WARN) $(CPPFLAGS) $(THREAD_FLAGS) $(FUZZ_SRC) -o $@ $(LDLIBS)

fuzz: fuzz-build
	./scripts/fuzz.sh --iterations $${FUZZ_ITERATIONS:-2000000} $${FUZZ_ARGS:-}

clean:
	rm -rf $(BUILD) $(FUZZ_BUILD)
