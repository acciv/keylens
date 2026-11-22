CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude

BIN := keylens
TEST := tests/test_scanner

.PHONY: all test clean

all: $(BIN)

$(BIN): src/scanner.cpp src/main.cpp include/keylens.hpp
	$(CXX) $(CXXFLAGS) src/scanner.cpp src/main.cpp -o $@

$(TEST): tests/test_scanner.cpp src/scanner.cpp include/keylens.hpp
	$(CXX) $(CXXFLAGS) tests/test_scanner.cpp src/scanner.cpp -o $@

test: $(TEST)
	./$(TEST)

clean:
	rm -f $(BIN) $(TEST)
