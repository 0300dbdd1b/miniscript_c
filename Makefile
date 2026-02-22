CC			= gcc
CXX			= g++

CXXFLAGS	= -O3 -Wall -Wextra -Wno-unused-parameter -std=c++17 -I. -Iminiscript/bitcoin
CFLAGS		= -O3 -Wall -Wextra -I.

TARGET		= libminiscript_c.a
TARGET_SO	= libminiscript_c.so
TEST_BIN	= run_tests

SRCS =											\
    miniscript_c.cpp							\
    miniscript/compiler.cpp						\
    miniscript/bitcoin/script/miniscript.cpp	\
    miniscript/bitcoin/script/script.cpp		\
    miniscript/bitcoin/util/spanparsing.cpp		\
    miniscript/bitcoin/util/strencodings.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET) $(TARGET_SO)

$(TARGET): $(OBJS)
	@echo "Creating static library $@"
	ar rcs $@ $^

$(TARGET_SO): CXXFLAGS += -fPIC
$(TARGET_SO): $(OBJS)
	@echo "Creating shared library $@"
	$(CXX) -shared -o $@ $^

%.o: %.cpp
	@echo "Compiling $<"
	$(CXX) $(CXXFLAGS) -fPIC -c $< -o $@

test: $(TARGET) test.c
	@echo "Compiling and running tests..."
	$(CC) $(CFLAGS) test.c $(TARGET) -lstdc++ -o $(TEST_BIN)
	./$(TEST_BIN)

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJS) $(TARGET) $(TARGET_SO) $(TEST_BIN)

.PHONY: all clean test
