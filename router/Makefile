CXX ?= g++
CXX_STANDARD := -std=c++17
DBGFLAGS = -g
OPTIMIZE_FLAGS := -O3
WERROR_FLAGS := -Wall -Wextra -Wpedantic -Werror

INCLUDE_DIR := include
SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

ifeq ($(OS),Windows_NT)
    LDFLAGS := -lws2_32 -lwpcap -lpacket -liphlpapi
    SOURCES := $(SRC_DIR)/common/lock.cpp $(SRC_DIR)/common/log.cpp
    SOURCES += $(SRC_DIR)/net/net_devs.cpp $(SRC_DIR)/net/package.cpp $(SRC_DIR)/net/socket_defs.cpp
    SOURCES += $(SRC_DIR)/struct/arp_table.cpp $(SRC_DIR)/struct/route_tree.cpp
    MKDIR := powershell -Command "New-Item -ItemType Directory -Force"
    RMDIR := powershell -Command "Remove-Item -Recurse -Force"
    RM := del /F /Q
else
    LDFLAGS := -lpcap
    SOURCES := $(shell find $(SRC_DIR)/ -name '*.cpp' -o -name '*.c')
    MKDIR := mkdir -p
    RMDIR := rm -rf
    RM := rm -f
endif

CXXFLAGS := $(CXX_STANDARD) $(DBGFLAGS) $(OPTIMIZE_FLAGS) $(WERROR_FLAGS) -I$(INCLUDE_DIR)
OBJECTS := $(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(SOURCES:.cpp=.o))

.PHONY: all 
all: bin

.PHONY: obj
obj: $(OBJECTS)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(MKDIR) $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(MKDIR) $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: bin
bin: $(BIN_DIR)/router
$(BIN_DIR)/router: main.cpp $(OBJECTS)
	$(MKDIR) $(BIN_DIR)
	$(CXX) $(CXXFLAGS) main.cpp $(OBJECTS) -o $(BIN_DIR)/router $(LDFLAGS)

.PHONY: test
test: $(BIN_DIR)/test
$(BIN_DIR)/test: test.cpp $(OBJECTS)
	$(MKDIR) $(BIN_DIR)
	$(CXX) $(CXXFLAGS) test.cpp $(OBJECTS) -o $(BIN_DIR)/test $(LDFLAGS)

.PHONY: clean
clean:
	$(RMDIR) $(OBJ_DIR)
	$(RMDIR) $(BIN_DIR)

.PHONY: format
format:
	@find . -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.hh" \) -exec clang-format -i {} +