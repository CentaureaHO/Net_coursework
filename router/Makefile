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
    LDFLAGS := -lws2_32 -lnpcap
    SOURCES := $(shell find $(SRC_DIR)/ -name '*.cpp' -o -name '*.c')
else
    LDFLAGS := -lpcap
    SOURCES := $(shell find $(SRC_DIR)/ -name '*.cpp' -o -name '*.c')
endif

OBJECTS := $(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(SOURCES:.cpp=.o))

.PHONY: all 
all: bin

.PHONY: obj
obj: $(OBJECTS)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXX_STANDARD) $(WERROR_FLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CXX) $(CXX_STANDARD) $(WERROR_FLAGS) -I$(INCLUDE_DIR) -c $< -o $@

.PHONY: bin
bin: obj
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXX_STANDARD) $(OPTIMIZE_FLAGS) $(WERROR_FLAGS) -I$(INCLUDE_DIR) main.cpp $(OBJECTS) -o $(BIN_DIR)/router $(LDFLAGS)

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: format
format:
	@find . -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.hh" \) -exec clang-format -i {} +