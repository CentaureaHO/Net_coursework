INCLUDE_DIR := include
SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

EXEC_NAME := capture
CXX ?= g++

INCLUDES = -I./$(INCLUDE_DIR)

CXX_STANDARD = -std=c++17
DBGFLAGS = -g
WERROR_FLAGS := -Wall -Wextra -Wpedantic -Werror
WARNINGS_IGNORE := -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-value

ifeq ($(OS),Windows_NT)
    LDFLAGS := -lwpcap
    MKDIR := powershell -Command "New-Item -ItemType Directory -Force"
    RMDIR := powershell -Command "Remove-Item -Recurse -Force"
    RM := del /Q
    SEP := /
    SOURCES := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/*.c)
else
    LDFLAGS := -lpcap
    MKDIR := mkdir -p
    RMDIR := rm -rf
    RM := rm -f
    SEP := /
    SOURCES := $(shell find $(SRC_DIR) -name '*.cpp' -o -name '*.c')
endif

CXXFLAGS = $(CXX_STANDARD) $(INCLUDES) $(WERROR_FLAGS) $(DBGFLAGS) $(WARNINGS_IGNORE)

MAIN_SRC := main.cpp
TEST_SRC := test.cpp
TEST_EXEC := test

OBJECTS := $(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(SOURCES:.cpp=.o))
OBJECTS := $(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(OBJECTS:.c=.o))

.PHONY: all
all: obj bin

.PHONY: obj
obj: $(OBJECTS)
$(OBJ_DIR)$(SEP)%.o: $(SRC_DIR)$(SEP)%.cpp
	$(MKDIR) $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)$(SEP)%.o: $(SRC_DIR)$(SEP)%.c
	$(MKDIR) $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: bin
bin: $(OBJECTS)
	$(MKDIR) $(BIN_DIR)
	$(CXX) $(OBJECTS) $(MAIN_SRC) -o $(BIN_DIR)$(SEP)$(EXEC_NAME) $(CXXFLAGS) $(LDFLAGS)

.PHONY: test
test: $(OBJECTS)
	$(MKDIR) $(BIN_DIR)
	$(CXX) $(OBJECTS) $(TEST_SRC) -o $(TEST_EXEC) $(CXXFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	-$(RMDIR) $(OBJ_DIR)
	-$(RMDIR) $(BIN_DIR)
	-$(RM) $(TEST_EXEC)