.PHONY: build

ifeq ($(OS),Windows_NT)
    RM = del /Q
    RMDIR = rmdir /Q /S
    MKDIR = mkdir
    ECHO = echo
    SLASH = \\
    EXE_EXT = .exe
else
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
    ECHO = echo
    SLASH = /
    EXE_EXT =
endif

BIN_DIR = bin
TARGET = $(BIN_DIR)$(SLASH)netscaner$(EXE_EXT)

build:
	go build -o $(TARGET) ./cmd/main.go

DEFAULT_GOAL := build