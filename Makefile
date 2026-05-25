BINARY=scp
BIN_DIR=bin

.PHONY: all build clean

all: build

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY) .

clean:
	rm -f $(BIN_DIR)/$(BINARY)
