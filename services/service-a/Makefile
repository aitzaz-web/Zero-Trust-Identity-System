CXX ?= g++
CXXFLAGS = -std=c++17 -Wall -O2
LDFLAGS = -lssl -lcrypto

SRC = main.cpp
TARGET = service-a

.PHONY: build clean

build: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

test: build
	@echo "Run manually: ./$(TARGET) --cert /path/to/cert.pem --key /path/to/key.pem --ca /path/to/chain.pem"
