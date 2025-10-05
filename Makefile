# ==============================================================
# Makefile: builds two binaries
#   bin/geo_ip    -> HTTP/HTTPS public-IP client (uses OpenSSL)
#   bin/geo_trace -> TCP geotracer (raw sockets)
# ==============================================================

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Iinclude -Wall -Wextra -Wpedantic -MMD -MP

# Detect macOS and configure OpenSSL include/lib paths (Homebrew)
ifeq ($(shell uname -s),Darwin)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3)
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS_IP    := -lssl -lcrypto
LDLIBS_TRACE :=

SRC_DIR   := src
BUILD_DIR := build
BIN_DIR   := bin

IP_BIN    := $(BIN_DIR)/geo_ip
TRACE_BIN := $(BIN_DIR)/geo_trace

# Mains
IP_MAIN        := main_ip.cpp
TRACE_MAIN     := main_trace.cpp

# Objects
IP_OBJS := \
  $(BUILD_DIR)/$(IP_MAIN:.cpp=.o) \
  $(BUILD_DIR)/$(SRC_DIR)/parsed_url.o \
  $(BUILD_DIR)/$(SRC_DIR)/dns_resolver.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_socket.o \
  $(BUILD_DIR)/$(SRC_DIR)/ssl_session.o

TRACE_OBJS := \
  $(BUILD_DIR)/$(TRACE_MAIN:.cpp=.o) \
  $(BUILD_DIR)/$(SRC_DIR)/dns_resolver.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_socket.o \
  $(BUILD_DIR)/$(SRC_DIR)/icmp_listener.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_probe.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_probe_common.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_probe_raw.o \
  $(BUILD_DIR)/$(SRC_DIR)/tcp_probe_connect.o \
  $(BUILD_DIR)/$(SRC_DIR)/diag_logger.o \
  $(BUILD_DIR)/$(SRC_DIR)/utils_net.o \
  $(BUILD_DIR)/$(SRC_DIR)/geo_resolver.o


.PHONY: all clean dirs help \
        ip find_ip geo_ip \
        trace geo_trace

# ==============================================================
# Default targets
# ==============================================================

# Build both by default
all: ip trace

# Build individual targets (aliases)
ip find_ip geo_ip: dirs $(IP_BIN)
trace geo_trace:   dirs $(TRACE_BIN)

# Ensure directories exist
dirs:
	@mkdir -p $(BUILD_DIR)/$(SRC_DIR) $(BIN_DIR)

# ==============================================================
# Link rules
# ==============================================================

$(IP_BIN): $(IP_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS_IP)

$(TRACE_BIN): $(TRACE_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS_TRACE)

# ==============================================================
# Compile rules
# ==============================================================

# Root-level mains
$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# src/*.cpp
$(BUILD_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ==============================================================
# Housekeeping
# ==============================================================

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

-include $(IP_OBJS:.o=.d) $(TRACE_OBJS:.o=.d)

help:
	@echo "Targets:"
	@echo "  make            - build both binaries"
	@echo "  make ip         - build bin/geo_ip (aka: find_ip, geo_ip)"
	@echo "  make trace      - build bin/geo_trace (aka: geo_trace)"
	@echo "  make clean      - remove build/ and bin/"
