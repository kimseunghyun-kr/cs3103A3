# Makefile: builds two binaries
#   bin/geo_ip    -> HTTP/HTTPS public-IP client (uses OpenSSL)
#   bin/geo_trace -> TCP geotracer (raw sockets)

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Iinclude -Wall -Wextra -Wpedantic -MMD -MP

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
  $(BUILD_DIR)/$(SRC_DIR)/diag_logger.o \
  $(BUILD_DIR)/$(SRC_DIR)/utils_net.o \
  $(BUILD_DIR)/$(SRC_DIR)/geo_resolver.o

.PHONY: all clean dirs help \
        ip find_ip geo_ip \
        trace geo_trace

# Build both by default
all: ip trace

# Phonies to build one at a time (aliases provided)
ip find_ip geo_ip: dirs $(IP_BIN)
trace geo_trace:   dirs $(TRACE_BIN)

# Ensure directories exist
dirs:
	@mkdir -p $(BUILD_DIR)/$(SRC_DIR) $(BIN_DIR)

# Link rules
$(IP_BIN): $(IP_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS_IP)

$(TRACE_BIN): $(TRACE_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS_TRACE)

# Compile rules (root-level mains)
$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile rules (src/*.cpp)
$(BUILD_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

-include $(IP_OBJS:.o=.d) $(TRACE_OBJS:.o=.d)

help:
	@echo "Targets:"
	@echo "  make            - build both binaries"
	@echo "  make ip         - build bin/geo_ip (aka: find_ip, geo_ip)"
	@echo "  make trace      - build bin/geo_trace (aka: geo_trace)"
	@echo "  make clean      - remove build/ and bin/"
