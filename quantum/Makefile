# Post-Quantum TLS Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -I/usr/local/include
LDFLAGS = -L/usr/local/lib -loqs -lssl -lcrypto -lpthread

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin
RESULTS_DIR = results

# Source files
PQ_CRYPTO_SRC = $(SRC_DIR)/pq_crypto.c
PQ_PERF_SRC = $(SRC_DIR)/pq_performance.c
CLIENT_SRC = $(SRC_DIR)/pq_tls_client.c
SERVER_SRC = $(SRC_DIR)/pq_tls_server.c

# Binaries
CLIENT_BIN = $(BIN_DIR)/pq_tls_client
SERVER_BIN = $(BIN_DIR)/pq_tls_server

# Default target
all: $(CLIENT_BIN) $(SERVER_BIN)

# Build client
$(CLIENT_BIN): $(CLIENT_SRC) $(PQ_CRYPTO_SRC) $(PQ_PERF_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built PQ-TLS client: $@"

# Build server
$(SERVER_BIN): $(SERVER_SRC) $(PQ_CRYPTO_SRC) $(PQ_PERF_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built PQ-TLS server: $@"

# Run test (start server in background, run client, then kill server)
test: all
	@mkdir -p $(RESULTS_DIR)
	@echo "Starting PQ-TLS server in background..."
	@./$(SERVER_BIN) > /tmp/pq_server.log 2>&1 & echo $$! > /tmp/pq_server.pid
	@sleep 1
	@echo "Running PQ-TLS client..."
	@./$(CLIENT_BIN)
	@echo "Stopping server..."
	@kill `cat /tmp/pq_server.pid` 2>/dev/null || true
	@rm -f /tmp/pq_server.pid
	@echo "✓ Test completed"

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f /tmp/pq_server.log /tmp/pq_server.pid
	@echo "✓ Cleaned build artifacts"

# Clean everything including results
distclean: clean
	rm -rf $(RESULTS_DIR)
	@echo "✓ Cleaned everything"

# Help
help:
	@echo "Post-Quantum TLS Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build client and server (default)"
	@echo "  test       - Run automated test"
	@echo "  clean      - Remove binaries"
	@echo "  distclean  - Remove binaries and results"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make           # Build everything"
	@echo "  make test      # Run automated test"
	@echo "  ./bin/pq_tls_server [port]"
	@echo "  ./bin/pq_tls_client [host] [port]"

.PHONY: all test clean distclean help
