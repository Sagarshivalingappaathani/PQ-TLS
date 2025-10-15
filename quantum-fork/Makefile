CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
INCLUDES = -Iinclude -I../vendor/openssl-oqs-install/include
LIBS = ../vendor/openssl-oqs-install/lib/libssl.a ../vendor/openssl-oqs-install/lib/libcrypto.a ../vendor/openssl-oqs-install/lib/liboqs.a -lpthread -ldl

SRCDIR = src
BUILDDIR = build
RESULTSDIR = results
CERTSDIR = certs

PERF_SRC = $(SRCDIR)/performance.c
CLIENT_SRC = $(SRCDIR)/tls_client.c
SERVER_SRC = $(SRCDIR)/tls_server.c

CLIENT = $(BUILDDIR)/tls_client
SERVER = $(BUILDDIR)/tls_server

.PHONY: all clean certs test help

all: $(BUILDDIR) $(RESULTSDIR) $(CLIENT) $(SERVER)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(CLIENT): $(CLIENT_SRC) $(PERF_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(CLIENT) $(CLIENT_SRC) $(PERF_SRC) $(LIBS)

$(SERVER): $(SERVER_SRC) $(PERF_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SERVER) $(SERVER_SRC) $(PERF_SRC) $(LIBS)

certs:
	mkdir -p $(CERTSDIR)
	openssl req -x509 -newkey rsa:2048 -nodes -keyout $(CERTSDIR)/server.key -out $(CERTSDIR)/server.crt -days 365 -subj "/C=US/ST=State/L=City/O=TLS-Test/CN=localhost"

test: all certs
	./$(SERVER) &

clean:
	rm -rf $(BUILDDIR)
	rm -f $(RESULTSDIR)/*.csv $(RESULTSDIR)/*.json

distclean: clean
	rm -rf $(CERTSDIR)

help:
	@echo "Targets:"
	@echo "  all    - Build client and server"
	@echo "  certs  - Generate certificates"
	@echo "  test   - Run test"
	@echo "  clean  - Clean build"
