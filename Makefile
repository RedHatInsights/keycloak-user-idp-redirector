.PHONY: help build clean test test-watch package install run-dev stop-dev logs-dev verify

# Default target
help:
	@echo "Keycloak User IDP Redirector - Build Targets"
	@echo ""
	@echo "Development:"
	@echo "  make build        - Compile source code"
	@echo "  make test         - Run unit tests"
	@echo "  make test-watch   - Run tests in watch mode"
	@echo "  make verify       - Run all checks (test + package)"
	@echo "  make package      - Build deployable JAR"
	@echo "  make clean        - Remove build artifacts"
	@echo ""
	@echo "Local Deployment (podman):"
	@echo "  make run-dev      - Start Keycloak with plugin mounted"
	@echo "  make stop-dev     - Stop Keycloak container"
	@echo "  make logs-dev     - Tail Keycloak logs"
	@echo ""
	@echo "Installation:"
	@echo "  make install      - Copy JAR to /opt/keycloak/providers/"
	@echo ""
	@echo "Config:"
	@echo "  KEYCLOAK_DIR      - Keycloak install path (default: /opt/keycloak)"
	@echo "  CONTAINER_NAME    - Podman container name (default: keycloak-dev)"

# Config
KEYCLOAK_DIR ?= /opt/keycloak
CONTAINER_NAME ?= keycloak-dev
JAR_FILE = target/user-idp-redirector-1.0.0.jar

# Build targets
build:
	mvn compile

clean:
	mvn clean
	@echo "Cleaned build artifacts"

test:
	mvn test

test-watch:
	@echo "Running tests in watch mode (Ctrl+C to stop)..."
	@while true; do \
		mvn test; \
		echo ""; \
		echo "Waiting for file changes... (Ctrl+C to stop)"; \
		inotifywait -q -r -e modify src/ pom.xml 2>/dev/null || \
		(echo "inotifywait not found, using sleep instead"; sleep 5); \
	done

package: clean
	mvn package
	@echo "Built: $(JAR_FILE)"

verify: clean
	mvn verify
	@echo "All checks passed"

# Installation
install: package
	@if [ ! -d "$(KEYCLOAK_DIR)/providers" ]; then \
		echo "Error: $(KEYCLOAK_DIR)/providers not found"; \
		echo "Set KEYCLOAK_DIR to your Keycloak installation"; \
		exit 1; \
	fi
	cp $(JAR_FILE) $(KEYCLOAK_DIR)/providers/
	@echo "Installed to $(KEYCLOAK_DIR)/providers/"
	@echo "Run: $(KEYCLOAK_DIR)/bin/kc.sh build && $(KEYCLOAK_DIR)/bin/kc.sh start"

# Local development with podman
run-dev: package
	@if podman ps -a --format '{{.Names}}' | /usr/bin/rg -q '^$(CONTAINER_NAME)$$'; then \
		echo "Stopping existing container..."; \
		podman stop $(CONTAINER_NAME) 2>/dev/null || true; \
		podman rm $(CONTAINER_NAME) 2>/dev/null || true; \
	fi
	@echo "Starting Keycloak with plugin..."
	podman run -d \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/$(JAR_FILE):/opt/keycloak/providers/user-idp-redirector-1.0.0.jar:z \
		-p 8080:8080 \
		-e KEYCLOAK_ADMIN=admin \
		-e KEYCLOAK_ADMIN_PASSWORD=admin \
		quay.io/keycloak/keycloak:26.0.0 \
		start-dev
	@echo ""
	@echo "Keycloak starting at http://localhost:8080"
	@echo "Admin: admin / admin"
	@echo ""
	@echo "Tail logs: make logs-dev"
	@echo "Stop:      make stop-dev"

stop-dev:
	@if podman ps -a --format '{{.Names}}' | /usr/bin/rg -q '^$(CONTAINER_NAME)$$'; then \
		podman stop $(CONTAINER_NAME); \
		podman rm $(CONTAINER_NAME); \
		echo "Stopped $(CONTAINER_NAME)"; \
	else \
		echo "Container $(CONTAINER_NAME) not running"; \
	fi

logs-dev:
	@if podman ps --format '{{.Names}}' | /usr/bin/rg -q '^$(CONTAINER_NAME)$$'; then \
		podman logs -f $(CONTAINER_NAME); \
	else \
		echo "Container $(CONTAINER_NAME) not running"; \
		exit 1; \
	fi
