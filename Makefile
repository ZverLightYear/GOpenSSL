# GOpenSSL Makefile
# Сборка Go библиотеки для криптографических операций с OpenSSL

# Переменные
GO=go
CGO_ENABLED=1
OPENSSL_DIR=./submodules/openssl
BUILD_DIR=build
BIN_DIR=bin
TEST_DIR=tests

# Флаги для CGO
export CGO_CFLAGS=-I$(OPENSSL_DIR)/include
export CGO_LDFLAGS=-L$(OPENSSL_DIR) -lcrypto -lssl

# Цели по умолчанию
.PHONY: all clean test build examples cli docs

all: build test examples

# Сборка основной библиотеки
build: $(BUILD_DIR)
	@echo "Building GOpenSSL library..."
	$(GO) build -v -o $(BUILD_DIR)/gopenssl.a ./crypto_engine.go ./hash_engine.go

# Сборка примеров
examples: build
	@echo "Building examples..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -v -o $(BIN_DIR)/basic_usage ./examples/basic_usage.go
	$(GO) build -v -o $(BIN_DIR)/cli ./cmd/cli/main.go

# Сборка CLI инструмента
cli: build
	@echo "Building CLI tool..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -v -o $(BIN_DIR)/gopenssl-cli ./cmd/cli/main.go

# Запуск тестов
test: build
	@echo "Running tests..."
	$(GO) test -v ./cgo/...
	$(GO) test -v ./tests/...

# Запуск тестов с покрытием
test-coverage: build
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./cgo/... ./tests/...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Проверка кода
lint:
	@echo "Running linter..."
	golangci-lint run

# Форматирование кода
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Генерация документации
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	godoc -http=:6060 &
	@echo "Documentation available at http://localhost:6060"
	@echo "Press Ctrl+C to stop"

# Создание директорий
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Очистка
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -f *.test

# Установка зависимостей
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# Проверка OpenSSL submodule
check-openssl:
	@echo "Checking OpenSSL submodule..."
	@if [ ! -d "$(OPENSSL_DIR)" ]; then \
		echo "OpenSSL submodule not found. Initializing..."; \
		git submodule init; \
		git submodule update; \
	fi

# Установка OpenSSL на Windows
install-openssl-windows:
	@echo "Installing OpenSSL on Windows..."
	@powershell -ExecutionPolicy Bypass -File scripts/install_openssl.ps1

# Проверка зависимостей
check-deps:
	@echo "Checking dependencies..."
	@powershell -ExecutionPolicy Bypass -File scripts/check_deps.ps1

# Сборка OpenSSL (если нужно)
build-openssl: check-openssl
	@echo "Building OpenSSL..."
	@if [ ! -f "$(OPENSSL_DIR)/libcrypto.a" ] || [ ! -f "$(OPENSSL_DIR)/libssl.a" ]; then \
		echo "OpenSSL libraries not found. Building..."; \
		cd $(OPENSSL_DIR) && \
		./config --prefix=. --openssldir=. && \
		make && \
		cd ..; \
	fi

# Полная сборка с OpenSSL
build-full: build-openssl build

# Запуск примеров
run-examples: examples
	@echo "Running examples..."
	@for example in $(BIN_DIR)/*; do \
		if [ -x "$$example" ]; then \
			echo "Running $$(basename $$example)..."; \
			./$$example; \
			echo ""; \
		fi \
	done

# Создание релиза
release: clean build test
	@echo "Creating release..."
	@mkdir -p release
	cp -r $(BUILD_DIR)/* release/
	cp -r $(BIN_DIR)/* release/
	cp README.md QUICKSTART.md BUILD.md INTEGRATION.md LICENSE release/
	@echo "Release created in release/ directory"

# Помощь
help:
	@echo "GOpenSSL Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build library, run tests, and build examples"
	@echo "  build            - Build the main library"
	@echo "  examples         - Build example programs"
	@echo "  cli              - Build CLI tool"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  lint             - Run linter"
	@echo "  fmt              - Format code"
	@echo "  docs             - Generate documentation"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  check-openssl    - Check OpenSSL submodule"
	@echo "  build-openssl    - Build OpenSSL libraries"
	@echo "  build-full       - Build OpenSSL and library"
	@echo "  run-examples     - Run all examples"
	@echo "  release          - Create release package"
	@echo "  help             - Show this help" 