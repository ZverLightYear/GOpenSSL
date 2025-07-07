# Makefile для сборки OpenSSL и gost-engine

OPENSSL_DIR=./submodules/src/openssl
GOST_DIR=./submodules/src/gost-engine
BUILD_DIR=./submodules/build
LIB_DIR=$(BUILD_DIR)/lib
INCLUDE_DIR=$(BUILD_DIR)/include

all: openssl gost-engine

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(LIB_DIR)
	mkdir -p $(INCLUDE_DIR)

openssl: $(BUILD_DIR)
	cd $(OPENSSL_DIR) && ./Configure no-shared no-tests --prefix=$(abspath $(BUILD_DIR)) && make -j && make install_sw

gost-engine: openssl
	cmake -S $(GOST_DIR) -B $(BUILD_DIR)/gost-engine -DOPENSSL_ROOT_DIR=$(abspath $(BUILD_DIR)) -DOPENSSL_ENGINES_DIR=$(abspath $(BUILD_DIR))/lib/engines-3 -DCMAKE_INSTALL_PREFIX=$(abspath $(BUILD_DIR))
	cmake --build $(BUILD_DIR)/gost-engine --target install

clean:
	rm -rf $(BUILD_DIR) 