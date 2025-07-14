#!/bin/bash
set -e

OPENSSL_DIR=submodules/openssl
CGO_DIR=cgo/src
BUILD_DIR=build
INCLUDE_DIR=include

mkdir -p $BUILD_DIR $INCLUDE_DIR

# --- AES + CBC/ECB core ---
CORE_SOURCES=(
  "$OPENSSL_DIR/crypto/aes/aes_core.c"
  "$OPENSSL_DIR/crypto/aes/aes_cbc.c"
  "$OPENSSL_DIR/crypto/aes/aes_ecb.c"
  "$OPENSSL_DIR/crypto/modes/cbc128.c"
  "$OPENSSL_DIR/crypto/mem_clr.c"
  "$OPENSSL_DIR/crypto/cryptlib.c"
)

EVP_SOURCES=(
  "$OPENSSL_DIR/crypto/evp/evp_enc.c"
  "$OPENSSL_DIR/crypto/evp/evp_lib.c"
  "$OPENSSL_DIR/crypto/evp/e_aes.c"
  "$OPENSSL_DIR/crypto/evp/evp_fetch.c"
  "$OPENSSL_DIR/crypto/evp/keymgmt_lib.c"
  "$OPENSSL_DIR/crypto/evp/names.c"
  "$OPENSSL_DIR/crypto/evp/cmeth_lib.c"
  "$OPENSSL_DIR/crypto/mem.c"
  "$OPENSSL_DIR/crypto/err/err.c"
  "$OPENSSL_DIR/crypto/objects/obj_dat.c"
  "$OPENSSL_DIR/crypto/objects/obj_lib.c"
  "$OPENSSL_DIR/crypto/property/property.c"
#  "$OPENSSL_DIR/crypto/rand/rand_lib.c"
#  "$OPENSSL_DIR/crypto/bn/bn_lib.c"
  "$OPENSSL_DIR/crypto/stack/stack.c"
  "$OPENSSL_DIR/crypto/lhash/lhash.c"
  "$OPENSSL_DIR/crypto/ctype.c"
#  "$OPENSSL_DIR/crypto/init.c"
)

ASN1_SOURCES=(
  "$OPENSSL_DIR/crypto/asn1/a_octet.c"
  "$OPENSSL_DIR/crypto/asn1/a_type.c"
  "$OPENSSL_DIR/crypto/asn1/tasn_enc.c"
  "$OPENSSL_DIR/crypto/asn1/tasn_dec.c"
  "$OPENSSL_DIR/crypto/objects/obj_dat.c"
  "$OPENSSL_DIR/crypto/objects/obj_lib.c"
  "$OPENSSL_DIR/crypto/err/err.c"
)

PKCS7_SOURCES=(
  "$OPENSSL_DIR/crypto/pkcs7/pk7_lib.c"
  "$OPENSSL_DIR/crypto/pkcs7/pk7_doit.c"
)

# --- все вместе ---
SOURCES=(
  "cgo/src/minicrypto.c"
  "cgo/src/pkcs7.c"
  "${CORE_SOURCES[@]}"
  "${EVP_SOURCES[@]}"
  "${ASN1_SOURCES[@]}"
  "${PKCS7_SOURCES[@]}"
)

# компилируем
for src in "${SOURCES[@]}"; do
  gcc -c \
    -Wno-deprecated-declarations \
    -I"$OPENSSL_DIR/include" \
    -I"$OPENSSL_DIR" \
    -I"$CGO_SRC/include" \
    -o "$BUILD_DIR/$(basename "$src" .c).o" \
    "$src"
done

# собираем статическую библиотеку
ar rcs "$BUILD_DIR/libminicrypto.a" "$BUILD_DIR"/*.o
