#!/bin/sh
# Generate the certificate scenarios used as test material.
#
# Usage: sh generate-certs.sh <output-dir>
#
# Writes only inside <output-dir>, which must already exist. Knows nothing about
# Docker or about publishing: it is run by scripts/generate.sh, either inside
# a container or on the host. Exits 0 on success and non-zero on any failure.
#
# POSIX sh on purpose: Alpine images ship busybox sh, not bash.

set -eu

WORK="${1:?usage: generate-certs.sh <output-dir>}"
OPENSSL_MIN_MAJOR=3
OPENSSL_MIN_MINOR=5   # 3.5 is the first version with ML-DSA

CURRENT="(setup)"

# --- Logging and errors -------------------------------------------------------

log()  { printf '%s\n' "$*" >&2; }
step() { CURRENT="$*"; log "→ $*"; }
die()  { log "✗ $*"; exit 1; }

# sh has no ERR trap: on exit, a non-zero status means something failed.
trap 'status=$?; if [ "$status" -ne 0 ]; then log "✗ failed at: $CURRENT"; fi' EXIT

[ -d "$WORK" ] || die "output directory does not exist: $WORK"

# --- Requirements -------------------------------------------------------------

step "checking OpenSSL"
command -v openssl >/dev/null 2>&1 || die "openssl is not installed"

VERSION="$(openssl version)"
case "$VERSION" in
  "OpenSSL "*) ;;
  *) die "OpenSSL required, found: $VERSION" ;;   # e.g. LibreSSL, macOS's /usr/bin/openssl
esac

# "OpenSSL 3.5.8 1 Jul 2025 (…)" → "3.5.8" → major 3, minor 5
number="${VERSION#OpenSSL }"
number="${number%% *}"
major="${number%%.*}"
rest="${number#*.}"
minor="${rest%%.*}"
if [ "$major" -lt "$OPENSSL_MIN_MAJOR" ] ||
   { [ "$major" -eq "$OPENSSL_MIN_MAJOR" ] && [ "$minor" -lt "$OPENSSL_MIN_MINOR" ]; }; then
  die "OpenSSL >= $OPENSSL_MIN_MAJOR.$OPENSSL_MIN_MINOR required, found: $VERSION"
fi
log "  $VERSION"

# Minimal config so that 'req' does not depend on each installation's openssl.cnf.
printf '[req]\ndistinguished_name = dn\n[dn]\n' > "$WORK/req.cnf"

# --- Helpers ------------------------------------------------------------------

# make_key <name> <rsa|p256|p384|p521|ed25519|ml-dsa-44>
make_key() {
  case "$2" in
    rsa)       openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$1.key" ;;
    p256)      openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/$1.key" ;;
    p384)      openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$WORK/$1.key" ;;
    p521)      openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$WORK/$1.key" ;;
    ed25519)   openssl genpkey -quiet -algorithm ED25519 -out "$WORK/$1.key" ;;
    ml-dsa-44) openssl genpkey -quiet -algorithm ML-DSA-44 -out "$WORK/$1.key" ;;
    *)         die "unknown key type: $2" ;;
  esac
}

# make_cert <name> <subject> <issuer|self> <extensions>
# The key <name>.key must already exist. <issuer> is the name of a certificate
# already generated in $WORK. The extensions are written to <name>.ext as-is.
make_cert() {
  printf '%s\n' "$4" > "$WORK/$1.ext"
  openssl req -new -config "$WORK/req.cnf" \
    -key "$WORK/$1.key" -subj "$2" -out "$WORK/$1.csr"
  if [ "$3" = self ]; then
    openssl x509 -req -in "$WORK/$1.csr" -signkey "$WORK/$1.key" \
      -days 365 -extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
  else
    openssl x509 -req -in "$WORK/$1.csr" \
      -CA "$WORK/$3.pem" -CAkey "$WORK/$3.key" -CAcreateserial \
      -days 90 -extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
  fi
}

# leaf_ext <subjectAltName value> [extendedKeyUsage value]
# Without the second argument the certificate has no EKU extension.
leaf_ext() {
  printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nsubjectAltName = %s\n' "$1"
  if [ -n "${2:-}" ]; then
    printf 'extendedKeyUsage = %s\n' "$2"
  fi
}

CA_EXT='basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign'

INTERMEDIATE_EXT='basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign'

# --- Chain: root → intermediate ----------------------------------------------
# Everything below is signed by the intermediate, so this section goes first.

step "root CA (self-signed, marked as CA)"
make_key root-ca p256
make_cert root-ca "/CN=certdrift test root CA" self "$CA_EXT"

step "intermediate CA"
make_key intermediate p256
make_cert intermediate "/CN=certdrift test intermediate CA" root-ca "$INTERMEDIATE_EXT"

# --- Key algorithms -----------------------------------------------------------

step "leaf RSA 2048, EKU serverAuth"
make_key leaf-rsa rsa
make_cert leaf-rsa "/CN=rsa.example" intermediate "$(leaf_ext "DNS:rsa.example" serverAuth)"

step "leaf EC P-256, EKU serverAuth + clientAuth"
make_key leaf-p256 p256
make_cert leaf-p256 "/CN=p256.example" intermediate "$(leaf_ext "DNS:p256.example" "serverAuth, clientAuth")"

step "leaf EC P-384"
make_key leaf-p384 p384
make_cert leaf-p384 "/CN=p384.example" intermediate "$(leaf_ext "DNS:p384.example" serverAuth)"

step "leaf EC P-521"
make_key leaf-p521 p521
make_cert leaf-p521 "/CN=p521.example" intermediate "$(leaf_ext "DNS:p521.example" serverAuth)"

step "leaf Ed25519, no EKU"
make_key leaf-ed25519 ed25519
make_cert leaf-ed25519 "/CN=ed25519.example" intermediate "$(leaf_ext "DNS:ed25519.example")"

step "leaf ML-DSA-44"
make_key leaf-ml-dsa-44 ml-dsa-44
make_cert leaf-ml-dsa-44 "/CN=mldsa.example" intermediate "$(leaf_ext "DNS:mldsa.example" serverAuth)"

# --- Subject Alternative Name -------------------------------------------------

step "leaf with every SAN kind"
make_key leaf-san-kinds p256
make_cert leaf-san-kinds "/CN=kinds.example" intermediate "$(leaf_ext "@san" serverAuth)
[san]
DNS.1 = kinds.example
IP.1 = 192.0.2.10
IP.2 = 2001:db8::1
email.1 = ops@example.com
URI.1 = https://example.com/service
dirName.1 = san_dir
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com
[san_dir]
CN = kinds directory name
O = certdrift"

step "leaf with SAN values containing a comma"
make_key leaf-san-comma p256
make_cert leaf-san-comma "/CN=comma.example" intermediate "$(leaf_ext "@san" serverAuth)
[san]
DNS.1 = comma.example
DNS.2 = a, b.example
URI.1 = https://example.com/x, y
dirName.1 = san_dir
[san_dir]
CN = Doe, John
O = certdrift"

# OpenSSL config files strip a bare "; it must be written as \" to survive.
# In this shell string, \\\" becomes \" in the file.
step "leaf with SAN values containing quotes"
make_key leaf-san-quotes p256
make_cert leaf-san-quotes "/CN=quotes.example" intermediate "$(leaf_ext "@san" serverAuth)
[san]
DNS.1 = quotes.example
DNS.2 = q\\\"uote.example
URI.1 = https://example.com/\\\"q\\\""

# --- Distinguished names -----------------------------------------------------

step "leaf with a multi-component subject and a comma inside a value"
make_key leaf-multi-dn p256
make_cert leaf-multi-dn "/C=CL/O=Acme, Inc./OU=Platform/CN=multi.example" intermediate "$(leaf_ext "DNS:multi.example" serverAuth)"

# --- Self-signed --------------------------------------------------------------
# The root CA above is the self-signed certificate marked as CA.

step "self-signed leaf (not marked as CA)"
make_key selfsigned-leaf p256
make_cert selfsigned-leaf "/CN=selfsigned.example" self "$(leaf_ext "DNS:selfsigned.example" serverAuth)"

# --- Bundles ------------------------------------------------------------------
# Built from certificates generated above, so this section goes last.

step "bundle in correct order (leaf, intermediate, root)"
cat "$WORK/leaf-p256.pem" "$WORK/intermediate.pem" "$WORK/root-ca.pem" > "$WORK/bundle-ordered.pem"

step "bundle out of order (root, leaf, intermediate)"
cat "$WORK/root-ca.pem" "$WORK/leaf-p256.pem" "$WORK/intermediate.pem" > "$WORK/bundle-shuffled.pem"

step "bundle with duplicates (leaf, intermediate, intermediate, root)"
cat "$WORK/leaf-p256.pem" "$WORK/intermediate.pem" "$WORK/intermediate.pem" "$WORK/root-ca.pem" > "$WORK/bundle-duplicates.pem"

step "bundle without end-entity (intermediate, root)"
cat "$WORK/intermediate.pem" "$WORK/root-ca.pem" > "$WORK/bundle-no-leaf.pem"

# --- Finish -------------------------------------------------------------------

step "recording OpenSSL details"
rm -f "$WORK"/*.csr "$WORK"/*.srl "$WORK/req.cnf"
openssl version -a > "$WORK/GENERATED.txt"

log "✓ scenarios generated"