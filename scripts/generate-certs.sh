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
OPENSSL_MIN_MINOR=5   # 3.5 is the first version with ML-DSA (and 3.4 the first with -not_before/-not_after)

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

# make_key <name> <rsa|rsa-pss|p256|p384|p521|brainpool-p256|sm2|ed25519|ml-dsa-44>
make_key() {
  case "$2" in
    rsa)            openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$1.key" ;;
    rsa-pss)        openssl genpkey -quiet -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$1.key" ;;
    p256)           openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/$1.key" ;;
    p384)           openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$WORK/$1.key" ;;
    p521)           openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$WORK/$1.key" ;;
    brainpool-p256) openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 -out "$WORK/$1.key" ;;
    sm2)            openssl genpkey -quiet -algorithm SM2 -out "$WORK/$1.key" ;;
    ed25519)        openssl genpkey -quiet -algorithm ED25519 -out "$WORK/$1.key" ;;
    ml-dsa-44)      openssl genpkey -quiet -algorithm ML-DSA-44 -out "$WORK/$1.key" ;;
    *)              die "unknown key type: $2" ;;
  esac
}

# make_leaf_keys <name> <key type>
# An end-entity gets two keys of the same type: <name>.key, which its
# certificate is made from, and <name>.mismatch.key, which matches nothing.
make_leaf_keys() {
  make_key "$1" "$2"
  make_key "$1.mismatch" "$2"
}

# make_cert <name> <subject> <issuer|self> <extensions> [x509 options]
# The key <name>.key must already exist. <issuer> is the name of a certificate
# already generated in $WORK. The extensions are written to <name>.ext as-is.
# [x509 options] replaces the default validity (-days 365 when self-signed,
# -days 90 otherwise); it is how a scenario sets explicit dates or a serial.
make_cert() {
  if [ "$#" -ge 5 ]; then
    options="$5"
  elif [ "$3" = self ]; then
    options="-days 365"
  else
    options="-days 90"
  fi
  printf '%s\n' "$4" > "$WORK/$1.ext"
  openssl req -new -config "$WORK/req.cnf" \
    -key "$WORK/$1.key" -subj "$2" -out "$WORK/$1.csr"
  # $options is unquoted on purpose: it holds several words, one per option.
  if [ "$3" = self ]; then
    openssl x509 -req -in "$WORK/$1.csr" -signkey "$WORK/$1.key" \
      $options -extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
  else
    openssl x509 -req -in "$WORK/$1.csr" \
      -CA "$WORK/$3.pem" -CAkey "$WORK/$3.key" -CAcreateserial \
      $options -extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
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

# --- Cross-signed root --------------------------------------------------------
# The same root, a second time: same subject and same key, but signed by an
# older root. The intermediate then verifies against both copies.

step "legacy root CA (self-signed, marked as CA)"
make_key legacy-root p256
make_cert legacy-root "/CN=certdrift test legacy root CA" self "$CA_EXT"

step "root CA cross-signed by the legacy root"
cp "$WORK/root-ca.key" "$WORK/root-ca-cross.key"
make_cert root-ca-cross "/CN=certdrift test root CA" legacy-root "$CA_EXT"

# --- Other shapes of a root ---------------------------------------------------
# Each one is a way a name, a key and a signature can disagree about who issued whom.

step "root CA rolled over to an RSA key (same name, signed by the root)"
make_key root-ca-rollover rsa
make_cert root-ca-rollover "/CN=certdrift test root CA" root-ca "$CA_EXT"

step "root CA renewed under the same key (self-signed again)"
cp "$WORK/root-ca.key" "$WORK/root-ca-renewed.key"
make_cert root-ca-renewed "/CN=certdrift test root CA" self "$CA_EXT"

step "root CA whose name differs only in case (same key, self-signed)"
cp "$WORK/root-ca.key" "$WORK/root-ca-recased.key"
make_cert root-ca-recased "/CN=Certdrift Test Root CA" self "$CA_EXT"

# --- Key algorithms -----------------------------------------------------------

step "leaf RSA 2048, EKU serverAuth"
make_leaf_keys leaf-rsa rsa
make_cert leaf-rsa "/CN=rsa.example" intermediate "$(leaf_ext "DNS:rsa.example" serverAuth)"

step "leaf RSA-PSS 2048"
make_leaf_keys leaf-rsa-pss rsa-pss
make_cert leaf-rsa-pss "/CN=rsapss.example" intermediate "$(leaf_ext "DNS:rsapss.example" serverAuth)"

step "leaf EC P-256, EKU serverAuth + clientAuth"
make_leaf_keys leaf-p256 p256
make_cert leaf-p256 "/CN=p256.example" intermediate "$(leaf_ext "DNS:p256.example" "serverAuth, clientAuth")"

step "leaf EC P-384"
make_leaf_keys leaf-p384 p384
make_cert leaf-p384 "/CN=p384.example" intermediate "$(leaf_ext "DNS:p384.example" serverAuth)"

step "leaf EC P-521"
make_leaf_keys leaf-p521 p521
make_cert leaf-p521 "/CN=p521.example" intermediate "$(leaf_ext "DNS:p521.example" serverAuth)"

step "leaf EC brainpoolP256r1 (a curve outside the NIST names)"
make_leaf_keys leaf-brainpool brainpool-p256
make_cert leaf-brainpool "/CN=brainpool.example" intermediate "$(leaf_ext "DNS:brainpool.example" serverAuth)"

step "leaf SM2 (a key type Node.js does not name)"
make_leaf_keys leaf-sm2 sm2
make_cert leaf-sm2 "/CN=sm2.example" intermediate "$(leaf_ext "DNS:sm2.example" serverAuth)"

step "leaf Ed25519, no EKU"
make_leaf_keys leaf-ed25519 ed25519
make_cert leaf-ed25519 "/CN=ed25519.example" intermediate "$(leaf_ext "DNS:ed25519.example")"

step "leaf ML-DSA-44"
make_leaf_keys leaf-ml-dsa-44 ml-dsa-44
make_cert leaf-ml-dsa-44 "/CN=mldsa.example" intermediate "$(leaf_ext "DNS:mldsa.example" serverAuth)"

# --- Subject Alternative Name -------------------------------------------------

step "leaf with every SAN kind"
make_leaf_keys leaf-san-kinds p256
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
make_leaf_keys leaf-san-comma p256
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
make_leaf_keys leaf-san-quotes p256
make_cert leaf-san-quotes "/CN=quotes.example" intermediate "$(leaf_ext "@san" serverAuth)
[san]
DNS.1 = quotes.example
DNS.2 = q\\\"uote.example
URI.1 = https://example.com/\\\"q\\\""

# --- Distinguished names -----------------------------------------------------

step "leaf with a multi-component subject and a comma inside a value"
make_leaf_keys leaf-multi-dn p256
make_cert leaf-multi-dn "/C=CL/O=Acme, Inc./OU=Platform/CN=multi.example" intermediate "$(leaf_ext "DNS:multi.example" serverAuth)"

# RFC 5280 requires the SAN to be critical when the subject is empty.
step "leaf with an empty subject (no CN, SAN only)"
make_leaf_keys leaf-no-cn p256
make_cert leaf-no-cn "/" intermediate "$(leaf_ext "critical, DNS:nocn.example" serverAuth)"

# --- Validity -----------------------------------------------------------------
# The 6-day leaf starts when it is generated. The other two use fixed dates, so
# they are expired, or zero-length, whenever they are generated.

step "leaf valid for 6 days"
make_leaf_keys leaf-6-days p256
make_cert leaf-6-days "/CN=sixdays.example" intermediate "$(leaf_ext "DNS:sixdays.example" serverAuth)" \
  "-days 6"

step "leaf already expired"
make_leaf_keys leaf-expired p256
make_cert leaf-expired "/CN=expired.example" intermediate "$(leaf_ext "DNS:expired.example" serverAuth)" \
  "-not_before 20250101000000Z -not_after 20250401000000Z"

step "leaf with notBefore equal to notAfter"
make_leaf_keys leaf-zero-validity p256
make_cert leaf-zero-validity "/CN=zero.example" intermediate "$(leaf_ext "DNS:zero.example" serverAuth)" \
  "-not_before 20260101000000Z -not_after 20260101000000Z"

# --- Serial numbers -----------------------------------------------------------
# RFC 5280 requires a positive serial; real certificates still break the rule.

step "leaf with a negative serial"
make_leaf_keys leaf-serial-negative p256
make_cert leaf-serial-negative "/CN=negative.example" intermediate "$(leaf_ext "DNS:negative.example" serverAuth)" \
  "-days 90 -set_serial -5"

step "leaf with serial zero"
make_leaf_keys leaf-serial-zero p256
make_cert leaf-serial-zero "/CN=zeroserial.example" intermediate "$(leaf_ext "DNS:zeroserial.example" serverAuth)" \
  "-days 90 -set_serial 0"

# --- Self-signed --------------------------------------------------------------
# The root CA above is the self-signed certificate marked as CA.

step "self-signed leaf (not marked as CA)"
make_leaf_keys selfsigned-leaf p256
make_cert selfsigned-leaf "/CN=selfsigned.example" self "$(leaf_ext "DNS:selfsigned.example" serverAuth)"

# --- Encodings ----------------------------------------------------------------

step "leaf EC P-256 in DER (the same certificate as leaf-p256.pem)"
openssl x509 -in "$WORK/leaf-p256.pem" -outform DER -out "$WORK/leaf-p256.der"

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

step "bundle with two end-entities (leaf RSA, leaf P-256, intermediate)"
cat "$WORK/leaf-rsa.pem" "$WORK/leaf-p256.pem" "$WORK/intermediate.pem" > "$WORK/bundle-two-leaves.pem"

step "bundle with a cross-signed root (intermediate, root, cross-signed root, legacy root)"
cat "$WORK/intermediate.pem" "$WORK/root-ca.pem" "$WORK/root-ca-cross.pem" "$WORK/legacy-root.pem" > "$WORK/bundle-cross-signed.pem"

step "bundle with a root and its renewal (root, renewed root)"
cat "$WORK/root-ca.pem" "$WORK/root-ca-renewed.pem" > "$WORK/bundle-renewed-root.pem"

# --- Finish -------------------------------------------------------------------

step "recording OpenSSL details"
rm -f "$WORK"/*.csr "$WORK"/*.srl "$WORK/req.cnf"
openssl version -a > "$WORK/GENERATED.txt"

log "✓ scenarios generated"
