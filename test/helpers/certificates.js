/**
 * Certificates that OpenSSL's own commands will not write, hand-built because a test needs the
 * case, made once with `openssl asn1parse -genconf <file> -noout -out <name>.der` and then
 * `openssl x509 -inform DER -in <name>.der -outform PEM`. Their signature is not valid, which does
 * not matter for a certificate observed alone. They share this configuration, with
 * `$PUBLIC_KEY` the 65 bytes of a P-256 public point in hexadecimal and `$CN` a common name:
 *
 *     asn1 = SEQUENCE:certificate
 *     [certificate]
 *     tbs = SEQUENCE:tbs
 *     sigalg = SEQUENCE:sigalg
 *     sig = FORMAT:HEX,BITSTRING:3006020101020101
 *     [sigalg]
 *     algorithm = OID:ecdsa-with-SHA256
 *     [tbs]
 *     version = EXPLICIT:0,INTEGER:2
 *     serial = INTEGER:5
 *     sigalg = SEQUENCE:sigalg
 *     issuer = SEQUENCE:name
 *     validity = SEQUENCE:validity
 *     subject = SEQUENCE:name
 *     spki = SEQUENCE:spki
 *     [name]
 *     rdn = SET:rdn
 *     [rdn]
 *     attribute = SEQUENCE:attribute
 *     [attribute]
 *     type = OID:commonName
 *     value = UTF8:$CN
 *     [spki]
 *     algorithm = SEQUENCE:ecalgorithm
 *     key = FORMAT:HEX,BITSTRING:$PUBLIC_KEY
 *     [ecalgorithm]
 *     id = OID:id-ecPublicKey
 *     curve = OID:prime256v1
 *
 * and differ in the `[validity]` section and in the extensions, as each constant says. Other
 * hand-built certificates of this kind are in `test/fields.test.js`, made from the same configuration.
 */

// CN empty. An Extended Key Usage extension that is present and lists nothing: its value is an
// empty SEQUENCE. Made like the others, a P-256 public key, a dummy signature and these
// validity dates, with the extensions section
//     exts = EXPLICIT:3,SEQUENCE:extensions
//     [extensions]
//     first = SEQUENCE:first
//     [first]
//     id = OID:extendedKeyUsage
//     value = OCTWRAP,SEQUENCE:none
//     [none]
// Node.js shows an empty list of usages, which is not what it shows for an absent extension.
export const EMPTY_EKU_EXTENSION = [
    "-----BEGIN CERTIFICATE-----",
    "MIHgMIHGoAMCAQICAQUwCgYIKoZIzj0EAwIwEDEOMAwGA1UEAwwFZW1wdHkwIhgP",
    "MjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowEDEOMAwGA1UEAwwFZW1w",
    "dHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQQiZ7oZMRUj6A7SB6Ta1KrK9hH",
    "+IyfBmhks4yd09UTb1BumVKCLa1+FZ1/DpZ3dfp2+olhO9P71WvGLZK7jvzDow0w",
    "CzAJBgNVHSUEAjAAMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN undecodable. An Extended Key Usage extension whose value is an INTEGER where a SEQUENCE of
// usages belongs. Made like EMPTY_EKU_EXTENSION, with
//     [first]
//     id = OID:extendedKeyUsage
//     value = OCTWRAP,INTEGER:1
// Node.js gives `undefined` for it, the same as for an absent extension.
export const UNDECODABLE_EKU_EXTENSION = [
    "-----BEGIN CERTIFICATE-----",
    "MIHtMIHToAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLdW5kZWNvZGFi",
    "bGUwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLdW5kZWNvZGFibGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQQiZ7oZMRU",
    "j6A7SB6Ta1KrK9hH+IyfBmhks4yd09UTb1BumVKCLa1+FZ1/DpZ3dfp2+olhO9P7",
    "1WvGLZK7jvzDow4wDDAKBgNVHSUEAwIBATAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");
