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

// CN twoeku. Two Extended Key Usage extensions, serverAuth and clientAuth, which is not valid
// X.509. Made like EMPTY_EKU_EXTENSION, with a one-year validity (`notAfter =
// GENERALIZEDTIME:20270101000000Z`) and these extensions
//     [extensions]
//     first = SEQUENCE:first
//     second = SEQUENCE:second
//     [first]
//     id = OID:extendedKeyUsage
//     value = OCTWRAP,SEQUENCE:serverAuth
//     [serverAuth]
//     usage = OID:serverAuth
//     [second]
//     id = OID:extendedKeyUsage
//     value = OCTWRAP,SEQUENCE:clientAuth
//     [clientAuth]
//     usage = OID:clientAuth
// Node.js gives `undefined` for it, the same as for an absent extension.
export const REPEATED_EKU_EXTENSION = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBATCB56ADAgECAgEFMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnR3b2VrdTAi",
    "GA8yMDI2MDEwMTAwMDAwMFoYDzIwMjcwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAZ0",
    "d29la3UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz8Gn6CvlMx96w",
    "r+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+4n/DwjTqRvFS",
    "oywwKjATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHSUEDDAKBggrBgEFBQcDAjAK",
    "BggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ekuconstr. One Extended Key Usage extension, serverAuth, whose value is a constructed OCTET
// STRING of two primitive ones, which BER allows and DER does not. Made like EMPTY_EKU_EXTENSION
// from the extension
//     [first]
//     id = OID:extendedKeyUsage
//     value = OCTWRAP,SEQUENCE:usages
//     [usages]
//     usage = OID:serverAuth
// whose DER was then edited: the value `04 0c 30 0a 06 08 2b 06 01 05 05 07 03 01` became
// `24 10 04 06 30 0a 06 08 2b 06 04 06 01 05 05 07 03 01`, and the lengths of the five elements
// that contain it, the extension `30 13`, the sequence of extensions `30 15`, the field `a3 17`,
// the body `30 81 d4` and the certificate `30 81 ee`, grew by 4. There is no basicConstraints.
// Node.js reads it, with `["1.3.6.1.5.5.7.3.1"]` for the usages, and keeps the bytes as they are.
export const CONSTRUCTED_EKU_EXTENSION = [
    "-----BEGIN CERTIFICATE-----",
    "MIH2MIHcoAMCAQICAQUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZWt1Y29uc3Ry",
    "MCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM",
    "CWVrdWNvbnN0cjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBCJnuhkxFSPoDtI",
    "HpNrUqsr2Ef4jJ8GaGSzjJ3T1RNvUG6ZUoItrX4VnX8Olnd1+nb6iWE70/vVa8Yt",
    "kruO/MOjGzAZMBcGA1UdJSQQBAYwCgYIKwYEBgEFBQcDATAKBggqhkjOPQQDAgMJ",
    "ADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");
