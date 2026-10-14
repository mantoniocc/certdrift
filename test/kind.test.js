import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect } from "../src/index.js";
import * as kindWarningModule from "../src/kind-warning.js";
import { kindWarning } from "../src/kind-warning.js";
import { certificatesIn } from "../src/material.js";
import { validatorFor } from "./helpers/schema.js";

// What `kind` says about a certificate: `ca` when basicConstraints marks it as a CA and, if a Key
// Usage extension is present, it includes keyCertSign, and `end-entity` otherwise. The fixtures
// only cover CA:TRUE together with keyCertSign, so the cases that separate this rule from "the
// basicConstraints says CA:TRUE" are built here, from fixed bytes: `npm run fixtures` replaces
// the fixtures with new keys, and `openssl req -x509` adds extensions of its own from the default
// configuration, so material made that way may not hold the extensions a test means to have.
// Every certificate below is therefore checked by `carries`, which finds the bytes of its
// extensions in the certificate itself, before its kind is asserted.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/**
 * Made once with `openssl asn1parse -genconf <file> -noout -out <name>.der` and then
 * `openssl x509 -inform DER -in <name>.der -outform PEM`, which writes what it is told to and
 * adds nothing. Their signature is not valid, which does not matter for a certificate observed
 * alone and whose kind is read from its extensions. They share this configuration, with
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
 *     exts = EXPLICIT:3,SEQUENCE:extensions
 *     [name]
 *     rdn = SET:rdn
 *     [rdn]
 *     attribute = SEQUENCE:attribute
 *     [attribute]
 *     type = OID:commonName
 *     value = UTF8:$CN
 *     [validity]
 *     notBefore = GENERALIZEDTIME:20260101000000Z
 *     notAfter = GENERALIZEDTIME:20360101000000Z
 *     [spki]
 *     algorithm = SEQUENCE:ecalgorithm
 *     key = FORMAT:HEX,BITSTRING:$PUBLIC_KEY
 *     [ecalgorithm]
 *     id = OID:id-ecPublicKey
 *     curve = OID:prime256v1
 *     [extensions]
 *     e1 = SEQUENCE:<first extension>
 *     e2 = SEQUENCE:<second extension>
 *
 * and differ in the extensions, which are the sections named in `EXTENSIONS`. A version 1
 * certificate leaves out the `version` line, and one with no extensions leaves out `exts`. The one
 * whose extensions field is empty keeps `exts` and lists no `e1`. A value that a section cannot
 * write, such as a length in the long form, is given as `FORMAT:HEX,OCTETSTRING:<its bytes>`.
 *
 * `genconf` writes definite lengths only, so the certificate with an indefinite length was made
 * from one with `CA:TRUE` alone by editing its DER: the extensions field `a3 13 <sequence>`
 * became `a3 80 <sequence> 00 00`, and the lengths of the two sequences that contain it, `30 81 f0`
 * and `30 81 d6`, grew by 2, to `30 81 f2` and `30 81 d8`.
 *
 * Each constant says which extensions it carries, as `openssl x509 -noout -ext
 * basicConstraints,keyUsage,subjectAltName` reported them when it was made.
 */

/**
 * The DER of each extension, from `asn1 = SEQUENCE:<section>` with the section written here.
 * Each value is what the certificate holds, so `carries` can look for it.
 */
const EXTENSIONS = {
    // id = OID:basicConstraints, critical = BOOLEAN:TRUE, value = OCTWRAP,SEQUENCE:value, with value: ca = BOOLEAN:TRUE
    basicConstraintsCa: "300f0603551d130101ff040530030101ff",
    // The same without the critical flag.
    basicConstraintsCaNotCritical: "300c0603551d13040530030101ff",
    // Critical, and its value is OCTWRAP,INTEGER:1, where a SEQUENCE belongs.
    basicConstraintsUndecodable: "300d0603551d130101ff0403020101",
    // id = OID:keyUsage, critical = BOOLEAN:TRUE, value = OCTWRAP,FORMAT:BITLIST,BITSTRING:5
    keyUsageCertSign: "300e0603551d0f0101ff040403020204",
    // The same with BITSTRING:0, which is digitalSignature.
    keyUsageDigitalSignature: "300e0603551d0f0101ff040403020780",
    // Critical, and its value is FORMAT:HEX,OCTETSTRING:030100: a bit string with no bit in it.
    keyUsageWithoutBits: "300d0603551d0f0101ff0403030100",
    // id = OID:subjectAltName, value = OCTWRAP,SEQUENCE:names, with names: dns = IMPLICIT:2,IA5STRING:a.example
    subjectAltName: "30140603551d11040d300b8209612e6578616d706c65",
    // Its value is OCTWRAP,INTEGER:1, where a SEQUENCE belongs.
    subjectAltNameUndecodable: "300a0603551d110403020101",
    // Critical, and its value is FORMAT:HEX,OCTETSTRING:3000: an empty sequence, which is CA:FALSE.
    basicConstraintsNotCa: "300c0603551d130101ff04023000",
    // CA:TRUE and pathlen:0, which lets the CA sign end-entity certificates and no other CA.
    basicConstraintsCaPathLength0: "30120603551d130101ff040830060101ff020100",
    // CA:TRUE and pathlen:-1, which OpenSSL cannot decode: a path length cannot be negative.
    basicConstraintsNegativePathLength: "30120603551d130101ff040830060101ff0201ff",
    // Only a path length, which leaves cA at its default, FALSE: pathlen = INTEGER:1
    basicConstraintsPathLengthWithoutCa: "300f0603551d130101ff04053003020101",
    // The value is FORMAT:HEX,OCTETSTRING:3081030101ff: CA:TRUE with the sequence length written as 81 03.
    basicConstraintsCaLongLength: "30100603551d130101ff04063081030101ff",
    // The value is FORMAT:HEX,OCTETSTRING:30030101ff0500: CA:TRUE and then a NULL after the sequence.
    basicConstraintsCaTrailingBytes: "30110603551d130101ff040730030101ff0500",
    // The value is FORMAT:HEX,OCTETSTRING:30060201010101ff: the path length, then cA.
    basicConstraintsPathLengthFirst: "30120603551d130101ff040830060201010101ff",
    // Critical, and its value is FORMAT:HEX,OCTETSTRING:03020804: a bit string with 8 unused bits.
    keyUsageUnusedBitsOutOfRange: "300e0603551d0f0101ff040403020804",
    // id = OID:extendedKeyUsage, value = OCTWRAP,SEQUENCE:ekuValue, with ekuValue: usage = OID:serverAuth
    extendedKeyUsage: "30130603551d25040c300a06082b06010505070301",
    // Its value is OCTWRAP,INTEGER:1, where a SEQUENCE belongs.
    extendedKeyUsageUndecodable: "300a0603551d250403020101",
    // id = OID:subjectKeyIdentifier, value = OCTWRAP,FORMAT:HEX,OCTETSTRING:<20 bytes of 11>
    subjectKeyIdentifier: "301d0603551d0e041604141111111111111111111111111111111111111111",
    // Its value is OCTWRAP,INTEGER:1, where an OCTET STRING belongs.
    subjectKeyIdentifierUndecodable: "300a0603551d0e0403020101",
    // id = OID:1.2.3.4, value = OCTWRAP,NULL, with and without critical = BOOLEAN:TRUE
    unknownCritical: "300c06032a03040101ff04020500",
    unknown: "300906032a030404020500",
    // id = OID:2.16.840.1.113730.1.1 (Netscape Certificate Type), value = OCTWRAP,FORMAT:BITLIST,BITSTRING:5, which is sslCA
    netscapeSslCa: "301106096086480186f8420101040403020204",
};

// CN ca-alone. basicConstraints critical, CA:TRUE. No Key Usage.
const CA_ALONE = [
    "-----BEGIN CERTIFICATE-----",
    "MIHsMIHSoAMCAQICAQUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIY2EtYWxvbmUw",
    "IhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowEzERMA8GA1UEAwwI",
    "Y2EtYWxvbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz8Gn6CvlM",
    "x96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+4n/DwjTq",
    "RvFSoxMwETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-certsign. basicConstraints critical, CA:TRUE. Key Usage critical, keyCertSign.
const CA_CERTSIGN = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBAjCB6KADAgECAgEFMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2NhLWNlcnRz",
    "aWduMCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBYxFDASBgNV",
    "BAMMC2NhLWNlcnRzaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XC",
    "c/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3l",
    "fuJ/w8I06kbxUqMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQw",
    "CgYIKoZIzj0EAwIDCQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-digitalsignature. basicConstraints critical, CA:TRUE. Key Usage critical, digitalSignature only.
const CA_DIGITALSIGNATURE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBEjCB+KADAgECAgEFMAoGCCqGSM49BAMCMB4xHDAaBgNVBAMME2NhLWRpZ2l0",
    "YWxzaWduYXR1cmUwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFow",
    "HjEcMBoGA1UEAwwTY2EtZGlnaXRhbHNpZ25hdHVyZTBZMBMGByqGSM49AgEGCCqG",
    "SM49AwEHA0IABI24OVOVwnPwafoK+UzH3rCv78+sfDY+l3Z5bCl4FH7eZqyj/69a",
    "WTIJzNshztej6nBmaZn95X7if8PCNOpG8VKjIzAhMA8GA1UdEwEB/wQFMAMBAf8w",
    "DgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN certsign-no-bc. Key Usage critical, keyCertSign. No basicConstraints.
const CERTSIGN_WITHOUT_BASIC_CONSTRAINTS = [
    "-----BEGIN CERTIFICATE-----",
    "MIH3MIHdoAMCAQICAQUwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOY2VydHNpZ24t",
    "bm8tYmMwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowGTEXMBUG",
    "A1UEAwwOY2VydHNpZ24tbm8tYmMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASN",
    "uDlTlcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pw",
    "ZmmZ/eV+4n/DwjTqRvFSoxIwEDAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwID",
    "CQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-ku-nobits. basicConstraints critical, CA:TRUE. Key Usage critical, present with no bit set (openssl prints it as "...").
const CA_KEY_USAGE_WITHOUT_BITS = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBAzCB6aADAgECAgEFMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDGNhLWt1LW5v",
    "Yml0czAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAXMRUwEwYD",
    "VQQDDAxjYS1rdS1ub2JpdHMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlT",
    "lcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ",
    "/eV+4n/DwjTqRvFSoyIwIDAPBgNVHRMBAf8EBTADAQH/MA0GA1UdDwEB/wQDAwEA",
    "MAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-noncritical. basicConstraints not critical, CA:TRUE. No Key Usage.
const CA_NOT_CRITICAL = [
    "-----BEGIN CERTIFICATE-----",
    "MIH1MIHboAMCAQICAQUwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOY2Etbm9uY3Jp",
    "dGljYWwwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowGTEXMBUG",
    "A1UEAwwOY2Etbm9uY3JpdGljYWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASN",
    "uDlTlcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pw",
    "ZmmZ/eV+4n/DwjTqRvFSoxAwDjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCAwkA",
    "MAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-twice. basicConstraints critical, CA:TRUE, twice, which is not valid X.509.
const BASIC_CONSTRAINTS_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIH9MIHjoAMCAQICAQUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIYmMtdHdpY2Uw",
    "IhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowEzERMA8GA1UEAwwI",
    "YmMtdHdpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz8Gn6CvlM",
    "x96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+4n/DwjTq",
    "RvFSoyQwIjAPBgNVHRMBAf8EBTADAQH/MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI",
    "zj0EAwIDCQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN san-twice. basicConstraints critical, CA:TRUE. subjectAltName DNS:a.example, twice, which is not valid X.509.
const SAN_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBGzCCAQCgAwIBAgIBBTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlzYW4tdHdp",
    "Y2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFDESMBAGA1UE",
    "AwwJc2FuLXR3aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp",
    "+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/",
    "w8I06kbxUqM/MD0wDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglhLmV4YW1w",
    "bGUwFAYDVR0RBA0wC4IJYS5leGFtcGxlMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-garbage. basicConstraints critical, whose value is an INTEGER where a SEQUENCE belongs (openssl prints it as "...").
const BASIC_CONSTRAINTS_UNDECODABLE = [
    "-----BEGIN CERTIFICATE-----",
    "MIHuMIHUoAMCAQICAQUwCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKYmMtZ2FyYmFn",
    "ZTAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAVMRMwEQYDVQQD",
    "DApiYy1nYXJiYWdlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp",
    "+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/",
    "w8I06kbxUqMRMA8wDQYDVR0TAQH/BAMCAQEwCgYIKoZIzj0EAwIDCQAwBgIBAQIB",
    "AQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN san-garbage. basicConstraints critical, CA:TRUE. subjectAltName whose value is an INTEGER where a SEQUENCE belongs.
const SAN_UNDECODABLE = [
    "-----BEGIN CERTIFICATE-----",
    "MIH+MIHkoAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLc2FuLWdhcmJh",
    "Z2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLc2FuLWdhcmJhZ2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSox8wHTAPBgNVHRMBAf8EBTADAQH/MAoGA1UdEQQDAgEBMAoGCCqG",
    "SM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN unknown-critical. basicConstraints critical, CA:TRUE. A critical extension, 1.2.3.4, that nothing defines.
const UNKNOWN_CRITICAL = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBCjCB8KADAgECAgEFMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEHVua25vd24t",
    "Y3JpdGljYWwwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowGzEZ",
    "MBcGA1UEAwwQdW5rbm93bi1jcml0aWNhbDBZMBMGByqGSM49AgEGCCqGSM49AwEH",
    "A0IABI24OVOVwnPwafoK+UzH3rCv78+sfDY+l3Z5bCl4FH7eZqyj/69aWTIJzNsh",
    "ztej6nBmaZn95X7if8PCNOpG8VKjITAfMA8GA1UdEwEB/wQFMAMBAf8wDAYDKgME",
    "AQH/BAIFADAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN unknown-twice. basicConstraints critical, CA:TRUE. An extension, 1.2.3.4, that nothing defines, twice.
const UNKNOWN_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBDDCB8qADAgECAgEFMAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDXVua25vd24t",
    "dHdpY2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowGDEWMBQG",
    "A1UEAwwNdW5rbm93bi10d2ljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI24",
    "OVOVwnPwafoK+UzH3rCv78+sfDY+l3Z5bCl4FH7eZqyj/69aWTIJzNshztej6nBm",
    "aZn95X7if8PCNOpG8VKjKTAnMA8GA1UdEwEB/wQFMAMBAf8wCQYDKgMEBAIFADAJ",
    "BgMqAwQEAgUAMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN v1-ca. Version 1, which has no place for extensions, carrying basicConstraints critical, CA:TRUE.
const V1_WITH_CA = [
    "-----BEGIN CERTIFICATE-----",
    "MIHhMIHHAgEFMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBXYxLWNhMCIYDzIwMjYw",
    "MTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBAxDjAMBgNVBAMMBXYxLWNhMFkw",
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8Nj6X",
    "dnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I06kbxUqMTMBEwDwYD",
    "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN nsca. Netscape Certificate Type sslCA. No basicConstraints and no Key Usage.
const NETSCAPE_CA = [
    "-----BEGIN CERTIFICATE-----",
    "MIHmMIHMoAMCAQICAQUwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEbnNjYTAiGA8y",
    "MDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARuc2Nh",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8",
    "Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I06kbxUqMVMBMw",
    "EQYJYIZIAYb4QgEBBAQDAgIEMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN v1root. Version 1, with no extensions at all, signed by its own key.
const V1_ROOT = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBCjCBsAIBBTAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZ2MXJvb3QwHhcNMjYx",
    "MDEyMTgyODAzWhcNMzYxMDA5MTgyODAzWjARMQ8wDQYDVQQDDAZ2MXJvb3QwWTAT",
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAAShrR//G9hUqcrfxw1Tw/3ipZgY/1mGSZ56",
    "iA+7+3/gDslXxA9QVqAGob5UymcPQonleUjYXt6ebxZJa41HO31rMAoGCCqGSM49",
    "BAMCA0kAMEYCIQCmzW3XGnuDywZIKUDbeMBLN5Xm7I8ow0NQL+0NcLCDAQIhAIfX",
    "Dw//Zx2/ZdYn/oxzU5wLBt7ZvctX9lN3t4ya5ERE",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-false. basicConstraints critical, CA:FALSE. Key Usage critical, digitalSignature.
const CA_FALSE = [
    "-----BEGIN CERTIFICATE-----",
    "MIH5MIHfoAMCAQICAQUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIY2EtZmFsc2Uw",
    "IhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowEzERMA8GA1UEAwwI",
    "Y2EtZmFsc2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz8Gn6CvlM",
    "x96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+4n/DwjTq",
    "RvFSoyAwHjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQD",
    "AgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ca-pathlen-0. basicConstraints critical, CA:TRUE, pathlen:0. Key Usage critical, keyCertSign.
const CA_PATH_LENGTH_0 = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBBzCB7aADAgECAgEFMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDGNhLXBhdGhs",
    "ZW4tMDAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAXMRUwEwYD",
    "VQQDDAxjYS1wYXRobGVuLTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlT",
    "lcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ",
    "/eV+4n/DwjTqRvFSoyYwJDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQE",
    "AwICBDAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN v3-no-extensions. Version 3 with no extensions field.
const VERSION_3_WITHOUT_EXTENSIONS = [
    "-----BEGIN CERTIFICATE-----",
    "MIHnMIHNoAMCAQICAQUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQdjMtbm8tZXh0",
    "ZW5zaW9uczAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAbMRkw",
    "FwYDVQQDDBB2My1uby1leHRlbnNpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD",
    "QgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO",
    "16PqcGZpmf3lfuJ/w8I06kbxUjAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN empty-extensions. Version 3 whose extensions field is present and holds an empty sequence.
const EMPTY_EXTENSIONS = [
    "-----BEGIN CERTIFICATE-----",
    "MIHrMIHRoAMCAQICAQUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQZW1wdHktZXh0",
    "ZW5zaW9uczAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAbMRkw",
    "FwYDVQQDDBBlbXB0eS1leHRlbnNpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD",
    "QgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO",
    "16PqcGZpmf3lfuJ/w8I06kbxUqMCMAAwCgYIKoZIzj0EAwIDCQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ku-twice. basicConstraints critical, CA:TRUE. Key Usage critical, keyCertSign, twice, which is not valid X.509.
const KEY_USAGE_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBDDCB8qADAgECAgEFMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCGt1LXR3aWNl",
    "MCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBMxETAPBgNVBAMM",
    "CGt1LXR3aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5",
    "TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I0",
    "6kbxUqMzMDEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDgYDVR0P",
    "AQH/BAQDAgIEMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-ku-bc. basicConstraints critical, CA:TRUE, then Key Usage critical, keyCertSign, then the same basicConstraints again.
const BASIC_CONSTRAINTS_KEY_USAGE_BASIC_CONSTRAINTS = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBDTCB86ADAgECAgEFMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCGJjLWt1LWJj",
    "MCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBMxETAPBgNVBAMM",
    "CGJjLWt1LWJjMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5",
    "TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I0",
    "6kbxUqM0MDIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0T",
    "AQH/BAUwAwEB/zAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-negative. basicConstraints critical, CA:TRUE, pathlen:-1, which is not valid X.509.
const BASIC_CONSTRAINTS_NEGATIVE_PATH_LENGTH = [
    "-----BEGIN CERTIFICATE-----",
    "MIH1MIHboAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLYmMtbmVnYXRp",
    "dmUwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLYmMtbmVnYXRpdmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSoxYwFDASBgNVHRMBAf8ECDAGAQH/AgH/MAoGCCqGSM49BAMCAwkA",
    "MAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN eku-twice. basicConstraints critical, CA:TRUE. Extended Key Usage serverAuth, twice, which is not valid X.509.
const EKU_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBGDCB/qADAgECAgEFMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWVrdS10d2lj",
    "ZTAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQD",
    "DAlla3UtdHdpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz8Gn6",
    "CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+4n/D",
    "wjTqRvFSoz0wOzAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMB",
    "MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN eku-garbage. basicConstraints critical, CA:TRUE. Extended Key Usage whose value is an INTEGER where a SEQUENCE belongs.
const EKU_UNDECODABLE = [
    "-----BEGIN CERTIFICATE-----",
    "MIH+MIHkoAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLZWt1LWdhcmJh",
    "Z2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLZWt1LWdhcmJhZ2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSox8wHTAPBgNVHRMBAf8EBTADAQH/MAoGA1UdJQQDAgEBMAoGCCqG",
    "SM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ski-twice. basicConstraints critical, CA:TRUE. subjectKeyIdentifier, twice, which is not valid X.509.
const SKI_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBLTCCARKgAwIBAgIBBTAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlza2ktdHdp",
    "Y2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFDESMBAGA1UE",
    "AwwJc2tpLXR3aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp",
    "+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/",
    "w8I06kbxUqNRME8wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUERERERERERER",
    "EREREREREREREREwHQYDVR0OBBYEFBERERERERERERERERERERERERERMAoGCCqG",
    "SM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ski-garbage. basicConstraints critical, CA:TRUE. subjectKeyIdentifier whose value is an INTEGER where an OCTET STRING belongs.
const SKI_UNDECODABLE = [
    "-----BEGIN CERTIFICATE-----",
    "MIH+MIHkoAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLc2tpLWdhcmJh",
    "Z2UwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLc2tpLWdhcmJhZ2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSox8wHTAPBgNVHRMBAf8EBTADAQH/MAoGA1UdDgQDAgEBMAoGCCqG",
    "SM49BAMCAwkAMAYCAQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ku-unused-8. basicConstraints critical, CA:TRUE. Key Usage critical, whose unused-bits octet is 8, where 7 is the most a bit string can have.
const KEY_USAGE_UNUSED_BITS_OUT_OF_RANGE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBAjCB6KADAgECAgEFMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2t1LXVudXNl",
    "ZC04MCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBYxFDASBgNV",
    "BAMMC2t1LXVudXNlZC04MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XC",
    "c/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3l",
    "fuJ/w8I06kbxUqMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCCAQw",
    "CgYIKoZIzj0EAwIDCQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-long-length. basicConstraints critical, CA:TRUE, whose sequence has its length written in the long form (81 03) where the short form would do.
const BASIC_CONSTRAINTS_LONG_LENGTH = [
    "-----BEGIN CERTIFICATE-----",
    "MIH5MIHfoAMCAQICAQUwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOYmMtbG9uZy1s",
    "ZW5ndGgwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowGTEXMBUG",
    "A1UEAwwOYmMtbG9uZy1sZW5ndGgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASN",
    "uDlTlcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pw",
    "ZmmZ/eV+4n/DwjTqRvFSoxQwEjAQBgNVHRMBAf8EBjCBAwEB/zAKBggqhkjOPQQD",
    "AgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-pathlen-no-ca. basicConstraints critical with a path length of 1 and no cA, which reads as CA:FALSE.
const BASIC_CONSTRAINTS_PATH_LENGTH_WITHOUT_CA = [
    "-----BEGIN CERTIFICATE-----",
    "MIH8MIHioAMCAQICAQUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQYmMtcGF0aGxl",
    "bi1uby1jYTAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAbMRkw",
    "FwYDVQQDDBBiYy1wYXRobGVuLW5vLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD",
    "QgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO",
    "16PqcGZpmf3lfuJ/w8I06kbxUqMTMBEwDwYDVR0TAQH/BAUwAwIBATAKBggqhkjO",
    "PQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-trailing. basicConstraints critical, CA:TRUE, with two bytes (a NULL) after its sequence inside the extension value.
const BASIC_CONSTRAINTS_TRAILING_BYTES = [
    "-----BEGIN CERTIFICATE-----",
    "MIH0MIHaoAMCAQICAQUwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLYmMtdHJhaWxp",
    "bmcwIhgPMjAyNjAxMDEwMDAwMDBaGA8yMDM2MDEwMTAwMDAwMFowFjEUMBIGA1UE",
    "AwwLYmMtdHJhaWxpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSoxUwEzARBgNVHRMBAf8EBzADAQH/BQAwCgYIKoZIzj0EAwIDCQAw",
    "BgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN bc-pathlen-first. basicConstraints critical whose sequence holds the path length before cA.
const BASIC_CONSTRAINTS_FIELDS_OUT_OF_ORDER = [
    "-----BEGIN CERTIFICATE-----",
    "MIH/MIHloAMCAQICAQUwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQYmMtcGF0aGxl",
    "bi1maXJzdDAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAbMRkw",
    "FwYDVQQDDBBiYy1wYXRobGVuLWZpcnN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD",
    "QgAEjbg5U5XCc/Bp+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO",
    "16PqcGZpmf3lfuJ/w8I06kbxUqMWMBQwEgYDVR0TAQH/BAgwBgIBAQEB/zAKBggq",
    "hkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN indefinite. basicConstraints critical, CA:TRUE, inside an extensions field whose length is indefinite (a3 80 ... 00 00).
const INDEFINITE_LENGTH = [
    "-----BEGIN CERTIFICATE-----",
    "MIHyMIHYoAMCAQICAQUwCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKaW5kZWZpbml0",
    "ZTAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAVMRMwEQYDVQQD",
    "DAppbmRlZmluaXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp",
    "+gr5TMfesK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/",
    "w8I06kbxUqOAMBEwDwYDVR0TAQH/BAUwAwEB/wAAMAoGCCqGSM49BAMCAwkAMAYC",
    "AQECAQE=",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN both-twice. basicConstraints critical, CA:TRUE, and Key Usage critical, keyCertSign, each of them twice, which is not valid X.509.
const BASIC_CONSTRAINTS_AND_KEY_USAGE_TWICE = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBIjCCAQegAwIBAgIBBTAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApib3RoLXR3",
    "aWNlMCIYDzIwMjYwMTAxMDAwMDAwWhgPMjAzNjAxMDEwMDAwMDBaMBUxEzARBgNV",
    "BAMMCmJvdGgtdHdpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlTlcJz",
    "8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ/eV+",
    "4n/DwjTqRvFSo0QwQjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAP",
    "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgMJADAG",
    "AgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN ku-before-bc. Key Usage critical, keyCertSign, and then basicConstraints critical, CA:TRUE: the extensions in the other order.
const KEY_USAGE_BEFORE_BASIC_CONSTRAINTS = [
    "-----BEGIN CERTIFICATE-----",
    "MIIBBDCB6qADAgECAgEFMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDGt1LWJlZm9y",
    "ZS1iYzAiGA8yMDI2MDEwMTAwMDAwMFoYDzIwMzYwMTAxMDAwMDAwWjAXMRUwEwYD",
    "VQQDDAxrdS1iZWZvcmUtYmMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNuDlT",
    "lcJz8Gn6CvlMx96wr+/PrHw2Ppd2eWwpeBR+3maso/+vWlkyCczbIc7Xo+pwZmmZ",
    "/eV+4n/DwjTqRvFSoyMwITAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB",
    "/zAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// A version 3 certificate starts its body with this, and a version 1 certificate leaves it out.
const VERSION_3 = Buffer.from("a003020102", "hex");
// The basicConstraints and Key Usage identifiers, as they are written in a certificate.
const BASIC_CONSTRAINTS_ID = Buffer.from("0603551d13", "hex");
const KEY_USAGE_ID = Buffer.from("0603551d0f", "hex");

/**
 * The DER length of a content, which every extension list in this file keeps under 128 bytes.
 * @param {Buffer} content
 */
function derLength(content) {
    assert.ok(content.length < 128, "the helper writes lengths of one byte");
    return Buffer.from([content.length]);
}

/**
 * Asserts that a certificate carries exactly these extensions, in this order, by finding the
 * bytes of its extensions field, `[3] { SEQUENCE { extension... } }`, in the certificate. With no
 * extension named, it asserts that the certificate holds neither basicConstraints nor Key Usage.
 *
 * This is how a test knows its material is the case it is named for. Node.js has no accessor for
 * either extension, and `ca` is false for several different certificates, so a test that read
 * only Node.js could pass while testing another case.
 * @param {string} pem
 * @param {(keyof typeof EXTENSIONS)[]} names
 */
function carries(pem, names) {
    const raw = new X509Certificate(pem).raw;
    if (names.length === 0) {
        assert.ok(!raw.includes(BASIC_CONSTRAINTS_ID), "the certificate holds basicConstraints");
        assert.ok(!raw.includes(KEY_USAGE_ID), "the certificate holds a Key Usage");
        return;
    }
    const body = Buffer.from(names.map((name) => EXTENSIONS[name]).join(""), "hex");
    const sequence = Buffer.concat([Buffer.from([0x30]), derLength(body), body]);
    const field = Buffer.concat([Buffer.from([0xa3]), derLength(sequence), sequence]);
    assert.ok(raw.includes(field), `the certificate does not carry exactly ${names.join(", ")}`);
}

/** @param {string} pem */
function isVersion1(pem) {
    return !new X509Certificate(pem).raw.includes(VERSION_3);
}

/**
 * The observation of a material of one certificate, which must validate.
 * @param {string | Buffer} material
 */
function observe(material) {
    const observation = inspect(material, { at: AT });
    assert.deepEqual(errorsOf(observation), []);
    return observation;
}

/** @param {string | Buffer} material */
function only(material) {
    return observe(material).certificates[0];
}

test("kind pins the three cases that separate the rules: CA:TRUE alone is ca, CA:TRUE with keyCertSign is ca, CA:TRUE with digitalSignature only is end-entity", async (t) => {
    await t.test("CA:TRUE with no Key Usage extension is ca", () => {
        carries(CA_ALONE, ["basicConstraintsCa"]);
        assert.equal(only(CA_ALONE).kind, "ca");
    });

    await t.test("CA:TRUE with Key Usage keyCertSign is ca", () => {
        carries(CA_CERTSIGN, ["basicConstraintsCa", "keyUsageCertSign"]);
        assert.equal(only(CA_CERTSIGN).kind, "ca");
    });

    await t.test("CA:TRUE with Key Usage digitalSignature only is end-entity", () => {
        carries(CA_DIGITALSIGNATURE, ["basicConstraintsCa", "keyUsageDigitalSignature"]);
        assert.equal(only(CA_DIGITALSIGNATURE).kind, "end-entity");
    });
});

// A certificate marked CA:TRUE that reads as end-entity looks like a bug. It is not: when a Key
// Usage extension is present, keyCertSign is the bit that allows the key to sign certificates, and a
// certificate whose Key Usage lacks it cannot be a CA. OpenSSL and Java apply the same rule, and
// Node.js reports `ca` from OpenSSL, so `kind` follows it. Whether one certificate issued another
// is a different question, answered by name and signature, so `issuedBy` does not depend on `kind`.
test("CA:TRUE without keyCertSign reads as end-entity, and that is not a bug: keyCertSign is the bit that allows a key to sign certificates", () => {
    carries(CA_DIGITALSIGNATURE, ["basicConstraintsCa", "keyUsageDigitalSignature"]);
    const unsigning = new X509Certificate(CA_DIGITALSIGNATURE);
    assert.equal(unsigning.ca, false);
    // checkIssued() is OpenSSL's check that a certificate may issue another one. Here the name
    // is the certificate's own, so only the key's permission to sign decides.
    assert.equal(unsigning.checkIssued(unsigning), false);
    assert.equal(only(CA_DIGITALSIGNATURE).kind, "end-entity");

    // The same certificate with keyCertSign is the other side of the rule.
    carries(CA_CERTSIGN, ["basicConstraintsCa", "keyUsageCertSign"]);
    const signing = new X509Certificate(CA_CERTSIGN);
    assert.equal(signing.ca, true);
    assert.equal(signing.checkIssued(signing), true);
    assert.equal(only(CA_CERTSIGN).kind, "ca");
});

test("kind of every fixture is ca when its extensions have CA:TRUE and, if they have a keyUsage, it includes keyCertSign, and end-entity otherwise", async (t) => {
    const names = readdirSync(fixturesUrl)
        .filter((name) => name.endsWith(".pem") && !name.startsWith("bundle-"))
        .sort();
    assert.ok(names.length >= 25, `expected the single-certificate fixtures, found ${names.length}`);
    for (const name of names) {
        await t.test(name, () => {
            const extensions = readFileSync(new URL(name.replace(/\.pem$/, ".ext"), fixturesUrl), "utf8");
            const keyUsage = extensions.match(/^keyUsage\s*=(.*)$/m);
            const isCa = /CA:TRUE/.test(extensions) && (keyUsage === null || /keyCertSign/.test(keyUsage[1]));
            assert.equal(only(readFileSync(new URL(name, fixturesUrl))).kind, isCa ? "ca" : "end-entity");
        });
    }
});

test("the check of the extensions fails for a certificate that carries others, so a case cannot be tested with the wrong material", async (t) => {
    await t.test("CA:TRUE alone is not CA:TRUE with keyCertSign, although Node.js reads both as ca", () => {
        assert.equal(new X509Certificate(CA_ALONE).ca, new X509Certificate(CA_CERTSIGN).ca);
        assert.throws(() => carries(CA_ALONE, ["basicConstraintsCa", "keyUsageCertSign"]), assert.AssertionError);
        assert.throws(() => carries(CA_CERTSIGN, ["basicConstraintsCa"]), assert.AssertionError);
    });

    await t.test("CA:TRUE with digitalSignature is not keyCertSign without basicConstraints, although Node.js reads both as not a CA", () => {
        assert.equal(new X509Certificate(CA_DIGITALSIGNATURE).ca, new X509Certificate(CERTSIGN_WITHOUT_BASIC_CONSTRAINTS).ca);
        assert.throws(() => carries(CA_DIGITALSIGNATURE, ["keyUsageCertSign"]), assert.AssertionError);
        assert.throws(() => carries(CERTSIGN_WITHOUT_BASIC_CONSTRAINTS, ["basicConstraintsCa", "keyUsageDigitalSignature"]), assert.AssertionError);
    });

    await t.test("a certificate with extensions is not one with none, and the other way round", () => {
        assert.throws(() => carries(CA_ALONE, []), assert.AssertionError);
        assert.throws(() => carries(V1_ROOT, ["basicConstraintsCa"]), assert.AssertionError);
        carries(V1_ROOT, []);
    });

    await t.test("a version 1 certificate is told from a version 3 one", () => {
        assert.equal(isVersion1(V1_ROOT), true);
        assert.equal(isVersion1(V1_WITH_CA), true);
        assert.equal(isVersion1(CA_ALONE), false);
    });
});

test("a Key Usage with keyCertSign and no basicConstraints is end-entity: the bit alone does not make a CA", () => {
    carries(CERTSIGN_WITHOUT_BASIC_CONSTRAINTS, ["keyUsageCertSign"]);
    assert.equal(only(CERTSIGN_WITHOUT_BASIC_CONSTRAINTS).kind, "end-entity");
});

test("a Key Usage that is present with no bit set decides, so CA:TRUE next to it is end-entity", () => {
    carries(CA_KEY_USAGE_WITHOUT_BITS, ["basicConstraintsCa", "keyUsageWithoutBits"]);
    assert.equal(only(CA_KEY_USAGE_WITHOUT_BITS).kind, "end-entity");
});

test("a basicConstraints that is not critical still marks a CA", () => {
    carries(CA_NOT_CRITICAL, ["basicConstraintsCaNotCritical"]);
    assert.equal(only(CA_NOT_CRITICAL).kind, "ca");
});

test("an extension nothing defines does not change kind, whether it is critical or repeated: CA:TRUE stays ca", async (t) => {
    await t.test("critical", () => {
        carries(UNKNOWN_CRITICAL, ["basicConstraintsCa", "unknownCritical"]);
        assert.equal(only(UNKNOWN_CRITICAL).kind, "ca");
    });

    await t.test("twice", () => {
        carries(UNKNOWN_TWICE, ["basicConstraintsCa", "unknown", "unknown"]);
        assert.equal(only(UNKNOWN_TWICE).kind, "ca");
    });
});

test("a Netscape certificate type that says sslCA, with no basicConstraints, is end-entity", () => {
    carries(NETSCAPE_CA, ["netscapeSslCa"]);
    assert.equal(only(NETSCAPE_CA).kind, "end-entity");
});

// An old root is version 1, which has no extensions: nothing marks it as a CA, so it is end-entity,
// while the signature check still sees that it signed itself.
test("a self-signed version 1 certificate is end-entity and still selfSigned", () => {
    assert.equal(isVersion1(V1_ROOT), true);
    carries(V1_ROOT, []);
    const node = new X509Certificate(V1_ROOT);
    assert.equal(node.verify(node.publicKey), true);
    assert.equal(node.ca, false);

    const certificate = only(V1_ROOT);
    assert.equal(certificate.kind, "end-entity");
    assert.equal(certificate.selfSigned, true);
    assert.deepEqual(certificate.issuedBy, [0]);
});

test("a version 1 certificate that carries basicConstraints CA:TRUE is ca, whatever the version says", () => {
    assert.equal(isVersion1(V1_WITH_CA), true);
    carries(V1_WITH_CA, ["basicConstraintsCa"]);
    assert.equal(only(V1_WITH_CA).kind, "ca");
});

// What `kind` says is Node.js's `ca`, which is false for a CA that carries a known extension twice
// or one that does not decode. The observation says so with a KIND_UNRELIABLE warning and `kind`
// keeps the value Node.js gives, so these certificates still read as end-entity. What it does not
// say is what else was lost: the fields built from the broken extension are simply missing, and
// that is how the code behaves today, not a rule.
test("a CA whose basicConstraints appears twice reads as end-entity, and KIND_UNRELIABLE says kind cannot be trusted", () => {
    carries(BASIC_CONSTRAINTS_TWICE, ["basicConstraintsCa", "basicConstraintsCa"]);
    assert.equal(new X509Certificate(BASIC_CONSTRAINTS_TWICE).ca, false);
    const observation = observe(BASIC_CONSTRAINTS_TWICE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.warnings, [
        { code: "KIND_UNRELIABLE", certificate: 0, message: "kind cannot be trusted: basicConstraints appears more than once" },
    ]);
});

test("a CA whose basicConstraints does not decode reads as end-entity, and KIND_UNRELIABLE says kind cannot be trusted", () => {
    carries(BASIC_CONSTRAINTS_UNDECODABLE, ["basicConstraintsUndecodable"]);
    const observation = observe(BASIC_CONSTRAINTS_UNDECODABLE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.warnings, [
        { code: "KIND_UNRELIABLE", certificate: 0, message: "kind cannot be trusted: basicConstraints does not decode" },
    ]);
});

test("a CA whose subjectAltName appears twice reads as end-entity with KIND_UNRELIABLE, and today san keeps only the first name", () => {
    carries(SAN_TWICE, ["basicConstraintsCa", "subjectAltName", "subjectAltName"]);
    assert.equal(new X509Certificate(SAN_TWICE).ca, false);
    const observation = observe(SAN_TWICE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.certificates[0].san, { dns: ["a.example"], ip: [], email: [], uri: [] });
    assert.deepEqual(observation.warnings.map(({ code, certificate }) => [code, certificate]), [["KIND_UNRELIABLE", 0]]);
});

test("a CA whose subjectAltName does not decode reads as end-entity with KIND_UNRELIABLE, and today san is empty", () => {
    carries(SAN_UNDECODABLE, ["basicConstraintsCa", "subjectAltNameUndecodable"]);
    assert.equal(new X509Certificate(SAN_UNDECODABLE).ca, false);
    const observation = observe(SAN_UNDECODABLE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.certificates[0].san, { dns: [], ip: [], email: [], uri: [] });
    assert.deepEqual(observation.warnings.map(({ code, certificate }) => [code, certificate]), [["KIND_UNRELIABLE", 0]]);
});

/**
 * What `inspect()` says about the kind of the one certificate of a material.
 * @param {string | Buffer} material
 */
function kindWarnings(material) {
    return observe(material).warnings.filter(({ code }) => code === "KIND_UNRELIABLE");
}

/** @param {string} pem */
function rawOf(pem) {
    return new X509Certificate(pem).raw;
}

// Each certificate below is a case of the rule: what basicConstraints and Key Usage say, which
// Node.js reads the same way. Called with the opposite of what Node.js reports, the reader gives
// the answer its own reading of the extensions makes, so that answer is tested without Node.js.
test("the reader works out a CA by the rule kind states, so told the opposite of what Node.js reports it warns with its own answer", async (t) => {
    /** @type {[string, string, (keyof typeof EXTENSIONS)[], boolean][]} */
    const cases = [
        ["CA:TRUE alone", CA_ALONE, ["basicConstraintsCa"], true],
        ["CA:TRUE not critical", CA_NOT_CRITICAL, ["basicConstraintsCaNotCritical"], true],
        ["CA:TRUE with keyCertSign", CA_CERTSIGN, ["basicConstraintsCa", "keyUsageCertSign"], true],
        ["CA:TRUE with pathlen 0 and keyCertSign", CA_PATH_LENGTH_0, ["basicConstraintsCaPathLength0", "keyUsageCertSign"], true],
        ["CA:TRUE with its length in the long form", BASIC_CONSTRAINTS_LONG_LENGTH, ["basicConstraintsCaLongLength"], true],
        ["CA:TRUE with digitalSignature only", CA_DIGITALSIGNATURE, ["basicConstraintsCa", "keyUsageDigitalSignature"], false],
        ["CA:FALSE", CA_FALSE, ["basicConstraintsNotCa", "keyUsageDigitalSignature"], false],
        ["keyCertSign and no basicConstraints", CERTSIGN_WITHOUT_BASIC_CONSTRAINTS, ["keyUsageCertSign"], false],
        ["a path length and no cA", BASIC_CONSTRAINTS_PATH_LENGTH_WITHOUT_CA, ["basicConstraintsPathLengthWithoutCa"], false],
        ["a Netscape certificate type and nothing else", NETSCAPE_CA, ["netscapeSslCa"], false],
        ["no extensions at all", VERSION_3_WITHOUT_EXTENSIONS, [], false],
    ];
    for (const [name, pem, extensions, isCa] of cases) {
        await t.test(name, () => {
            carries(pem, extensions);
            const raw = rawOf(pem);
            assert.equal(new X509Certificate(pem).ca, isCa, "Node.js reads the case differently from the rule");
            assert.equal(kindWarning(raw, isCa, 0), null);
            assert.equal(
                kindWarning(raw, !isCa, 0)?.message,
                `kind cannot be trusted: Node.js reads the certificate as ${isCa ? "end-entity" : "ca"}, and its basicConstraints and Key Usage make it ${isCa ? "a CA" : "not a CA"}`,
            );
        });
    }

    await t.test("a version 1 certificate with basicConstraints CA:TRUE is a CA and one with no extensions is not", () => {
        assert.equal(kindWarning(rawOf(V1_WITH_CA), true, 0), null);
        assert.match(kindWarning(rawOf(V1_WITH_CA), false, 0)?.message ?? "", /make it a CA$/);
        assert.equal(kindWarning(rawOf(V1_ROOT), false, 0), null);
        assert.match(kindWarning(rawOf(V1_ROOT), true, 0)?.message ?? "", /make it not a CA$/);
    });
});

test("the reader of basicConstraints and Key Usage imports nothing, exports only kindWarning and is used only by inspect", () => {
    assert.deepEqual(Object.keys(kindWarningModule), ["kindWarning"]);
    const source = readFileSync(new URL("../src/kind-warning.js", import.meta.url), "utf8");
    assert.doesNotMatch(source, /^\s*import\b|\bimport\s*\(|\brequire\s*\(|\bfrom\s*["']/m);
    // Reading another field with it would start a parser. The only file that may use it is the one
    // that compares its answer with Node.js's.
    const users = readdirSync(new URL("../src/", import.meta.url), { recursive: true, encoding: "utf8" })
        .filter((path) => path.endsWith(".js") && path !== "kind-warning.js")
        .filter((path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8").includes("kind-warning.js"));
    assert.deepEqual(users, ["inspect.js"]);
});

test("KIND_UNRELIABLE comes once per certificate, says which of the three it is, quotes nothing from the certificate and leaves kind as Node.js reads it", async (t) => {
    await t.test("an extension that appears more than once names it, or both", () => {
        const cases = [
            [BASIC_CONSTRAINTS_TWICE, "basicConstraints appears more than once"],
            [KEY_USAGE_TWICE, "Key Usage appears more than once"],
            [BASIC_CONSTRAINTS_KEY_USAGE_BASIC_CONSTRAINTS, "basicConstraints appears more than once"],
            [BASIC_CONSTRAINTS_AND_KEY_USAGE_TWICE, "basicConstraints and Key Usage appear more than once"],
        ];
        for (const [pem, why] of cases) {
            assert.deepEqual(kindWarnings(pem).map(({ message }) => message), [`kind cannot be trusted: ${why}`]);
            assert.equal(only(pem).kind, "end-entity");
        }
    });

    await t.test("an extension that does not decode names it", () => {
        assert.deepEqual(kindWarnings(BASIC_CONSTRAINTS_UNDECODABLE).map(({ message }) => message), ["kind cannot be trusted: basicConstraints does not decode"]);
        assert.deepEqual(kindWarnings(CA_KEY_USAGE_WITHOUT_BITS).map(({ message }) => message), ["kind cannot be trusted: Key Usage does not decode"]);
        assert.deepEqual(kindWarnings(KEY_USAGE_UNUSED_BITS_OUT_OF_RANGE).map(({ message }) => message), ["kind cannot be trusted: Key Usage does not decode"]);
    });

    await t.test("a certificate the rule and Node.js read differently says what each of them reads", () => {
        assert.deepEqual(kindWarnings(BASIC_CONSTRAINTS_NEGATIVE_PATH_LENGTH).map(({ message }) => message), [
            "kind cannot be trusted: Node.js reads the certificate as end-entity, and its basicConstraints and Key Usage make it a CA",
        ]);
        assert.equal(only(BASIC_CONSTRAINTS_NEGATIVE_PATH_LENGTH).kind, "end-entity");
    });

    await t.test("the message is the same for another certificate in the same case, so it holds nothing of the certificate", () => {
        const [first] = kindWarnings(BASIC_CONSTRAINTS_TWICE);
        const [second] = kindWarnings(BASIC_CONSTRAINTS_KEY_USAGE_BASIC_CONSTRAINTS);
        assert.equal(first.message, second.message);
        for (const pem of [BASIC_CONSTRAINTS_TWICE, SAN_TWICE, EKU_TWICE]) {
            const { certificates, warnings } = observe(pem);
            const [{ subject, serial, sha256 }] = certificates;
            for (const { message } of warnings) {
                assert.ok(!message.includes(subject.cn ?? "\0") && !message.includes(serial) && !message.includes(sha256.slice(0, 8)), message);
            }
        }
    });

    await t.test("a certificate that would give several reasons gets one warning, and each certificate of a material gets its own", () => {
        // Both extensions repeated, and the other certificate repeats basicConstraints.
        assert.equal(kindWarnings(BASIC_CONSTRAINTS_AND_KEY_USAGE_TWICE).length, 1);
        const observation = inspect(BASIC_CONSTRAINTS_TWICE + SAN_TWICE, { at: AT, select: sha256Of(SAN_TWICE).slice(0, 8) });
        assert.deepEqual(observation.warnings.map(({ code, certificate }) => [code, certificate]), [["KIND_UNRELIABLE", 0], ["KIND_UNRELIABLE", 1]]);
    });

    await t.test("kind is what Node.js reads, in every case that warns", () => {
        const warned = [BASIC_CONSTRAINTS_TWICE, KEY_USAGE_TWICE, BASIC_CONSTRAINTS_UNDECODABLE, BASIC_CONSTRAINTS_NEGATIVE_PATH_LENGTH, SAN_TWICE, EKU_TWICE, SKI_TWICE, BASIC_CONSTRAINTS_TRAILING_BYTES, INDEFINITE_LENGTH];
        for (const pem of warned) {
            assert.equal(kindWarnings(pem).length, 1);
            assert.equal(only(pem).kind, new X509Certificate(pem).ca ? "ca" : "end-entity");
        }
    });
});

/** @param {string} pem */
function sha256Of(pem) {
    return observe(pem).certificates[0].sha256;
}

// The comparison with Node.js is what finds a broken extension the reader does not read, so the
// warning needs no list of them and stops by itself if Node.js stops reading them as end-entity.
test("the comparison alone finds a broken extension the reader does not read, so the warning stops if Node.js reads the certificate as a CA", async (t) => {
    const messages = new Set();
    for (const [name, pem, extensions] of /** @type {[string, string, (keyof typeof EXTENSIONS)[]][]} */ ([
        ["subjectAltName twice", SAN_TWICE, ["basicConstraintsCa", "subjectAltName", "subjectAltName"]],
        ["subjectAltName that does not decode", SAN_UNDECODABLE, ["basicConstraintsCa", "subjectAltNameUndecodable"]],
        ["Extended Key Usage twice", EKU_TWICE, ["basicConstraintsCa", "extendedKeyUsage", "extendedKeyUsage"]],
        ["Extended Key Usage that does not decode", EKU_UNDECODABLE, ["basicConstraintsCa", "extendedKeyUsageUndecodable"]],
        ["subjectKeyIdentifier twice", SKI_TWICE, ["basicConstraintsCa", "subjectKeyIdentifier", "subjectKeyIdentifier"]],
        ["subjectKeyIdentifier that does not decode", SKI_UNDECODABLE, ["basicConstraintsCa", "subjectKeyIdentifierUndecodable"]],
    ])) {
        await t.test(name, () => {
            carries(pem, extensions);
            assert.equal(new X509Certificate(pem).ca, false);
            const [warning] = kindWarnings(pem);
            messages.add(warning.message);
            // Were Node.js to read the same bytes as a CA, nothing would be left to warn about.
            assert.equal(kindWarning(rawOf(pem), true, 0), null);
        });
    }
    assert.equal(messages.size, 1, "the reason is the disagreement, not the extension that caused it");
});

test("these do not warn: kind is right, whether it is ca or end-entity", async (t) => {
    /** @type {[string, string, (keyof typeof EXTENSIONS)[], string][]} */
    const cases = [
        ["a CA whose Key Usage lacks keyCertSign, which reads end-entity on purpose", CA_DIGITALSIGNATURE, ["basicConstraintsCa", "keyUsageDigitalSignature"], "end-entity"],
        ["CA:FALSE", CA_FALSE, ["basicConstraintsNotCa", "keyUsageDigitalSignature"], "end-entity"],
        ["a CA with path length 0", CA_PATH_LENGTH_0, ["basicConstraintsCaPathLength0", "keyUsageCertSign"], "ca"],
        ["keyCertSign and no basicConstraints", CERTSIGN_WITHOUT_BASIC_CONSTRAINTS, ["keyUsageCertSign"], "end-entity"],
        ["an unknown critical extension", UNKNOWN_CRITICAL, ["basicConstraintsCa", "unknownCritical"], "ca"],
        ["an unknown extension repeated", UNKNOWN_TWICE, ["basicConstraintsCa", "unknown", "unknown"], "ca"],
        ["a Netscape certificate type and nothing else", NETSCAPE_CA, ["netscapeSslCa"], "end-entity"],
        ["CA:TRUE alone", CA_ALONE, ["basicConstraintsCa"], "ca"],
        ["CA:TRUE with keyCertSign", CA_CERTSIGN, ["basicConstraintsCa", "keyUsageCertSign"], "ca"],
        ["CA:TRUE that is not critical", CA_NOT_CRITICAL, ["basicConstraintsCaNotCritical"], "ca"],
        ["a basicConstraints with a path length and no cA", BASIC_CONSTRAINTS_PATH_LENGTH_WITHOUT_CA, ["basicConstraintsPathLengthWithoutCa"], "end-entity"],
        ["a basicConstraints whose sequence has its length in the long form", BASIC_CONSTRAINTS_LONG_LENGTH, ["basicConstraintsCaLongLength"], "ca"],
        ["a version 1 certificate with basicConstraints CA:TRUE", V1_WITH_CA, ["basicConstraintsCa"], "ca"],
    ];
    for (const [name, pem, extensions, kind] of cases) {
        await t.test(name, () => {
            carries(pem, extensions);
            const observation = observe(pem);
            assert.equal(observation.certificates[0].kind, kind);
            assert.deepEqual(observation.warnings, []);
        });
    }

    await t.test("a certificate with no extensions", () => {
        carries(VERSION_3_WITHOUT_EXTENSIONS, []);
        assert.equal(isVersion1(VERSION_3_WITHOUT_EXTENSIONS), false);
        assert.deepEqual(observe(VERSION_3_WITHOUT_EXTENSIONS).warnings, []);
        assert.equal(only(VERSION_3_WITHOUT_EXTENSIONS).kind, "end-entity");
    });

    await t.test("a version 1 certificate, which has no place for extensions", () => {
        carries(V1_ROOT, []);
        assert.equal(isVersion1(V1_ROOT), true);
        assert.deepEqual(observe(V1_ROOT).warnings, []);
    });

    await t.test("an extensions field that is present and empty", () => {
        assert.ok(rawOf(EMPTY_EXTENSIONS).includes(Buffer.from("a3023000", "hex")), "the extensions field is not the empty one");
        assert.equal(new X509Certificate(EMPTY_EXTENSIONS).ca, false);
        assert.deepEqual(observe(EMPTY_EXTENSIONS).warnings, []);
        assert.equal(only(EMPTY_EXTENSIONS).kind, "end-entity");
    });
});

test("these warn, and kind keeps the value Node.js gives: end-entity for a CA that Node.js could not read", async (t) => {
    /** @type {[string, string, (keyof typeof EXTENSIONS)[]][]} */
    const cases = [
        ["basicConstraints twice", BASIC_CONSTRAINTS_TWICE, ["basicConstraintsCa", "basicConstraintsCa"]],
        ["Key Usage twice", KEY_USAGE_TWICE, ["basicConstraintsCa", "keyUsageCertSign", "keyUsageCertSign"]],
        ["basicConstraints, Key Usage and basicConstraints again", BASIC_CONSTRAINTS_KEY_USAGE_BASIC_CONSTRAINTS, ["basicConstraintsCa", "keyUsageCertSign", "basicConstraintsCa"]],
        ["a basicConstraints that does not decode", BASIC_CONSTRAINTS_UNDECODABLE, ["basicConstraintsUndecodable"]],
        ["a Key Usage with no bit", CA_KEY_USAGE_WITHOUT_BITS, ["basicConstraintsCa", "keyUsageWithoutBits"]],
        ["a basicConstraints with a negative path length", BASIC_CONSTRAINTS_NEGATIVE_PATH_LENGTH, ["basicConstraintsNegativePathLength"]],
        ["a CA whose subjectAltName is repeated", SAN_TWICE, ["basicConstraintsCa", "subjectAltName", "subjectAltName"]],
        ["a CA whose subjectAltName does not decode", SAN_UNDECODABLE, ["basicConstraintsCa", "subjectAltNameUndecodable"]],
        ["a CA whose Extended Key Usage is repeated", EKU_TWICE, ["basicConstraintsCa", "extendedKeyUsage", "extendedKeyUsage"]],
        ["a CA whose Extended Key Usage does not decode", EKU_UNDECODABLE, ["basicConstraintsCa", "extendedKeyUsageUndecodable"]],
        ["a CA whose subjectKeyIdentifier is repeated", SKI_TWICE, ["basicConstraintsCa", "subjectKeyIdentifier", "subjectKeyIdentifier"]],
        ["a CA whose subjectKeyIdentifier does not decode", SKI_UNDECODABLE, ["basicConstraintsCa", "subjectKeyIdentifierUndecodable"]],
    ];
    for (const [name, pem, extensions] of cases) {
        await t.test(name, () => {
            carries(pem, extensions);
            assert.equal(new X509Certificate(pem).ca, false);
            const observation = observe(pem);
            assert.equal(observation.certificates[0].kind, "end-entity");
            assert.deepEqual(observation.warnings.map(({ code, certificate }) => [code, certificate]), [["KIND_UNRELIABLE", 0]]);
        });
    }
});

// Bytes Node.js accepts that are not what a certificate should hold. The reader warns where it
// cannot be sure of what it reads, and it does not where the bytes have one reading.
test("a basicConstraints whose bytes are not what the rule reads warns, whatever Node.js makes of them", async (t) => {
    await t.test("bytes after the sequence: Node.js reads a CA and the reader does not decode it", () => {
        carries(BASIC_CONSTRAINTS_TRAILING_BYTES, ["basicConstraintsCaTrailingBytes"]);
        assert.equal(new X509Certificate(BASIC_CONSTRAINTS_TRAILING_BYTES).ca, true);
        assert.deepEqual(kindWarnings(BASIC_CONSTRAINTS_TRAILING_BYTES).map(({ message }) => message), ["kind cannot be trusted: basicConstraints does not decode"]);
        assert.equal(only(BASIC_CONSTRAINTS_TRAILING_BYTES).kind, "ca");
    });

    await t.test("the path length before cA: it does not decode", () => {
        carries(BASIC_CONSTRAINTS_FIELDS_OUT_OF_ORDER, ["basicConstraintsPathLengthFirst"]);
        assert.equal(new X509Certificate(BASIC_CONSTRAINTS_FIELDS_OUT_OF_ORDER).ca, false);
        assert.deepEqual(kindWarnings(BASIC_CONSTRAINTS_FIELDS_OUT_OF_ORDER).map(({ message }) => message), ["kind cannot be trusted: basicConstraints does not decode"]);
    });

    await t.test("an unused-bits octet above 7 in Key Usage: it does not decode", () => {
        carries(KEY_USAGE_UNUSED_BITS_OUT_OF_RANGE, ["basicConstraintsCa", "keyUsageUnusedBitsOutOfRange"]);
        assert.equal(new X509Certificate(KEY_USAGE_UNUSED_BITS_OUT_OF_RANGE).ca, false);
        assert.deepEqual(kindWarnings(KEY_USAGE_UNUSED_BITS_OUT_OF_RANGE).map(({ message }) => message), ["kind cannot be trusted: Key Usage does not decode"]);
    });
});

// Node.js re-encodes the outer structure of a certificate, so a BER length there changes `raw` and
// the material is refused. An indefinite length inside the body does not change it: `raw` is the
// input, Node.js reads the CA, and the reader, which accepts definite lengths only, cannot walk it.
test("an indefinite length in the extensions is read by Node.js as a CA and cannot be walked, so it warns that the extensions could not be read", () => {
    const raw = rawOf(INDEFINITE_LENGTH);
    assert.ok(raw.includes(Buffer.from(`a3803011${EXTENSIONS.basicConstraintsCa}0000`, "hex")), "the extensions field is not the indefinite one");
    assert.equal(new X509Certificate(INDEFINITE_LENGTH).ca, true);
    const observation = observe(INDEFINITE_LENGTH);
    assert.equal(observation.certificates[0].kind, "ca");
    assert.deepEqual(observation.warnings, [
        { code: "KIND_UNRELIABLE", certificate: 0, message: "kind cannot be trusted: the certificate's extensions could not be read to check it" },
    ]);
});

test("no certificate in test/fixtures/ gets KIND_UNRELIABLE", () => {
    const names = readdirSync(fixturesUrl).filter((name) => /\.(pem|der)$/.test(name)).sort();
    let count = 0;
    let cas = 0;
    for (const name of names) {
        for (const { certificate, block } of certificatesIn(readFileSync(new URL(name, fixturesUrl)))) {
            count += 1;
            if (certificate.ca) cas += 1;
            assert.equal(kindWarning(certificate.raw, certificate.ca, 0), null, `${name}, input block ${block}`);
        }
    }
    assert.ok(count >= 25, `expected the fixtures' certificates, found ${count}`);
    assert.ok(cas > 0 && cas < count, "the fixtures must hold both CAs and end entities");
});

test("KIND_UNRELIABLE follows the duplicate and subject alternative name warnings, by certificate index", () => {
    const kinds = readFileSync(new URL("leaf-san-kinds.pem", fixturesUrl), "latin1");
    // The first certificate is repeated, the leaf is index 1 and holds two names the contract does
    // not represent, and the one that repeats basicConstraints is index 2.
    const observation = inspect(SAN_TWICE + SAN_TWICE + kinds + BASIC_CONSTRAINTS_TWICE, { at: AT, select: sha256Of(kinds).slice(0, 8) });
    assert.deepEqual(observation.warnings.map(({ code, certificate }) => [code, certificate]), [
        ["DUPLICATE_CERTIFICATE", 0],
        ["SAN_TYPE_UNREPRESENTED", 1],
        ["SAN_TYPE_UNREPRESENTED", 1],
        ["KIND_UNRELIABLE", 0],
        ["KIND_UNRELIABLE", 2],
    ]);
    assert.deepEqual(errorsOf(observation), []);
});

// The reader is handed bytes of a certificate Node.js has parsed, but it must not need that to be
// safe: it is called here on bytes made wrong in every way a byte can be, and on inputs no
// certificate is.
test("the reader never throws and never guesses: cut anywhere or with any byte changed, it gives no warning or a KIND_UNRELIABLE one", async (t) => {
    const raw = rawOf(CA_CERTSIGN);
    /** @param {Uint8Array} bytes */
    const outcome = (bytes) => {
        const results = [true, false].map((ca) => kindWarning(bytes, ca, 3));
        for (const result of results) {
            if (result === null) continue;
            assert.equal(result.code, "KIND_UNRELIABLE");
            assert.equal(result.certificate, 3);
            assert.match(result.message, /^kind cannot be trusted: [a-zA-Z ,.'-]+$/);
        }
        return results;
    };

    await t.test("every prefix of a certificate is one it cannot read", () => {
        for (let length = 0; length < raw.length; length += 1) {
            for (const result of outcome(raw.subarray(0, length))) {
                assert.equal(result?.message, "kind cannot be trusted: the certificate's extensions could not be read to check it", `${length} bytes`);
            }
        }
    });

    await t.test("every byte set to every value", () => {
        const changed = Buffer.from(raw);
        for (let position = 0; position < raw.length; position += 1) {
            for (let value = 0; value < 256; value += 1) {
                changed[position] = value;
                outcome(changed);
            }
            changed[position] = raw[position];
        }
    });

    await t.test("inputs that are not certificates", () => {
        const inputs = [
            "",
            "30",
            "3080",
            "30 80 00 00",
            "30 85 01 00 00 00 00",
            "30 84 ff ff ff ff",
            "30 03 02 01 01",
            "1f 81 00 00",
            "30 06 30 04 a3 82 ff ff",
        ].map((text) => Buffer.from(text.replaceAll(" ", ""), "hex"));
        for (const bytes of inputs) {
            for (const result of outcome(bytes)) assert.notEqual(result, null, bytes.toString("hex"));
        }
    });

    await t.test("a view of a larger buffer is read inside its own bounds", () => {
        const padded = Buffer.concat([Buffer.alloc(16, 0x30), raw, Buffer.alloc(16, 0x30)]);
        assert.equal(kindWarning(padded.subarray(16, 16 + raw.length), true, 0), null);
        assert.notEqual(kindWarning(padded.subarray(16, 16 + raw.length + 4), true, 0), null);
    });
});

// More cases of bytes that Node.js and the reader both read, and have to read the same way for the
// warning to stay silent where `kind` is right.
test("the order of the extensions does not matter: Key Usage before basicConstraints is read the same, whichever bits it holds", () => {
    carries(KEY_USAGE_BEFORE_BASIC_CONSTRAINTS, ["keyUsageCertSign", "basicConstraintsCa"]);
    assert.equal(only(KEY_USAGE_BEFORE_BASIC_CONSTRAINTS).kind, "ca");
    assert.deepEqual(observe(KEY_USAGE_BEFORE_BASIC_CONSTRAINTS).warnings, []);

    // The same certificate with the Key Usage value `03 02 02 04` (keyCertSign) replaced by `03 02 07 80` (digitalSignature).
    const raw = Buffer.from(rawOf(KEY_USAGE_BEFORE_BASIC_CONSTRAINTS));
    const at = raw.indexOf(Buffer.from("0403020204", "hex"));
    assert.notEqual(at, -1, "the Key Usage was not found");
    Buffer.from("03020780", "hex").copy(raw, at + 1);
    assert.equal(new X509Certificate(raw).ca, false);
    const observation = inspect(raw, { at: AT });
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.warnings, []);
});

test("Key Usage bits that are unused do not count: keyCertSign hidden by the unused-bits octet is not set, for Node.js and for the reader", async (t) => {
    /**
     * CA_CERTSIGN with its Key Usage value, `03 02 02 04`, replaced by another of the same length.
     * @param {string} value
     */
    const withKeyUsage = (value) => {
        const raw = Buffer.from(rawOf(CA_CERTSIGN));
        const at = raw.indexOf(Buffer.from("0403020204", "hex"));
        assert.notEqual(at, -1, "the Key Usage of CA_CERTSIGN was not found");
        Buffer.from(value, "hex").copy(raw, at + 1);
        return raw;
    };

    await t.test("two unused bits leave keyCertSign set", () => {
        const raw = withKeyUsage("03020204");
        assert.equal(new X509Certificate(raw).ca, true);
        assert.equal(kindWarning(raw, true, 0), null);
    });

    await t.test("three unused bits clear it: the same octet reads as no bit set", () => {
        const raw = withKeyUsage("03020304");
        assert.equal(new X509Certificate(raw).ca, false);
        assert.equal(kindWarning(raw, false, 0), null);
        assert.equal(inspect(raw, { at: AT }).certificates[0].kind, "end-entity");
        assert.deepEqual(inspect(raw, { at: AT }).warnings, []);
    });

    await t.test("eight zero bits are a Key Usage that is present and decides, not one that does not decode", () => {
        const raw = withKeyUsage("03020000");
        assert.equal(new X509Certificate(raw).ca, false);
        assert.deepEqual(inspect(raw, { at: AT }).warnings, []);
    });
});

// The reader trusts a length only as far as the element that holds it goes. These certificates
// differ from CA_ALONE in one length, so that every other length still adds up and only the
// element holding the changed one can tell.
test("a length that runs past the element holding it, or stops short of it, is never read", async (t) => {
    const raw = rawOf(CA_ALONE);
    // The extensions field of CA_ALONE is `a3 13 30 11 30 0f <oid> <critical> 04 05 30 03 01 01 ff`.
    const field = raw.indexOf(Buffer.from("a3133011300f0603551d13", "hex"));
    assert.notEqual(field, -1, "the extensions field of CA_ALONE was not found");
    const lengths = {
        "the extensions field": field + 1,
        "the sequence of extensions": field + 3,
        "the extension": field + 5,
        // Counting from `a3`: the extension starts at 4, its identifier is at 6 to 10, its critical flag at 11 to 13, and the tag of its value is at 14.
        "the value of the extension": field + 15,
    };
    for (const [name, at] of Object.entries(lengths)) {
        for (const change of [1, -1]) {
            await t.test(`${name} ${change > 0 ? "one byte too long" : "one byte too short"}`, () => {
                const changed = Buffer.from(raw);
                changed[at] += change;
                for (const ca of [true, false]) {
                    assert.equal(kindWarning(changed, ca, 0)?.message, "kind cannot be trusted: the certificate's extensions could not be read to check it");
                }
            });
        }
    }
    assert.equal(kindWarning(raw, true, 0), null, "the unchanged certificate must read");
});

// A length byte of 0x80 is the indefinite length. Read as zero, the element would be empty and the
// elements it holds would become its siblings, so an indefinite length on the body of the
// certificate would read as a certificate with no extensions: no warning, and a wrong kind.
test("an indefinite length is never read as an empty element: on the body of the certificate it would read as no extensions", () => {
    const raw = rawOf(CA_ALONE);
    // `30 81 ec` (the certificate) and `30 81 d2` (its body) come first, and the body is d2 bytes.
    assert.deepEqual([...raw.subarray(0, 6)], [0x30, 0x81, 0xec, 0x30, 0x81, 0xd2]);
    const body = raw.subarray(6, 6 + 0xd2);
    const rest = raw.subarray(6 + 0xd2);
    const inner = Buffer.concat([Buffer.from("3080", "hex"), body, Buffer.from("0000", "hex"), rest]);
    const indefinite = Buffer.concat([Buffer.from([0x30, 0x81, inner.length]), inner]);
    for (const ca of [true, false]) {
        assert.equal(kindWarning(indefinite, ca, 0)?.message, "kind cannot be trusted: the certificate's extensions could not be read to check it");
    }
});
