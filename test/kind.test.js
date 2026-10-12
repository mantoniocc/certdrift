import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect } from "../src/index.js";
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
 * certificate leaves out the `version` line, and one with no extensions leaves out `exts`.
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

// What follows is what the code does today, not a rule the schema states. For a certificate that
// repeats an extension OpenSSL knows, or holds one it cannot decode, Node.js reports `ca` false
// whatever basicConstraints says, so `kind` is end-entity. The observation says nothing about it:
// no warning is emitted, and the extension that could not be read is simply missing from the fields
// built from it. A decision to report or to read these certificates differently changes these
// tests, and a change in Node.js or OpenSSL that does it by itself is noticed here.
test("today a CA whose basicConstraints appears twice reads as end-entity", () => {
    carries(BASIC_CONSTRAINTS_TWICE, ["basicConstraintsCa", "basicConstraintsCa"]);
    assert.equal(new X509Certificate(BASIC_CONSTRAINTS_TWICE).ca, false);
    const observation = observe(BASIC_CONSTRAINTS_TWICE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.warnings, []);
});

test("today a CA whose basicConstraints does not decode reads as end-entity with no warning", () => {
    carries(BASIC_CONSTRAINTS_UNDECODABLE, ["basicConstraintsUndecodable"]);
    const observation = observe(BASIC_CONSTRAINTS_UNDECODABLE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.warnings, []);
});

test("today a CA whose subjectAltName appears twice reads as end-entity, with the first name kept and no warning", () => {
    carries(SAN_TWICE, ["basicConstraintsCa", "subjectAltName", "subjectAltName"]);
    assert.equal(new X509Certificate(SAN_TWICE).ca, false);
    const observation = observe(SAN_TWICE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.certificates[0].san, { dns: ["a.example"], ip: [], email: [], uri: [] });
    assert.deepEqual(observation.warnings, []);
});

test("today a CA whose subjectAltName does not decode reads as end-entity with no SAN and no warning", () => {
    carries(SAN_UNDECODABLE, ["basicConstraintsCa", "subjectAltNameUndecodable"]);
    assert.equal(new X509Certificate(SAN_UNDECODABLE).ca, false);
    const observation = observe(SAN_UNDECODABLE);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.certificates[0].san, { dns: [], ip: [], email: [], uri: [] });
    assert.deepEqual(observation.warnings, []);
});
