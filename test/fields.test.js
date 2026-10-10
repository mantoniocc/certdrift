import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate, generateKeyPairSync } from "node:crypto";
import { inspect, ParseError } from "../src/index.js";
import { derivedOf } from "../src/derived.js";
import { validityDate } from "../src/dates.js";
import { distinguishedName } from "../src/names.js";
import { extendedKeyUsage } from "../src/usage.js";
import { publicKeyOf } from "../src/key.js";
import { validatorFor } from "./helpers/schema.js";

// The normalized fields of one certificate: names, dates, serial, usages and key. Nothing here
// may depend on a fixture's exact bytes, because `npm run fixtures` replaces them, so every
// expectation comes from the scenario that generates the fixture (its dates, serial, key type
// and extensions) or from Node.js itself. Dates that are not fixed are given as offsets from
// the dates the scenario fixes.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/**
 * The only certificate of a fixture, as the observation describes it.
 * @param {string} name
 * @param {Date} [at]
 */
function observe(name, at = AT) {
    const observation = inspect(fixture(name), { at });
    assert.deepEqual(errorsOf(observation), [], name);
    return observation.certificates[0];
}

/**
 * An instant given as an ISO text and a number of seconds from it.
 * @param {string} iso
 * @param {number} seconds
 */
function instant(iso, seconds) {
    return new Date(Date.parse(iso) + Math.round(seconds) * 1000);
}

// leaf-expired and leaf-zero-validity have fixed dates in the generator, so they are the only
// fixtures that can be compared with a number written here.
const EXPIRED = { notBefore: "2025-01-01T00:00:00Z", notAfter: "2025-04-01T00:00:00Z", seconds: 90 * 86400 };
const ZERO = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z" };

/**
 * Three certificates that OpenSSL's own commands will not write, made once with
 * `openssl asn1parse -genconf <file> -noout -out <name>.der` and then
 * `openssl x509 -inform DER -in <name>.der -outform PEM`. Their signature is not valid, which
 * does not matter for a certificate observed alone. They share this configuration, with
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
 * and differ in the `[validity]` section and in the extensions, as each constant says.
 */

// CN badtime. openssl refuses to write 30 February as a time, so it is written as an octet
// string with the tag of a GeneralizedTime:
//     [validity]
//     notBefore = IMPLICIT:24U,OCTETSTRING:20260230000000Z
//     notAfter = GENERALIZEDTIME:20270101000000Z
// Node.js gives an Invalid Date for notBefore.
const IMPOSSIBLE_DATE = [
    "-----BEGIN CERTIFICATE-----",
    "MIHVMIG7oAMCAQICAQUwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHYmFkdGltZTAi",
    "GA8yMDI2MDIzMDAwMDAwMFoYDzIwMjcwMTAxMDAwMDAwWjASMRAwDgYDVQQDDAdi",
    "YWR0aW1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5TMfe",
    "sK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I06kbx",
    "UjAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN fraction. A fraction of a second and an offset in notBefore, and the last second of the
// year 9999 in notAfter:
//     [validity]
//     notBefore = GENERALIZEDTIME:20260101000000.999+0130
//     notAfter = GENERALIZEDTIME:99991231235959Z
// Node.js reads notBefore as 2025-12-31T22:30:00Z, truncating the fraction.
const FRACTION_AND_OFFSET = [
    "-----BEGIN CERTIFICATE-----",
    "MIHfMIHFoAMCAQICAQUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIZnJhY3Rpb24w",
    "KhgXMjAyNjAxMDEwMDAwMDAuOTk5KzAxMzAYDzk5OTkxMjMxMjM1OTU5WjATMREw",
    "DwYDVQQDDAhmcmFjdGlvbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI24OVOV",
    "wnPwafoK+UzH3rCv78+sfDY+l3Z5bCl4FH7eZqyj/69aWTIJzNshztej6nBmaZn9",
    "5X7if8PCNOpG8VIwCgYIKoZIzj0EAwIDCQAwBgIBAQIBAQ==",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN oldyears. Dates before 1970: the first day of the year 0000 in notBefore, and a UTCTime of
// year 50, which RFC 5280 reads as 1950, in notAfter:
//     [validity]
//     notBefore = GENERALIZEDTIME:00000101000000Z
//     notAfter = UTCTIME:500101000000Z
const BEFORE_THE_EPOCH = [
    "-----BEGIN CERTIFICATE-----",
    "MIHVMIG7oAMCAQICAQUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIb2xkeWVhcnMw",
    "IBgPMDAwMDAxMDEwMDAwMDBaFw01MDAxMDEwMDAwMDBaMBMxETAPBgNVBAMMCG9s",
    "ZHllYXJzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjbg5U5XCc/Bp+gr5TMfe",
    "sK/vz6x8Nj6XdnlsKXgUft5mrKP/r1pZMgnM2yHO16PqcGZpmf3lfuJ/w8I06kbx",
    "UjAKBggqhkjOPQQDAgMJADAGAgEBAgEB",
    "-----END CERTIFICATE-----",
    "",
].join("\n");

// CN twoeku. Two Extended Key Usage extensions, serverAuth and clientAuth, which is not valid
// X.509. Added to [tbs]:
//     exts = EXPLICIT:3,SEQUENCE:extensions
//     [validity]
//     notBefore = GENERALIZEDTIME:20260101000000Z
//     notAfter = GENERALIZEDTIME:20270101000000Z
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
// Node.js shows no usages at all, the same as for a certificate without the extension.
const TWO_EKU_EXTENSIONS = [
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

test("derived.daysRemaining is (notAfter - at) in days with one decimal, negative once expired: leaf-expired.pem", async (t) => {
    const { notAfter } = EXPIRED;

    await t.test("leaf-expired.pem: 532 days and 14:02:11 after it expired", () => {
        const certificate = observe("leaf-expired.pem");
        assert.equal(certificate.notAfter, notAfter);
        assert.equal(certificate.derived.daysRemaining, -532.6);
    });

    await t.test("leaf-zero-validity.pem: 257 days and 14:02:11 after its single instant", () => {
        assert.equal(observe("leaf-zero-validity.pem").derived.daysRemaining, -257.6);
    });

    await t.test("a certificate with time left is positive: leaf-6-days.pem", () => {
        // Its validity is "-days 6" from the day it is generated, so the notAfter of the fixture is the oracle.
        const { notAfter: end } = observe("leaf-6-days.pem");
        const at = instant(end, -2 * 86400 - 3600);
        assert.equal(observe("leaf-6-days.pem", at).derived.daysRemaining, 2.0);
        assert.equal(observe("leaf-6-days.pem", instant(end, -2 * 86400 - 5 * 3600)).derived.daysRemaining, 2.2);
    });

    await t.test("at the very instant it expires it is 0, and not -0", () => {
        assert.ok(Object.is(observe("leaf-expired.pem", instant(notAfter, 0)).derived.daysRemaining, 0));
    });

    await t.test("a rounded-away amount is 0 on both sides, never -0", () => {
        assert.ok(Object.is(observe("leaf-expired.pem", instant(notAfter, 60)).derived.daysRemaining, 0));
        assert.ok(Object.is(observe("leaf-expired.pem", instant(notAfter, -60)).derived.daysRemaining, 0));
    });

    await t.test("a half decimal rounds away from zero: 4320 seconds is 0.05 days", () => {
        assert.equal(observe("leaf-expired.pem", instant(notAfter, -4320)).derived.daysRemaining, 0.1);
        assert.equal(observe("leaf-expired.pem", instant(notAfter, 4320)).derived.daysRemaining, -0.1);
        assert.ok(Object.is(observe("leaf-expired.pem", instant(notAfter, -4319)).derived.daysRemaining, 0));
        assert.ok(Object.is(observe("leaf-expired.pem", instant(notAfter, 4319)).derived.daysRemaining, 0));
    });

    await t.test("a whole number of days has no fraction to round", () => {
        assert.equal(observe("leaf-expired.pem", instant(notAfter, -30 * 86400)).derived.daysRemaining, 30);
        assert.equal(observe("leaf-expired.pem", instant(notAfter, 30 * 86400)).derived.daysRemaining, -30);
    });

    await t.test("the dates are used to the second, and the span from year 0 to year 9999 stays exact", () => {
        const start = new Date("0000-01-01T00:00:00Z");
        const end = new Date("9999-12-31T23:59:59Z");
        const at = new Date("5000-06-15T12:00:00Z");
        // Tenths of a day with BigInt, so the oracle shares nothing with the implementation.
        const seconds = BigInt((end.getTime() - at.getTime()) / 1000);
        const tenths = (seconds * 20n + 86400n) / 172800n;
        assert.equal(derivedOf(start, end, at).daysRemaining, Number(tenths) / 10);
    });
});

test("derived.lifetimeFraction is (at - notBefore) / (notAfter - notBefore) with two decimals, may exceed 1 or be negative, and is null when notAfter is not after notBefore: leaf-zero-validity.pem", async (t) => {
    const { notBefore, notAfter, seconds } = EXPIRED;

    await t.test("leaf-zero-validity.pem: the validity has no duration, so there is no fraction", () => {
        const certificate = observe("leaf-zero-validity.pem");
        assert.equal(certificate.notBefore, ZERO.notBefore);
        assert.equal(certificate.notAfter, ZERO.notAfter);
        assert.equal(certificate.derived.lifetimeFraction, null);
        // The days left are still known.
        assert.equal(typeof certificate.derived.daysRemaining, "number");
    });

    await t.test("a notAfter before the notBefore has no fraction either", () => {
        const earlier = new Date(ZERO.notBefore);
        assert.equal(derivedOf(instant(ZERO.notBefore, 10), earlier, AT).lifetimeFraction, null);
        assert.equal(derivedOf(instant(ZERO.notBefore, 1), earlier, AT).lifetimeFraction, null);
    });

    await t.test("leaf-expired.pem is far past its end: 0.5 of its lifetime at the middle, 1 at the end, 2.01 and 6 beyond it", () => {
        const fraction = (/** @type {number} */ offset) => observe("leaf-expired.pem", instant(notBefore, offset)).derived.lifetimeFraction;
        assert.equal(fraction(seconds / 2), 0.5);
        assert.equal(fraction(seconds), 1);
        assert.equal(fraction(seconds * 2.01), 2.01);
        assert.equal(fraction(seconds * 6), 6);
        assert.equal(observe("leaf-expired.pem").derived.lifetimeFraction, 6.92);
    });

    await t.test("it is 0 at the start, and not -0 a moment before it", () => {
        const fraction = (/** @type {number} */ offset) => observe("leaf-expired.pem", instant(notBefore, offset)).derived.lifetimeFraction;
        assert.ok(Object.is(fraction(0), 0));
        assert.ok(Object.is(fraction(-1), 0));
    });

    await t.test("it is negative before the certificate is valid", () => {
        const fraction = (/** @type {number} */ offset) => observe("leaf-expired.pem", instant(notBefore, offset)).derived.lifetimeFraction;
        assert.equal(fraction(-seconds / 2), -0.5);
        assert.equal(fraction(-seconds), -1);
    });

    await t.test("a half hundredth rounds away from zero: 1.5 hundredths of 90 days is 116640 seconds", () => {
        const fraction = (/** @type {number} */ offset) => observe("leaf-expired.pem", instant(notBefore, offset)).derived.lifetimeFraction;
        assert.equal(fraction(116640), 0.02);
        assert.equal(fraction(116639), 0.01);
        assert.equal(fraction(-116640), -0.02);
        assert.equal(fraction(-116639), -0.01);
    });

    await t.test("the end of the validity is where the fraction reaches 1", () => {
        assert.equal(observe("leaf-expired.pem", instant(notAfter, 0)).derived.lifetimeFraction, 1);
    });
});

test('dn joins components with ", " and keeps the backslash escape on a comma inside a value: leaf-multi-dn.pem', async (t) => {
    await t.test("leaf-multi-dn.pem: the comma inside O stays escaped, so there are four components", () => {
        const { subject } = observe("leaf-multi-dn.pem");
        assert.equal(subject.dn, "C=CL, O=Acme\\, Inc., OU=Platform, CN=multi.example");
        // A reader splits on a ", " that is not escaped, and gets the four components of the scenario.
        assert.deepEqual(subject.dn.split(/(?<!\\), /), ["C=CL", "O=Acme\\, Inc.", "OU=Platform", "CN=multi.example"]);
        assert.equal(subject.cn, "multi.example");
    });

    await t.test("an escaped comma and two components are different text", () => {
        assert.notEqual(distinguishedName("O=Acme\\, Inc."), distinguishedName("O=Acme\nInc."));
        assert.equal(distinguishedName("O=Acme\\, Inc."), "O=Acme\\, Inc.");
        assert.equal(distinguishedName("O=Acme\nInc."), "O=Acme, Inc.");
    });

    await t.test("the issuer has its own name, in the same form", () => {
        // The generator signs every leaf with the intermediate "/CN=certdrift test intermediate CA".
        assert.deepEqual(observe("leaf-multi-dn.pem").issuer, { cn: "certdrift test intermediate CA", dn: "CN=certdrift test intermediate CA" });
    });

    await t.test("a line break inside a value is written \\0A by Node.js and does not make a component", () => {
        assert.equal(distinguishedName("O=a\\0Ab\nCN=x"), "O=a\\0Ab, CN=x");
    });

    await t.test("the components of a multi-valued RDN keep the text Node.js gives them", () => {
        assert.equal(distinguishedName("CN=a + O=b\nOU=x"), "CN=a + O=b, OU=x");
    });

    await t.test("a value with a plus, a backslash or a leading space keeps its escapes", () => {
        assert.equal(distinguishedName("O=a \\+ b\nOU=\\ lead\nCN=back\\\\slash"), "O=a \\+ b, OU=\\ lead, CN=back\\\\slash");
    });

    await t.test("an empty name, which Node.js gives as undefined, is an empty string", () => {
        assert.equal(distinguishedName(undefined), "");
        assert.equal(distinguishedName(""), "");
    });
});

test("cn is null when the certificate has no subject: leaf-no-cn.pem", () => {
    const certificate = observe("leaf-no-cn.pem");
    assert.deepEqual(certificate.subject, { cn: null, dn: "" });
    // Only the subject is empty: the issuer is read as usual.
    assert.deepEqual(certificate.issuer, { cn: "certdrift test intermediate CA", dn: "CN=certdrift test intermediate CA" });
});

test("dates are ISO 8601 UTC with second precision and no milliseconds", async (t) => {
    const names = [
        "leaf-p256.pem", "leaf-expired.pem", "leaf-zero-validity.pem", "leaf-6-days.pem", "root-ca.pem",
        "intermediate.pem", "selfsigned-leaf.pem", "leaf-rsa.pem", "leaf-ed25519.pem", "leaf-sm2.pem",
    ];
    for (const name of names) {
        await t.test(`${name}: both dates have the pattern and name the same instant as Node.js`, () => {
            const certificate = observe(name);
            const node = new X509Certificate(fixture(name));
            // Node.js's own text ("Jan  1 00:00:00 2025 GMT") is read by the engine, not by the library.
            const dates = { notBefore: node.validFrom, notAfter: node.validTo };
            for (const field of /** @type {const} */ (["notBefore", "notAfter"])) {
                assert.match(certificate[field], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, `${name} ${field}`);
                assert.equal(Date.parse(certificate[field]), Date.parse(dates[field]), `${name} ${field}`);
            }
        });
    }

    await t.test("leaf-expired.pem: the dates the scenario fixes", () => {
        const certificate = observe("leaf-expired.pem");
        assert.equal(certificate.notBefore, "2025-01-01T00:00:00Z");
        assert.equal(certificate.notAfter, "2025-04-01T00:00:00Z");
    });

    await t.test("a fraction of a second and an offset: the fraction is cut, and the instant is in UTC", () => {
        const observation = inspect(FRACTION_AND_OFFSET, { at: AT });
        assert.deepEqual(errorsOf(observation), []);
        const [certificate] = observation.certificates;
        assert.equal(certificate.notBefore, "2025-12-31T22:30:00Z");
        assert.equal(certificate.notAfter, "9999-12-31T23:59:59Z");
    });

    await t.test("dates before 1970: year 0000 and a UTCTime of year 50, which is 1950", () => {
        const observation = inspect(BEFORE_THE_EPOCH, { at: AT });
        assert.deepEqual(errorsOf(observation), []);
        const [{ notBefore, notAfter, derived }] = observation.certificates;
        assert.equal(notBefore, "0000-01-01T00:00:00Z");
        assert.equal(notAfter, "1950-01-01T00:00:00Z");

        // The same quotients with BigInt, which shares nothing with the implementation.
        const seconds = (/** @type {string} */ iso) => BigInt(Date.parse(iso) / 1000);
        const at = BigInt(AT.getTime() / 1000);
        const left = seconds(notAfter) - at;
        const days = (-left * 20n + 86400n) / 172800n;
        assert.equal(derived.daysRemaining, -Number(days) / 10);
        const length = seconds(notAfter) - seconds(notBefore);
        const lived = at - seconds(notBefore);
        assert.equal(derived.lifetimeFraction, Number((lived * 200n + length) / (2n * length)) / 100);
        assert.ok(derived.lifetimeFraction > 1);
    });

    await t.test("the last second of the year 9999 is a four-digit year", () => {
        const [certificate] = inspect(FRACTION_AND_OFFSET, { at: AT }).certificates;
        assert.equal(certificate.derived.daysRemaining, Math.round(((Date.parse("9999-12-31T23:59:59Z") - AT.getTime()) / 86400000) * 10) / 10);
    });

    await t.test("a date that is not an instant throws a ParseError naming the input block", () => {
        const key = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        const cases = [{ material: IMPOSSIBLE_DATE, block: 1 }, { material: key + IMPOSSIBLE_DATE, block: 2 }];
        for (const { material, block } of cases) {
            assert.throws(() => inspect(material, { at: AT }), (error) => {
                assert.ok(error instanceof ParseError, `expected a ParseError, got ${error}`);
                assert.equal(error.block, block);
                assert.match(error.message, new RegExp(`input block ${block}\\b.*notBefore`));
                return true;
            });
        }
    });

    // For this certificate Node.js builds `validFromDate` from memory nothing has written: it is an
    // Invalid Date in one call and a date thousands of years away in another, on the same bytes and
    // the same process, so no test can rely on seeing either. The text is stable, and it is what
    // validityDate reads.
    await t.test("Node.js writes Bad time value for it, which is the signal validityDate reads", () => {
        const node = new X509Certificate(IMPOSSIBLE_DATE);
        assert.equal(node.validFrom, "Bad time value");
        assert.ok(Number.isNaN(Date.parse(node.validFrom)));
        assert.equal(node.validTo, "Jan  1 00:00:00 2027 GMT");
    });

    await t.test("validityDate trusts the text, not a Date that looks fine", () => {
        const garbage = new Date("+054746-03-18T20:31:48Z");
        assert.throws(() => validityDate(garbage, "Bad time value", 3, "notAfter"), (error) => {
            assert.ok(error instanceof ParseError);
            assert.equal(error.block, 3);
            assert.match(error.message, /input block 3\b.*notAfter/);
            return true;
        });
    });

    await t.test("validityDate rejects what is not a date in either form", () => {
        const good = new Date("2026-01-01T00:00:00Z");
        /** @type {[Date | undefined, string | undefined][]} */
        const cases = [[new Date(Number.NaN), "Jan  1 00:00:00 2026 GMT"], [good, undefined], [undefined, "Jan  1 00:00:00 2026 GMT"], [good, ""]];
        for (const [date, text] of cases) {
            assert.throws(() => validityDate(date, text, 1, "notBefore"), ParseError);
        }
    });

    await t.test("validityDate gives the date as Node.js has it when both forms agree that it is one", () => {
        // The fraction is in the text and not in the date, which is cut to the second.
        const date = new Date("2025-12-31T22:30:00Z");
        assert.equal(validityDate(date, "Dec 31 22:30:00.999 2025 GMT", 1, "notBefore").getTime(), date.getTime());
        // A year before 100 is read by the engine as a year in the 1900s or 2000s, which is why the text is only a signal.
        const first = new Date("0000-01-01T00:00:00Z");
        assert.equal(validityDate(first, "Jan  1 00:00:00 0 GMT", 1, "notBefore").getTime(), first.getTime());
    });
});

test("serial is uppercase hexadecimal with no separators, keeping a leading - when it is negative: leaf-serial-negative.pem gives -05 and leaf-serial-zero.pem gives 0", async (t) => {
    await t.test("leaf-serial-negative.pem", () => assert.equal(observe("leaf-serial-negative.pem").serial, "-05"));
    await t.test("leaf-serial-zero.pem", () => assert.equal(observe("leaf-serial-zero.pem").serial, "0"));

    await t.test("every other certificate has a long serial of uppercase digits, with no colon or prefix", () => {
        for (const name of ["leaf-p256.pem", "leaf-rsa.pem", "root-ca.pem", "intermediate.pem", "selfsigned-leaf.pem"]) {
            const { serial } = observe(name);
            assert.match(serial, /^[0-9A-F]+$/, name);
            // The generator's serials are 20 random bytes, so they are long whatever their first byte is.
            assert.ok(serial.length >= 30, `${name}: ${serial}`);
        }
    });

    await t.test("it is the serial Node.js reports", () => {
        for (const name of ["leaf-p256.pem", "leaf-serial-negative.pem", "leaf-serial-zero.pem", "root-ca.pem"]) {
            assert.equal(observe(name).serial, new X509Certificate(fixture(name)).serialNumber, name);
        }
    });
});

test("eku maps known OIDs to names, leaves the OID as text otherwise, is sorted, and is null when the extension is absent", async (t) => {
    // The generator gives every leaf serverAuth, leaf-p256 also clientAuth, and leaf-ed25519 no extension.
    const EXPECTED = {
        "leaf-ed25519.pem": null,
        "leaf-p256.pem": ["clientAuth", "serverAuth"],
        "leaf-p384.pem": ["serverAuth"],
        "leaf-p521.pem": ["serverAuth"],
        "leaf-rsa.pem": ["serverAuth"],
        "leaf-rsa-pss.pem": ["serverAuth"],
        "leaf-brainpool.pem": ["serverAuth"],
        "leaf-sm2.pem": ["serverAuth"],
        "leaf-ml-dsa-44.pem": ["serverAuth"],
        "leaf-multi-dn.pem": ["serverAuth"],
        "leaf-no-cn.pem": ["serverAuth"],
        "leaf-expired.pem": ["serverAuth"],
    };
    for (const [name, eku] of Object.entries(EXPECTED)) {
        await t.test(name, () => assert.deepEqual(observe(name).eku, eku));
    }

    await t.test("a CA without the extension is null too", () => {
        assert.equal(observe("root-ca.pem").eku, null);
    });

    await t.test("the six names the contract knows, from their OIDs, in order", () => {
        assert.deepEqual(
            extendedKeyUsage([
                "1.3.6.1.5.5.7.3.9", "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.4",
                "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1",
            ]),
            ["OCSPSigning", "clientAuth", "codeSigning", "emailProtection", "serverAuth", "timeStamping"],
        );
    });

    await t.test("an OID with no name stays as text, including anyExtendedKeyUsage", () => {
        assert.deepEqual(
            extendedKeyUsage(["1.3.6.1.5.5.7.3.1", "2.5.29.37.0", "1.3.6.1.4.1.311.10.3.4"]),
            ["1.3.6.1.4.1.311.10.3.4", "2.5.29.37.0", "serverAuth"],
        );
    });

    await t.test("the order is by code unit, so it does not depend on the machine's locale", () => {
        assert.deepEqual(extendedKeyUsage(["serverAuth", "9.9", "OCSPSigning", "10.1", "clientAuth"]), ["10.1", "9.9", "OCSPSigning", "clientAuth", "serverAuth"]);
        assert.deepEqual(extendedKeyUsage(["1.3.6.1.5.5.7.3.9", "1.3.6.1.5.5.7.3.1"]), ["OCSPSigning", "serverAuth"]);
    });

    await t.test("a repeated usage is kept", () => {
        assert.deepEqual(extendedKeyUsage(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.1"]), ["serverAuth", "serverAuth"]);
    });

    await t.test("an extension with no usages is an empty list, which is not the same as no extension", () => {
        assert.deepEqual(extendedKeyUsage([]), []);
        assert.equal(extendedKeyUsage(undefined), null);
    });

    await t.test("the list is a copy: sorting it does not reorder the one Node.js gave", () => {
        const given = ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"];
        extendedKeyUsage(given);
        assert.deepEqual(given, ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"]);
    });

    // Node.js shows no usages when the certificate carries the extension twice, and gives
    // `undefined` for an extension it cannot decode, so both read as "no restriction". The
    // restriction cannot be seen without reading the DER, which is not done here.
    await t.test("a certificate with two Extended Key Usage extensions is shown with none, as Node.js shows it", () => {
        const certificate = inspect(TWO_EKU_EXTENSIONS, { at: AT }).certificates[0];
        assert.equal(new X509Certificate(TWO_EKU_EXTENSIONS).keyUsage, undefined);
        assert.equal(certificate.eku, null);
    });
});

/**
 * The key type and what the generator makes of it for each leaf.
 * @type {Record<string, { algorithm: string | null, size: number | null, curve: string | null }>}
 */
const KEYS = {
    "leaf-rsa.pem": { algorithm: "rsa", size: 2048, curve: null },
    "leaf-rsa-pss.pem": { algorithm: "rsa-pss", size: 2048, curve: null },
    "leaf-p256.pem": { algorithm: "ec", size: 256, curve: "P-256" },
    "leaf-p384.pem": { algorithm: "ec", size: 384, curve: "P-384" },
    "leaf-p521.pem": { algorithm: "ec", size: 521, curve: "P-521" },
    "leaf-brainpool.pem": { algorithm: "ec", size: null, curve: "brainpoolP256r1" },
    "leaf-ed25519.pem": { algorithm: "ed25519", size: null, curve: null },
    "leaf-ml-dsa-44.pem": { algorithm: "ml-dsa-44", size: null, curve: null },
    "leaf-sm2.pem": { algorithm: null, size: null, curve: null },
};

/**
 * A public key of a type Node.js can generate.
 * @param {string} type
 * @param {object} [options]
 * @returns {import("node:crypto").KeyObject}
 */
function publicKey(type, options) {
    const generate = /** @type {(type: string, options?: object) => { publicKey: import("node:crypto").KeyObject }} */ (/** @type {unknown} */ (generateKeyPairSync));
    return generate(type, options).publicKey;
}

test("key.algorithm is the lowercase asymmetricKeyType, and null when Node.js does not identify the type: leaf-sm2.pem", async (t) => {
    for (const [name, { algorithm }] of Object.entries(KEYS)) {
        await t.test(name, () => assert.equal(observe(name).key.algorithm, algorithm));
    }

    await t.test("leaf-sm2.pem: Node.js loads the key and gives no type for it", () => {
        const { publicKey: key } = new X509Certificate(fixture("leaf-sm2.pem"));
        assert.equal(key.asymmetricKeyType, undefined);
        assert.equal(observe("leaf-sm2.pem").key.algorithm, null);
    });

    await t.test("other types Node.js can generate keep its name", () => {
        /** @type {[string, object?][]} */
        const types = [["ed448"], ["x25519"], ["ml-dsa-65"], ["dsa", { modulusLength: 1024, divisorLength: 160 }]];
        for (const [type, options] of types) {
            assert.equal(publicKeyOf(publicKey(type, options)).algorithm, type);
        }
    });

    await t.test("a type in capitals is written in lowercase", () => {
        assert.equal(publicKeyOf({ asymmetricKeyType: "ED25519" }).algorithm, "ed25519");
    });
});

test("key.size is the modulus length for RSA or the curve size for a NIST-named curve, and null otherwise: leaf-ed25519.pem and leaf-ml-dsa-44.pem", async (t) => {
    for (const [name, { size }] of Object.entries(KEYS)) {
        await t.test(name, () => assert.equal(observe(name).key.size, size));
    }

    await t.test("an RSA modulus that is not a power of two is its own length", () => {
        assert.equal(publicKeyOf(publicKey("rsa", { modulusLength: 1025 })).size, 1025);
    });

    await t.test("a key with a modulus that is neither RSA nor RSA-PSS has no size: DSA", () => {
        const key = publicKey("dsa", { modulusLength: 1024, divisorLength: 160 });
        assert.equal(key.asymmetricKeyDetails?.modulusLength, 1024);
        assert.equal(publicKeyOf(key).size, null);
    });

    await t.test("curves outside the NIST map have no size: secp224r1 and secp256k1", () => {
        for (const namedCurve of ["secp224r1", "secp256k1"]) {
            assert.equal(publicKeyOf(publicKey("ec", { namedCurve })).size, null, namedCurve);
        }
    });

    await t.test("a modulus length that is not a positive integer is not a size", () => {
        for (const modulusLength of [0, -1, 2048.5, Number.NaN, "2048", undefined]) {
            assert.equal(publicKeyOf({ asymmetricKeyType: "rsa", asymmetricKeyDetails: /** @type {any} */ ({ modulusLength }) }).size, null, String(modulusLength));
        }
    });
});

test("key.curve is the NIST name when one exists, otherwise the name Node.js reports, and null for non-EC keys: leaf-brainpool.pem keeps brainpoolP256r1 with size null", async (t) => {
    for (const [name, { curve }] of Object.entries(KEYS)) {
        await t.test(name, () => assert.equal(observe(name).key.curve, curve));
    }

    await t.test("Node.js names the NIST curves prime256v1, secp384r1 and secp521r1", () => {
        const names = ["leaf-p256.pem", "leaf-p384.pem", "leaf-p521.pem"].map((name) => new X509Certificate(fixture(name)).publicKey.asymmetricKeyDetails?.namedCurve);
        assert.deepEqual(names, ["prime256v1", "secp384r1", "secp521r1"]);
    });

    await t.test("a curve outside the map keeps the name Node.js reports: secp224r1, secp256k1, brainpoolP384r1", () => {
        for (const namedCurve of ["secp224r1", "secp256k1", "brainpoolP384r1"]) {
            assert.deepEqual(publicKeyOf(publicKey("ec", { namedCurve })), { algorithm: "ec", size: null, curve: namedCurve });
        }
    });

    await t.test("a curve already written with its NIST name is not mistaken for another one", () => {
        assert.deepEqual(publicKeyOf({ asymmetricKeyType: "ec", asymmetricKeyDetails: { namedCurve: "P-256" } }), { algorithm: "ec", size: null, curve: "P-256" });
    });

    await t.test("an EC key without a curve name has none to report", () => {
        assert.deepEqual(publicKeyOf({ asymmetricKeyType: "ec", asymmetricKeyDetails: {} }), { algorithm: "ec", size: null, curve: null });
        assert.deepEqual(publicKeyOf({ asymmetricKeyType: "ec" }), { algorithm: "ec", size: null, curve: null });
        assert.deepEqual(publicKeyOf({ asymmetricKeyType: "ec", asymmetricKeyDetails: /** @type {any} */ ({ namedCurve: "" }) }), { algorithm: "ec", size: null, curve: null });
    });

    await t.test("a key that is not EC has no curve, even when its details name one", () => {
        assert.equal(publicKeyOf({ asymmetricKeyType: "rsa", asymmetricKeyDetails: { modulusLength: 2048, namedCurve: "prime256v1" } }).curve, null);
    });
});

test("asymmetricKeyDetails is never spread into the result: its fields are picked one by one", async (t) => {
    await t.test("every key of every fixture has exactly algorithm, size and curve, and serializes", () => {
        for (const name of Object.keys(KEYS)) {
            const { key } = observe(name);
            assert.deepEqual(Object.keys(key), ["algorithm", "size", "curve"], name);
            assert.doesNotThrow(() => JSON.stringify(key), name);
        }
    });

    await t.test("an RSA key, whose details hold a BigInt", () => {
        const key = publicKey("rsa", { modulusLength: 2048 });
        assert.equal(typeof key.asymmetricKeyDetails?.publicExponent, "bigint");
        const result = publicKeyOf(key);
        assert.deepEqual(result, { algorithm: "rsa", size: 2048, curve: null });
        assert.doesNotThrow(() => JSON.stringify(result));
    });

    await t.test("an RSA-PSS key with parameters, whose details hold a hash, a mask hash and a salt length", () => {
        const key = publicKey("rsa-pss", { modulusLength: 2048, hashAlgorithm: "sha256", mgf1HashAlgorithm: "sha256", saltLength: 32 });
        assert.deepEqual(Object.keys(key.asymmetricKeyDetails ?? {}).sort(), ["hashAlgorithm", "mgf1HashAlgorithm", "modulusLength", "publicExponent", "saltLength"]);
        assert.deepEqual(publicKeyOf(key), { algorithm: "rsa-pss", size: 2048, curve: null });
    });

    await t.test("fields the contract does not describe never reach the result, whatever the details hold", () => {
        const details = { modulusLength: 4096, namedCurve: "prime256v1", publicExponent: 65537n, divisorLength: 256, hashAlgorithm: "sha256", extra: { nested: 1n } };
        // Each type takes only what the contract says it has, even though its details name more.
        const expected = {
            rsa: { size: 4096, curve: null },
            "rsa-pss": { size: 4096, curve: null },
            ec: { size: 256, curve: "P-256" },
            dsa: { size: null, curve: null },
            ed25519: { size: null, curve: null },
            "future-type": { size: null, curve: null },
        };
        for (const [asymmetricKeyType, { size, curve }] of Object.entries(expected)) {
            const result = publicKeyOf({ asymmetricKeyType, asymmetricKeyDetails: details });
            assert.deepEqual(result, { algorithm: asymmetricKeyType, size, curve });
            assert.deepEqual(Object.keys(result), ["algorithm", "size", "curve"], asymmetricKeyType);
            assert.doesNotThrow(() => JSON.stringify(result), asymmetricKeyType);
        }
    });
});
