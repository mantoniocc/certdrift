import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { evaluate, inspect } from "../src/index.js";
import { ekuWarning } from "../src/kind-warning.js";
import { certificatesIn } from "../src/material.js";
import { runMain } from "./helpers/command.js";
import { validatorFor } from "./helpers/schema.js";
import { CONSTRUCTED_EKU_EXTENSION, EMPTY_EKU_EXTENSION, REPEATED_EKU_EXTENSION, UNDECODABLE_EKU_EXTENSION } from "./helpers/certificates.js";

// `eku` is Node.js's `keyUsage`, which is `undefined` for an Extended Key Usage extension that is
// absent and for one that is present and cannot be read. The warning tells the second from the
// first by counting the extension in the certificate's bytes and comparing with what Node.js
// reports. These tests keep that comparison honest: each certificate's bytes are checked, and so is
// what Node.js reads from them, before the warning is asserted, so that a change in Node.js shows
// up as a failing test and not as a silently different warning.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

const REPEATED_REASON = "eku cannot be trusted: Extended Key Usage appears more than once";
const UNDECODABLE_REASON = "eku cannot be trusted: Extended Key Usage does not decode";
const NOT_READ_REASON = "kind cannot be trusted: the certificate's extensions could not be read to check it";

/** @param {string} pem */
const rawOf = (pem) => new X509Certificate(pem).raw;

/** @param {string} pem */
const usagesOf = (pem) => new X509Certificate(pem).keyUsage;

/**
 * The observation of a material, which must validate.
 * @param {string | Uint8Array} material
 * @param {string} [select]
 */
function observe(material, select) {
    const observation = inspect(material, { at: AT, ...(select === undefined ? {} : { select }) });
    assert.deepEqual(errorsOf(observation), []);
    return observation;
}

/** @param {string | Uint8Array} material */
const warningsOf = (material) => observe(material).warnings;

/** @param {string} name */
const fixture = (name) => readFileSync(new URL(name, fixturesUrl));

// ---------------------------------------------------------------------------------------------
// Certificates built from bytes, to give the reader the cases the hand-built ones do not hold.

/**
 * A DER element with its length in the shortest form.
 * @param {number} tag
 * @param {Buffer} content
 */
function der(tag, content) {
    const length = content.length;
    const header = length < 0x80 ? [tag, length] : length < 0x100 ? [tag, 0x81, length] : [tag, 0x82, length >> 8, length & 0xff];
    return Buffer.concat([Buffer.from(header), content]);
}

/** @param {string} hex */
const bytes = (hex) => Buffer.from(hex.replaceAll(" ", ""), "hex");

// UNDECODABLE_EKU_EXTENSION is `30 81 ed 30 81 d3 <body up to the extensions> a3 0e 30 0c 30 0a 06 03
// 55 1d 25 04 03 02 01 01 <signature algorithm and value>`. These certificates keep everything
// else and replace the extensions field, so each differs from it in the extensions alone, and the
// lengths of the body and of the certificate are written again to fit.
const BASE = rawOf(UNDECODABLE_EKU_EXTENSION);
const BASE_FIELD = bytes("a30e300c300a0603551d250403020101");
const BASE_AT = BASE.indexOf(BASE_FIELD);
assert.notEqual(BASE_AT, -1, "the extensions field of UNDECODABLE_EKU_EXTENSION was not found");

/**
 * One certificate with these extensions, each given as a whole DER element.
 * @param {Buffer[]} extensions
 * @param {{ indefinite?: boolean }} [options] Write the extensions field with the indefinite length.
 */
function withExtensions(extensions, { indefinite = false } = {}) {
    const list = der(0x30, Buffer.concat(extensions));
    const field = indefinite ? Buffer.concat([bytes("a3 80"), list, bytes("00 00")]) : der(0xa3, list);
    const body = der(0x30, Buffer.concat([BASE.subarray(6, BASE_AT), field]));
    return der(0x30, Buffer.concat([body, BASE.subarray(BASE_AT + BASE_FIELD.length)]));
}

const EKU_ID = bytes("06 03 55 1d 25");
/**
 * An Extended Key Usage extension with this value.
 * @param {string} value The bytes inside the OCTET STRING.
 * @param {{ critical?: boolean, id?: Buffer }} [options]
 */
function extendedKeyUsage(value, { critical = false, id = EKU_ID } = {}) {
    return der(0x30, Buffer.concat([id, critical ? bytes("01 01 ff") : Buffer.alloc(0), der(0x04, bytes(value))]));
}

const SERVER_AUTH = "30 0a 06 08 2b 06 01 05 05 07 03 01";
const CLIENT_AUTH = "30 0a 06 08 2b 06 01 05 05 07 03 02";
const INTEGER = "02 01 01";

// ---------------------------------------------------------------------------------------------
// What Node.js gives for each hand-built certificate

test("what Node.js gives for each certificate the tests rely on: the usages, and the extension in the bytes", async (t) => {
    await t.test("an extension that lists nothing is an empty list", () => {
        assert.ok(rawOf(EMPTY_EKU_EXTENSION).includes(bytes("30 09 06 03 55 1d 25 04 02 30 00")));
        assert.deepEqual(usagesOf(EMPTY_EKU_EXTENSION), []);
    });

    await t.test("an extension whose value is an INTEGER gives undefined, as an absent one does", () => {
        assert.ok(rawOf(UNDECODABLE_EKU_EXTENSION).includes(bytes("30 0a 06 03 55 1d 25 04 03 02 01 01")));
        assert.equal(usagesOf(UNDECODABLE_EKU_EXTENSION), undefined);
    });

    await t.test("the extension twice gives undefined, although each copy alone is readable", () => {
        const raw = rawOf(REPEATED_EKU_EXTENSION);
        assert.ok(raw.includes(bytes("30 13 06 03 55 1d 25 04 0c 30 0a 06 08 2b 06 01 05 05 07 03 01 30 13 06 03 55 1d 25 04 0c 30 0a 06 08 2b 06 01 05 05 07 03 02")));
        assert.equal(usagesOf(REPEATED_EKU_EXTENSION), undefined);
        assert.deepEqual(usagesOf(pemOf(withExtensions([extendedKeyUsage(SERVER_AUTH)]))), ["1.3.6.1.5.5.7.3.1"]);
    });

    await t.test("the extension once, with a constructed OCTET STRING for its value, is read", () => {
        assert.ok(rawOf(CONSTRUCTED_EKU_EXTENSION).includes(bytes("30 17 06 03 55 1d 25 24 10 04 06 30 0a 06 08 2b 06 04 06 01 05 05 07 03 01")));
        assert.deepEqual(usagesOf(CONSTRUCTED_EKU_EXTENSION), ["1.3.6.1.5.5.7.3.1"]);
    });
});

// ---------------------------------------------------------------------------------------------
// The warning

test("EKU_UNRELIABLE comes once per certificate with its index, says whether the extension is repeated or does not decode, and quotes nothing from the certificate", async (t) => {
    await t.test("an extension that appears twice says so", () => {
        assert.equal(usagesOf(REPEATED_EKU_EXTENSION), undefined);
        assert.deepEqual(warningsOf(REPEATED_EKU_EXTENSION), [{ code: "EKU_UNRELIABLE", certificate: 0, message: REPEATED_REASON }]);
    });

    await t.test("an extension whose value does not decode says so", () => {
        assert.equal(usagesOf(UNDECODABLE_EKU_EXTENSION), undefined);
        assert.deepEqual(warningsOf(UNDECODABLE_EKU_EXTENSION), [{ code: "EKU_UNRELIABLE", certificate: 0, message: UNDECODABLE_REASON }]);
    });

    await t.test("an extension three times is still one warning", () => {
        const pem = pemOf(withExtensions([extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(SERVER_AUTH)]));
        assert.equal(usagesOf(pem), undefined);
        assert.deepEqual(warningsOf(pem).map(({ code, message }) => [code, message]), [["EKU_UNRELIABLE", REPEATED_REASON]]);
    });

    await t.test("each certificate of a material gets its own, by its index", () => {
        const leaf = readFileSync(new URL("leaf-p256.pem", fixturesUrl), "latin1");
        const select = observe(leaf).certificates[0].sha256.slice(0, 8);
        const observation = observe(UNDECODABLE_EKU_EXTENSION + leaf + REPEATED_EKU_EXTENSION, select);
        assert.deepEqual(observation.warnings.map(({ code, certificate, message }) => [code, certificate, message]), [
            ["EKU_UNRELIABLE", 0, UNDECODABLE_REASON],
            ["EKU_UNRELIABLE", 2, REPEATED_REASON],
        ]);
    });

    await t.test("the message holds nothing of the certificate", () => {
        for (const pem of [REPEATED_EKU_EXTENSION, UNDECODABLE_EKU_EXTENSION]) {
            const { certificates, warnings } = observe(pem);
            const [{ subject, serial, sha256 }] = certificates;
            for (const { message } of warnings) {
                assert.ok(!message.includes(subject.cn ?? "\0") && !message.includes(serial) && !message.includes(sha256.slice(0, 8)) && !message.includes("1.3.6.1"), message);
            }
        }
        assert.match(REPEATED_REASON, /^[a-zA-Z :.]+$/);
    });
});

test("no warning for an Extended Key Usage that is absent, one that lists nothing, or one that lists usages", async (t) => {
    await t.test("absent", () => {
        const extensions = readFileSync(new URL("leaf-ed25519.ext", fixturesUrl), "utf8");
        assert.doesNotMatch(extensions, /extendedKeyUsage/);
        assert.equal(usagesOf(fixture("leaf-ed25519.pem").toString()), undefined);
        const observation = observe(fixture("leaf-ed25519.pem"));
        assert.equal(observation.certificates[0].eku, null);
        assert.deepEqual(observation.warnings, []);
    });

    await t.test("present and listing nothing", () => {
        assert.deepEqual(usagesOf(EMPTY_EKU_EXTENSION), []);
        const observation = observe(EMPTY_EKU_EXTENSION);
        assert.deepEqual(observation.certificates[0].eku, []);
        assert.deepEqual(observation.warnings, []);
    });

    await t.test("present and listing usages", () => {
        const extensions = readFileSync(new URL("leaf-p256.ext", fixturesUrl), "utf8");
        assert.match(extensions, /extendedKeyUsage = serverAuth, clientAuth/);
        const observation = observe(fixture("leaf-p256.pem"));
        assert.deepEqual(observation.certificates[0].eku, ["clientAuth", "serverAuth"]);
        assert.deepEqual(observation.warnings, []);
    });
});

test("the decision is by comparison: told that Node.js read the usages, the reader has nothing to warn about", () => {
    for (const pem of [REPEATED_EKU_EXTENSION, UNDECODABLE_EKU_EXTENSION]) {
        assert.notEqual(ekuWarning(rawOf(pem), undefined, 0), null);
        assert.equal(ekuWarning(rawOf(pem), ["1.3.6.1.5.5.7.3.1"], 0), null);
        assert.equal(ekuWarning(rawOf(pem), [], 0), null);
    }
});

test("eku keeps the value Node.js gives, and expectEku, ekuAllows and rejectEku give the same verdicts as they would without the warning", async (t) => {
    const entries = { expectEku: { value: ["serverAuth"] }, ekuAllows: { value: ["serverAuth"] }, rejectEku: { value: ["serverAuth"] } };
    for (const [name, pem] of [["repeated", REPEATED_EKU_EXTENSION], ["undecodable", UNDECODABLE_EKU_EXTENSION]]) {
        await t.test(name, () => {
            assert.equal(usagesOf(pem), undefined);
            const observation = observe(pem);
            assert.equal(observation.certificates[0].eku, null);
            assert.equal(observation.warnings.length, 1);
            assert.deepEqual(Object.keys(observation.warnings[0]), ["code", "certificate", "message"]);

            const { notBefore } = observation.certificates[0];
            /** @type {import("../src/index.js").Policy} */
            const policy = { contract: 1, ...entries };
            const withWarning = evaluate(observation, policy, { now: notBefore });
            const without = evaluate({ ...observation, warnings: [] }, policy, { now: notBefore });
            assert.deepEqual(withWarning.results, without.results);
            const verdicts = withWarning.results.slice(2).map(({ code, status }) => `${code} ${status}`);
            assert.deepEqual(verdicts, ["EKU_MISSING fail", "EKU_NOT_PERMITTED pass", "EKU_FORBIDDEN pass"]);
        });
    }
});

// ---------------------------------------------------------------------------------------------
// Bytes the criteria do not name, and that the purpose covers

test("the extension is counted and its value is not decoded, so Node.js decides what is readable", async (t) => {
    /** @type {[string, Buffer[], boolean][]} */
    const cases = [
        // [name, extensions, whether Node.js reads the usages]
        ["bytes after the sequence of usages are read by Node.js", [extendedKeyUsage(`${SERVER_AUTH} 05 00`)], true],
        ["a length in the long form is read by Node.js", [extendedKeyUsage("30 81 0a 06 08 2b 06 01 05 05 07 03 01")], true],
        ["a critical extension is read by Node.js", [extendedKeyUsage(SERVER_AUTH, { critical: true })], true],
        ["a value that is a SEQUENCE of INTEGER does not decode", [extendedKeyUsage(`30 03 ${INTEGER}`)], false],
        ["a value that is an empty OID does not decode", [extendedKeyUsage("30 02 06 00")], false],
        ["a value cut short does not decode", [extendedKeyUsage("30 0a 06 08 2b 06 01 05 05 07 03")], false],
        ["a value that is an INTEGER does not decode", [extendedKeyUsage(INTEGER)], false],
    ];
    for (const [name, extensions, read] of cases) {
        await t.test(name, () => {
            const pem = pemOf(withExtensions(extensions));
            assert.equal(usagesOf(pem) !== undefined, read, "Node.js reads this value differently");
            const warnings = warningsOf(pem);
            if (read) {
                assert.deepEqual(warnings, []);
                assert.deepEqual(observe(pem).certificates[0].eku, ["serverAuth"]);
            } else {
                assert.deepEqual(warnings.map(({ code, certificate, message }) => [code, certificate, message]), [["EKU_UNRELIABLE", 0, UNDECODABLE_REASON]]);
            }
        });
    }
});

test("an extension repeated is repeated whatever its copies hold: different usages, or one that does not decode", async (t) => {
    const cases = {
        "different usages": [extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(CLIENT_AUTH)],
        "one copy that does not decode": [extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(INTEGER)],
        "both copies that do not decode": [extendedKeyUsage(INTEGER), extendedKeyUsage(INTEGER)],
        "one critical and one not": [extendedKeyUsage(SERVER_AUTH, { critical: true }), extendedKeyUsage(SERVER_AUTH)],
    };
    for (const [name, extensions] of Object.entries(cases)) {
        await t.test(name, () => {
            const pem = pemOf(withExtensions(extensions));
            assert.equal(usagesOf(pem), undefined);
            assert.deepEqual(warningsOf(pem).map(({ message }) => message), [REPEATED_REASON]);
        });
    }
});

test("only the Extended Key Usage is counted: another identifier, even one that starts like it, is not", async (t) => {
    await t.test("2.5.29.38, which nothing defines here", () => {
        const pem = pemOf(withExtensions([extendedKeyUsage(INTEGER, { id: bytes("06 03 55 1d 26") }), extendedKeyUsage(INTEGER, { id: bytes("06 03 55 1d 26") })]));
        assert.equal(usagesOf(pem), undefined);
        assert.deepEqual(warningsOf(pem), []);
    });

    await t.test("2.5.29.37.0, whose identifier has the Extended Key Usage's as its start", () => {
        const pem = pemOf(withExtensions([extendedKeyUsage(INTEGER, { id: bytes("06 04 55 1d 25 00") })]));
        assert.equal(usagesOf(pem), undefined);
        assert.deepEqual(warningsOf(pem), []);
    });

    await t.test("a repeated subjectAltName next to one Extended Key Usage that is read", () => {
        const san = der(0x30, Buffer.concat([bytes("06 03 55 1d 11"), der(0x04, bytes("30 0b 82 09 61 2e 65 78 61 6d 70 6c 65"))]));
        const pem = pemOf(withExtensions([san, extendedKeyUsage(SERVER_AUTH), san]));
        assert.deepEqual(usagesOf(pem), ["1.3.6.1.5.5.7.3.1"]);
        assert.deepEqual(warningsOf(pem), []);
    });
});

test("a certificate can have both warnings: a CA whose Extended Key Usage is repeated and whose basicConstraints is too", () => {
    const basicConstraints = der(0x30, Buffer.concat([bytes("06 03 55 1d 13"), bytes("01 01 ff"), der(0x04, bytes("30 03 01 01 ff"))]));
    const pem = pemOf(withExtensions([basicConstraints, basicConstraints, extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(SERVER_AUTH)]));
    assert.equal(usagesOf(pem), undefined);
    assert.deepEqual(warningsOf(pem).map(({ code, certificate, message }) => [code, certificate, message]), [
        ["KIND_UNRELIABLE", 0, "kind cannot be trusted: basicConstraints appears more than once"],
        ["EKU_UNRELIABLE", 0, REPEATED_REASON],
    ]);
});

// ---------------------------------------------------------------------------------------------
// The limits of the reader

test("a certificate whose extensions cannot be read gets KIND_UNRELIABLE and no second warning from the Extended Key Usage reader", async (t) => {
    await t.test("an indefinite length on the extensions field, around an Extended Key Usage that appears twice", () => {
        const raw = withExtensions([extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(SERVER_AUTH)], { indefinite: true });
        assert.ok(raw.includes(bytes("a3 80 30")), "the extensions field is not the indefinite one");
        const pem = pemOf(raw);
        assert.equal(usagesOf(pem), undefined);
        assert.equal(new X509Certificate(pem).raw.equals(raw), true, "Node.js keeps the bytes as they are");
        assert.deepEqual(warningsOf(pem), [{ code: "KIND_UNRELIABLE", certificate: 0, message: NOT_READ_REASON }]);
    });

    await t.test("a length that runs past the element holding it, or stops short of it", () => {
        const raw = Buffer.from(withExtensions([extendedKeyUsage(SERVER_AUTH), extendedKeyUsage(SERVER_AUTH)]));
        // `a3 2c 30 2a 30 13 <identifier> 04 0c <value>` and then the second extension, counted from the field.
        const field = raw.indexOf(bytes("a3 2c 30 2a 30 13 06 03 55 1d 25"));
        assert.notEqual(field, -1, "the extensions field was not found");
        const lengths = { "the field": field + 1, "the list": field + 3, "the first extension": field + 5, "its value": field + 12 };
        for (const [name, at] of Object.entries(lengths)) {
            for (const change of [1, -1]) {
                const changed = Buffer.from(raw);
                changed[at] += change;
                assert.equal(ekuWarning(changed, undefined, 0), null, `${name} ${change}`);
            }
        }
        assert.notEqual(ekuWarning(raw, undefined, 0), null, "the unchanged certificate must read");
    });

    await t.test("an extension that is not a SEQUENCE of an identifier, an optional flag and an OCTET STRING", () => {
        const notSequence = bytes("04 03 55 1d 25");
        const noValue = der(0x30, EKU_ID);
        const flagLast = der(0x30, Buffer.concat([EKU_ID, der(0x04, bytes(SERVER_AUTH)), bytes("01 01 ff")]));
        for (const extension of [notSequence, noValue, flagLast]) {
            const raw = withExtensions([extendedKeyUsage(SERVER_AUTH), extension, extendedKeyUsage(SERVER_AUTH)]);
            assert.equal(ekuWarning(raw, undefined, 0), null, extension.toString("hex"));
        }
    });
});

test("the Extended Key Usage reader never throws and never guesses: cut anywhere or with any byte changed, it gives no warning or a well-formed one, and the value is never read", async (t) => {
    const raw = rawOf(REPEATED_EKU_EXTENSION);
    /** @param {Uint8Array} input */
    const outcome = (input) => {
        const result = ekuWarning(input, undefined, 3);
        assert.equal(ekuWarning(input, [], 3), null, "Node.js read the usages");
        if (result !== null) {
            assert.equal(result.code, "EKU_UNRELIABLE");
            assert.equal(result.certificate, 3);
            assert.match(result.message, /^eku cannot be trusted: Extended Key Usage (appears more than once|does not decode)$/);
        }
        return result;
    };

    await t.test("every prefix of a certificate is one it cannot read, so it gives no warning", () => {
        for (let length = 0; length < raw.length; length += 1) assert.equal(outcome(raw.subarray(0, length)), null, `${length} bytes`);
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
        for (const text of ["", "30", "3080", "30 80 00 00", "30 85 01 00 00 00 00", "30 84 ff ff ff ff", "30 03 02 01 01", "1f 81 00 00", "30 06 30 04 a3 82 ff ff"]) {
            assert.equal(outcome(bytes(text)), null, text);
        }
    });

    await t.test("what the value holds changes nothing: the extension is counted, not read", () => {
        const value = raw.indexOf(bytes("04 0c 30 0a 06 08"));
        assert.notEqual(value, -1);
        for (let position = value + 2; position < value + 14; position += 1) {
            const changed = Buffer.from(raw);
            changed[position] ^= 0xff;
            assert.equal(outcome(changed)?.message, REPEATED_REASON, `byte ${position - value}`);
        }
    });

    await t.test("a view of a larger buffer is read inside its own bounds", () => {
        const padded = Buffer.concat([Buffer.alloc(16, 0x30), raw, Buffer.alloc(16, 0x30)]);
        assert.notEqual(ekuWarning(padded.subarray(16, 16 + raw.length), undefined, 0), null);
        assert.equal(ekuWarning(padded.subarray(16, 16 + raw.length + 4), undefined, 0), null);
    });
});

// ---------------------------------------------------------------------------------------------
// Today's behaviour that looks wrong and is outside this warning

// The walk that finds the extensions refuses an OCTET STRING that is constructed, which BER allows.
// Node.js reads such a value, `eku` is right and `kind` is too, and the certificate still gets
// KIND_UNRELIABLE, for how another extension is encoded. Neither the walk nor the warning is
// changed by this test; it states what happens.
test("today a certificate whose Extended Key Usage value is a constructed OCTET STRING gets KIND_UNRELIABLE although kind is right, and no EKU_UNRELIABLE because eku is read", () => {
    assert.deepEqual(usagesOf(CONSTRUCTED_EKU_EXTENSION), ["1.3.6.1.5.5.7.3.1"]);
    assert.equal(new X509Certificate(CONSTRUCTED_EKU_EXTENSION).ca, false);
    assert.ok(!rawOf(CONSTRUCTED_EKU_EXTENSION).includes(bytes("06 03 55 1d 13")), "the certificate holds basicConstraints");
    const observation = observe(CONSTRUCTED_EKU_EXTENSION);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.deepEqual(observation.certificates[0].eku, ["serverAuth"]);
    assert.deepEqual(observation.warnings, [{ code: "KIND_UNRELIABLE", certificate: 0, message: NOT_READ_REASON }]);
});

// ---------------------------------------------------------------------------------------------
// Where it is shown

test("inspect and check print EKU_UNRELIABLE with the other warnings, --json carries it, and the verdict of check is unchanged", async () => {
    const expected = `  EKU_UNRELIABLE [0] ${REPEATED_REASON}`;

    const inspected = await runMain(["inspect", "-"], { input: REPEATED_EKU_EXTENSION });
    assert.equal(inspected.code, 0, inspected.stderr);
    const lines = inspected.stdout.split("\n");
    assert.equal(lines[lines.indexOf("Warnings") + 1], expected);

    const json = JSON.parse((await runMain(["inspect", "--json", "-"], { input: REPEATED_EKU_EXTENSION })).stdout);
    assert.deepEqual(json.warnings, [{ code: "EKU_UNRELIABLE", certificate: 0, message: REPEATED_REASON }]);
    assert.deepEqual(errorsOf(json), []);

    const checked = await runMain(["check", "--as-of", "2026-06-01", "--reject-eku", "codeSigning", "-"], { input: REPEATED_EKU_EXTENSION });
    assert.equal(checked.code, 0, checked.stderr);
    const output = checked.stdout.split("\n");
    const heading = output.indexOf("Warnings");
    assert.ok(heading > 0 && output[heading + 1] === expected && output.indexOf("0 failed · exit 0") > heading + 1, checked.stdout);

    const checkedJson = JSON.parse((await runMain(["check", "--json", "--as-of", "2026-06-01", "--reject-eku", "codeSigning", "-"], { input: REPEATED_EKU_EXTENSION })).stdout);
    assert.deepEqual(checkedJson.observation.warnings.map((/** @type {{ code: string }} */ warning) => warning.code), ["EKU_UNRELIABLE"]);
});

test("the README lists EKU_UNRELIABLE with what it means", () => {
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    assert.match(readme, /`eku` is also `null` when the extension is present and Node\.js cannot read it, which happens when it appears more than once or its value does not decode/);
    assert.match(readme, /The observation carries an `EKU_UNRELIABLE` warning for that certificate/);
    assert.match(readme, /`KIND_UNRELIABLE` and `EKU_UNRELIABLE`, follow the results/);
});

test("no certificate in test/fixtures/ gets EKU_UNRELIABLE", () => {
    const names = readdirSync(fixturesUrl).filter((name) => /\.(pem|der)$/.test(name)).sort();
    let count = 0;
    let listed = 0;
    let absent = 0;
    for (const name of names) {
        for (const { certificate, block } of certificatesIn(readFileSync(new URL(name, fixturesUrl)))) {
            count += 1;
            if (certificate.keyUsage === undefined) absent += 1;
            else listed += 1;
            assert.equal(ekuWarning(certificate.raw, certificate.keyUsage, 0), null, `${name}, input block ${block}`);
        }
    }
    assert.ok(count >= 25, `expected the fixtures' certificates, found ${count}`);
    assert.ok(listed > 0 && absent > 0, "the fixtures must hold certificates with and without the extension");
});

/**
 * A certificate in DER as PEM.
 * @param {Buffer} raw
 */
function pemOf(raw) {
    const lines = raw.toString("base64").match(/.{1,64}/g) ?? [];
    return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----", ""].join("\n");
}
