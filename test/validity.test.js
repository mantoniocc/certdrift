import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { inspect, outsideValidity } from "../src/index.js";
import { present } from "../bin/cli.js";

// Every test builds its instants from the dates it is given, so none of them reads the clock, and
// none depends on a fixture's exact bytes: `npm run fixtures` replaces them.

const fixture = (/** @type {string} */ name) => readFileSync(new URL(`fixtures/${name}`, import.meta.url));

const START = "2026-03-01T10:00:00Z";
const END = "2026-06-01T10:00:00Z";

/**
 * An instant as text, moved by whole seconds.
 * @param {string} timestamp
 * @param {number} seconds
 */
function shifted(timestamp, seconds) {
    return new Date(Date.parse(timestamp) + seconds * 1000).toISOString().replace(".000Z", "Z");
}

// A certificate whose notAfter is before its notBefore. Node.js reads it, but OpenSSL will not
// make one (`end date before start date`), so it is a generated certificate with the two date
// fields swapped: notBefore 2030-01-01, notAfter 2020-01-01. Its signature no longer matches, and
// nothing here depends on it.
const INVERTED = `-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUdkBPKOEfnDihc02zc5ukqNRpwmkwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQaW52ZXJ0ZWQuZXhhbXBsZTAeFw0zMDAxMDEwMDAwMDBaFw0y
MDAxMDEwMDAwMDBaMBsxGTAXBgNVBAMMEGludmVydGVkLmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARpOoXpMaCgXclMQ7pnbRKYoxlw+O/zZFhHAbT0
qMKqSOBA9JmNJcFpeG1ihBbUSkwewpcVtTQ9DYUYswrZEPAIo1MwUTAdBgNVHQ4E
FgQUQuQuHUOMw5TOEDdkVaJ1t8q10/owHwYDVR0jBBgwFoAUQuQuHUOMw5TOEDdk
VaJ1t8q10/owDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBXm+zo
AzXn4S9ztKG3tn94K8EUbbAwCMXAuXsKIAZPLwIhAOLqLY41P18JZ1FEm3GP0Gpf
h/Aba4cA+O3xNzLBfYEx
-----END CERTIFICATE-----
`;

test("outsideValidity is reachable from the package entry point and says whether a validity is current, has ended or has not started", () => {
    assert.deepEqual(outsideValidity(START, END, "2026-04-01T00:00:00Z"), []);
    assert.deepEqual(outsideValidity(START, END, "2026-07-01T00:00:00Z"), ["expired"]);
    assert.deepEqual(outsideValidity(START, END, "2026-02-01T00:00:00Z"), ["not yet valid"]);
});

test("an instant equal to notBefore or to notAfter is inside the validity, and one second outside either end is not", () => {
    for (const as of [(/** @type {string} */ text) => text, (/** @type {string} */ text) => new Date(text)]) {
        assert.deepEqual(outsideValidity(as(START), as(END), as(START)), [], "at notBefore");
        assert.deepEqual(outsideValidity(as(START), as(END), as(END)), [], "at notAfter");
        assert.deepEqual(outsideValidity(as(START), as(END), as(shifted(START, -1))), ["not yet valid"], "a second before notBefore");
        assert.deepEqual(outsideValidity(as(START), as(END), as(shifted(END, 1))), ["expired"], "a second after notAfter");
    }
    // A validity that starts and ends in the same second is that one second.
    assert.deepEqual(outsideValidity(START, START, START), []);
    assert.deepEqual(outsideValidity(START, START, shifted(START, 1)), ["expired"]);
    assert.deepEqual(outsideValidity(START, START, shifted(START, -1)), ["not yet valid"]);
});

test("outsideValidity agrees with the definitions of EXPIRED and NOT_YET_VALID, each on its own, over every position of the two dates", () => {
    // EXPIRED: notAfter is before now. NOT_YET_VALID: notBefore is after now. Each date is a second
    // before, at and after the instant, which includes the periods that end before they start.
    const now = "2026-05-05T12:00:00Z";
    const around = [shifted(now, -1), now, shifted(now, 1)];
    for (const notBefore of around) {
        for (const notAfter of around) {
            const found = outsideValidity(notBefore, notAfter, now);
            assert.equal(found.includes("not yet valid"), notBefore > now, `${notBefore} ${notAfter}`);
            assert.equal(found.includes("expired"), notAfter < now, `${notBefore} ${notAfter}`);
            assert.equal(found.length, Number(notBefore > now) + Number(notAfter < now), `${notBefore} ${notAfter}`);
        }
    }
});

test("a validity that ended an hour ago is expired although daysRemaining reads 0, and one that ends in an hour is current", () => {
    const { certificates } = inspect(fixture("leaf-p256.pem"), { at: new Date(0) });
    const { notBefore, notAfter } = certificates[0];
    const after = inspect(fixture("leaf-p256.pem"), { at: new Date(Date.parse(notAfter) + 3_600_000) });
    const before = inspect(fixture("leaf-p256.pem"), { at: new Date(Date.parse(notAfter) - 3_600_000) });
    assert.equal(after.certificates[0].derived.daysRemaining, 0);
    assert.equal(before.certificates[0].derived.daysRemaining, 0);
    assert.deepEqual(outsideValidity(notBefore, notAfter, after.observation.at), ["expired"]);
    assert.deepEqual(outsideValidity(notBefore, notAfter, before.observation.at), []);
    assert.match(present(after, { verbose: false, colour: false }), /\n  remaining   0 days, 100% of the lifetime used \(expired\)\n/);
    assert.match(present(before, { verbose: false, colour: false }), /\n  remaining   0 days, 100% of the lifetime used\n/);
});

test("an instant that is not a valid instant is refused with a TypeError that names the argument, and is never read as current", () => {
    const notTimestamps = [
        // Date.parse moves these to another day or reads them in local time.
        "2026-02-30T00:00:00Z", "2026-04-31T00:00:00Z", "2026-09-15T24:00:00Z", "2026-09-15T23:59:60Z", "2026-13-01T00:00:00Z",
        "2026-09-15T14:02:11", "2026-09-15t14:02:11z", "2026-09-15T14:02:11.000Z", "2026-09-15", "2026-09-15T14:02Z",
        "+002026-09-15T14:02:11Z", " 2026-09-15T14:02:11Z", "2026-09-15T14:02:11Z ", "2026-09-15T14:02:11+00:00", "", "now",
    ];
    const notInstants = [new Date(Number.NaN), 0, 1789480931000, null, undefined, {}, [], true, new String(START), { getTime: () => 0 }];
    for (const bad of [...notTimestamps, ...notInstants]) {
        for (const [position, name] of /** @type {const} */ ([[0, "notBefore"], [1, "notAfter"], [2, "now"]])) {
            const args = /** @type {[any, any, any]} */ ([START, END, "2026-04-01T00:00:00Z"]);
            args[position] = bad;
            assert.throws(() => outsideValidity(...args), (error) => error instanceof TypeError && error.message.startsWith(`${name} must be a valid Date or a timestamp`), `${name}: ${String(bad)}`);
        }
    }
});

test("a Date from another realm or of a subclass is an instant, and one with milliseconds is cut to the whole second like the observation's at", () => {
    const foreign = runInNewContext(`new Date("${END}")`);
    assert.equal(foreign instanceof Date, false);
    assert.deepEqual(outsideValidity(START, END, foreign), []);
    assert.deepEqual(outsideValidity(foreign, foreign, END), []);
    class Later extends Date {}
    assert.deepEqual(outsideValidity(START, END, new Later(Date.parse(END))), []);

    // The instant of a check result has whole seconds, so a Date a fraction past notAfter is the same instant.
    assert.deepEqual(outsideValidity(START, END, new Date(Date.parse(END) + 999)), []);
    assert.deepEqual(outsideValidity(START, END, new Date(Date.parse(END) + 1000)), ["expired"]);
    assert.deepEqual(outsideValidity(new Date(Date.parse(START) + 999), END, START), []);
    assert.deepEqual(outsideValidity(START, END, new Date(Date.parse(START) - 1)), ["not yet valid"]);

    // Before 1970 the cut is toward the earlier second, as `inspect()` cuts `at`: half a second after
    // 23:59:58 is still 23:59:58, which is the end of this period and so inside it. Cutting toward
    // zero would read 23:59:59 and call it expired.
    assert.deepEqual(outsideValidity("1969-12-31T00:00:00Z", "1969-12-31T23:59:58Z", new Date("1969-12-31T23:59:58.500Z")), []);
});

test("a Date whose own getTime answers something else is read by its real time, or refused, and never read as current", () => {
    const now = "2026-04-01T00:00:00Z";
    // The engine's value is the one that counts: these subclasses answer a string, nothing, a
    // number of another instant or an error, and a comparison with a string is false both ways.
    class Text extends Date { getTime() { return /** @type {any} */ ("x"); } }
    class Nothing extends Date { getTime() { return /** @type {any} */ (undefined); } }
    class Elsewhere extends Date { getTime() { return Date.parse("2030-01-01T00:00:00Z"); } }
    class Throws extends Date {
        /** @returns {number} */
        getTime() {
            throw new Error("no");
        }
    }
    for (const Subclass of [Text, Nothing, Elsewhere, Throws]) {
        assert.deepEqual(outsideValidity(START, END, new Subclass(now)), [], Subclass.name);
        assert.deepEqual(outsideValidity(START, END, new Subclass("2026-07-01T00:00:00Z")), ["expired"], Subclass.name);
    }
    // An Invalid Date is refused whatever its subclass says about itself.
    class Claims extends Date { getTime() { return 0; } }
    assert.throws(() => outsideValidity(START, END, new Claims(Number.NaN)), TypeError);
});

test("the years 0000 and 9999 are instants as text, and a Date beyond them is compared", () => {
    assert.deepEqual(outsideValidity("0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", START), []);
    assert.deepEqual(outsideValidity("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z"), ["expired"]);
    assert.deepEqual(outsideValidity("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", "0000-01-01T00:00:00Z"), ["not yet valid"]);
    assert.deepEqual(outsideValidity(START, END, new Date(Date.UTC(10000, 0, 1))), ["expired"]);
    assert.deepEqual(outsideValidity(START, END, new Date(-62198755200000)), ["not yet valid"]);
    assert.throws(() => outsideValidity(START, END, "10000-01-01T00:00:00Z"), TypeError);
    // An expanded year survives the round trip through `toISOString()` and is still not a timestamp
    // of the contract, so only the pattern refuses it. Compared, they would read as expired and as
    // not yet valid.
    for (const text of ["+010000-01-01T00:00:00Z", "-000001-01-01T00:00:00Z"]) {
        assert.throws(() => outsideValidity(START, END, text), (error) => error instanceof TypeError && error.message.startsWith("now must be a valid Date or a timestamp"), text);
    }
});

test("a certificate whose validity ends before it starts is outside it in both ways between its dates, and is labelled with both", () => {
    const [certificate] = inspect(INVERTED, { at: new Date(0) }).certificates;
    assert.equal(certificate.notBefore, "2030-01-01T00:00:00Z");
    assert.equal(certificate.notAfter, "2020-01-01T00:00:00Z");
    const found = (/** @type {string} */ now) => outsideValidity(certificate.notBefore, certificate.notAfter, now);
    assert.deepEqual(found("2025-01-01T00:00:00Z"), ["not yet valid", "expired"]);
    assert.deepEqual(found("2019-01-01T00:00:00Z"), ["not yet valid"]);
    assert.deepEqual(found("2031-01-01T00:00:00Z"), ["expired"]);
    // Each condition is its own rule, so a caller that asks about one gets the answer of that one.
    assert.equal(found("2025-01-01T00:00:00Z").includes("expired"), true);
    assert.equal(found("2025-01-01T00:00:00Z").includes("not yet valid"), true);

    const text = present(inspect(INVERTED, { at: new Date("2025-01-01T00:00:00Z") }), { verbose: false, colour: false });
    assert.match(text, /\n  remaining   -?\d+(\.\d)? days?, no lifetime to measure \(not yet valid, expired\)\n/);
});
