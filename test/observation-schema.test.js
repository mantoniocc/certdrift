import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validateFor } from "./helpers/schema.js";

const examplesUrl = new URL("../schema/examples/observation/", import.meta.url);

/** @param {URL} url */
function readJson(url) {
    return JSON.parse(readFileSync(url, "utf8"));
}

const errorsOf = validateFor("observation");

test("the schema compiles in strict mode", () => {
    assert.equal(typeof errorsOf, "function");
});

const exampleFiles = readdirSync(examplesUrl).filter((name) => name.endsWith(".json")).sort();

test("the examples required by the contract exist", ()=> {
    const required = [
        "file-single.json",
        "file-bundle-chain.json",
        "tls-host.json",
        "external.json",
        "intermediate-only.json",
        "no-eku.json",
        "ip-san.json",
        "ed25519.json",
    ];
    for (const name of required) {
        assert.ok(exampleFiles.includes(name), `missing example ${name}`)
    }
});

for (const name of exampleFiles) {
    test(`example ${name} validates against the schema`, () => {
        assert.deepEqual(errorsOf(readJson(new URL(name, examplesUrl))), []);
    });

    // JSON Schema cannot compare a value with the length or the order of another list,
    // so these rules are checked here to keep the examples honest.
    test(`example ${name} is consistent where the schema cannot tell`, () => {
        const observation = readJson(new URL(name, examplesUrl));
        const count = observation.certificates.length;
        assert.ok(observation.target < count, "target points outside certificates[]");
        observation.certificates.forEach((/** @type {any} */ certificate, /** @type {number} */ position) => {
            assert.equal(certificate.index, position, "index must equal the position in certificates[]");
            const ascending = [...certificate.issuedBy].sort((a, b) => a - b);
            assert.deepEqual(certificate.issuedBy, ascending, "issuedBy must be in ascending order");
            for (const issuer of certificate.issuedBy) {
                assert.ok(issuer < count, "issuedBy points outside certificates[]");
            }
        });
        for (const warning of observation.warnings) {
            if (warning.certificate !== null) {
                assert.ok(warning.certificate < count, "warning points outside certificates[]");
            }
        }
    });
}

/** Every case starts from a fresh copy of a valid example. */
function base() {
    return readJson(new URL("file-single.json", examplesUrl));
}

test("a renamed field fails validation", () => {
    const nested = base();
    nested.certificates[0].expiresAt = nested.certificates[0].notAfter;
    delete nested.certificates[0].notAfter;
    assert.ok(errorsOf(nested).some((e) => e.includes("notAfter")));

    const topLevel = base();
    topLevel.notices = topLevel.warnings;
    delete topLevel.warnings;
    assert.ok(errorsOf(topLevel).some((e) => e.includes("warnings")));
});

test("an extra field passes validation", () => {
    const document = base();
    document.tool = { name: "certdrift", version: "9.9.9" };
    document.observation.source.label = "production";
    document.certificates[0].ocsp = { url: "http://ocsp.example.com" };
    assert.deepEqual(errorsOf(document), []);
});

test("unknown values in open fields pass validation", () => {
    const document = base();
    document.observation.source = { kind: "archive", ref: "backup-2026.tar" };
    document.certificates[0].kind = "attribute-authority";
    document.certificates[0].key.algorithm = "slh-dsa-sha2-128s";
    document.warnings.push({ code: "SOMETHING_NEW", certificate: null, message: "a future warning" });
    assert.deepEqual(errorsOf(document), []);
});

test("an unknown format fails validation", () => {
    const document = base();
    document.format = "mtc";
    assert.ok(errorsOf(document).some((e) => e.startsWith("/format")));
});

test("a different contract version fails validation", () => {
    const document = base();
    document.contract = 2;
    assert.ok(errorsOf(document).some((e) => e.startsWith("/contract")));
});