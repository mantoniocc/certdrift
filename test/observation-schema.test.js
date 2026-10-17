import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validatorFor } from "./helpers/schema.js";

const examplesUrl = new URL("../schema/examples/observation/", import.meta.url);

/** @param {URL} url */
function readJson(url) {
    return JSON.parse(readFileSync(url, "utf8"));
}

const errorsOf = validatorFor("observation");

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
        "kind-unreliable.json",
        "eku-unreliable.json",
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

const schema = readJson(new URL("../schema/observation.schema.json", import.meta.url));

test("the description of kind says ca needs basicConstraints marking a CA and keyCertSign when Key Usage is present, that anything else is end-entity, and that keyCertSign is the bit that allows a key to sign certificates", () => {
    const { description } = schema.$defs.certificate.properties.kind;
    assert.match(description, /\bca\b[^;]*basicConstraints marks the certificate as a CA/);
    assert.match(description, /if a Key Usage extension is present, it includes keyCertSign/);
    assert.match(description, /keyCertSign, the bit that allows a key to sign certificates/);
    assert.match(description, /end-entity for anything else/);
    assert.match(description, /marked as a CA whose Key Usage lacks keyCertSign/);
});

test("kind keeps its name, type and place among the required fields, and the contract stays 1", () => {
    const { description, ...kind } = schema.$defs.certificate.properties.kind;
    assert.equal(typeof description, "string");
    assert.deepEqual(kind, { type: "string", minLength: 1 });
    assert.ok(schema.$defs.certificate.required.includes("kind"));
    assert.equal(schema.properties.contract.const, 1);
});

test("the schema lists KIND_UNRELIABLE among the warning codes, says it comes after the others by certificate index, and an example carries it and validates", () => {
    const { description: code } = schema.$defs.warning.properties.code;
    assert.match(code, /Known values: DUPLICATE_CERTIFICATE, SAN_TYPE_UNREPRESENTED, KIND_UNRELIABLE, EKU_UNRELIABLE\./);
    assert.match(code, /KIND_UNRELIABLE, at most one per certificate/);
    assert.match(code, /kind keeps the value Node\.js gives/);
    assert.match(code, /never quotes a value from the certificate/);

    const { description: order } = schema.properties.warnings;
    assert.match(order, /first DUPLICATE_CERTIFICATE, in input order; then SAN_TYPE_UNREPRESENTED, by certificate index/);
    assert.match(order, /then KIND_UNRELIABLE, by certificate index/);

    const example = readJson(new URL("kind-unreliable.json", examplesUrl));
    assert.deepEqual(errorsOf(example), []);
    assert.deepEqual(example.warnings.map((/** @type {{ code: string }} */ warning) => warning.code), ["KIND_UNRELIABLE"]);
    assert.equal(example.certificates[example.warnings[0].certificate].kind, "end-entity");
});

test("adding the KIND_UNRELIABLE warning keeps the contract at 1 and the shape of a warning", () => {
    assert.equal(schema.properties.contract.const, 1);
    assert.deepEqual(schema.$defs.warning.required, ["code", "certificate", "message"]);
    assert.equal(schema.$defs.warning.properties.code.pattern, "^[A-Z][A-Z0-9_]*$");
});

test("the schema lists EKU_UNRELIABLE among the warning codes, says it comes after KIND_UNRELIABLE by certificate index, and an example carries it and validates", () => {
    const { description: code } = schema.$defs.warning.properties.code;
    assert.match(code, /EKU_UNRELIABLE, at most one per certificate: eku cannot be trusted for it/);
    assert.match(code, /appears more than once, or one whose value does not decode/);
    assert.match(code, /eku keeps the value Node\.js gives/);
    assert.match(code, /gets KIND_UNRELIABLE and no EKU_UNRELIABLE, and a certificate can have both/);
    assert.match(code, /never quotes a value from the certificate/);

    const { description: order } = schema.properties.warnings;
    assert.match(order, /then KIND_UNRELIABLE, by certificate index; then EKU_UNRELIABLE, by certificate index\./);

    const example = readJson(new URL("eku-unreliable.json", examplesUrl));
    assert.deepEqual(errorsOf(example), []);
    assert.deepEqual(example.warnings.map((/** @type {{ code: string }} */ warning) => warning.code), ["EKU_UNRELIABLE"]);
    assert.equal(example.certificates[example.warnings[0].certificate].eku, null);
});

test("adding the EKU_UNRELIABLE warning keeps the contract at 1, the shape of a warning and the description of eku", () => {
    assert.equal(schema.properties.contract.const, 1);
    assert.deepEqual(schema.$defs.warning.required, ["code", "certificate", "message"]);
    assert.equal(schema.$defs.warning.properties.code.pattern, "^[A-Z][A-Z0-9_]*$");
    assert.deepEqual(schema.$defs.certificate.properties.eku.type, ["array", "null"]);
});
