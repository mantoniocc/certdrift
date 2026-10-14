import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { validatorFor } from "./helpers/schema.js";
import { policyProblems as publicPolicyProblems, EXTENDED_KEY_USAGE_OIDS, inspect } from "../src/index.js";
import { policyProblems, sanItem, ENTRIES, DURATION, DNS_NAME, DNS_NAME_LENGTH, OID, SHA256 } from "../src/policy.js";
import { canonicalAddress } from "../src/san.js";

const errorsOf = validatorFor("policy");
const observationSchema = JSON.parse(readFileSync(new URL("../schema/observation.schema.json", import.meta.url), "utf8"));
const schema = JSON.parse(readFileSync(new URL("../schema/policy.schema.json", import.meta.url), "utf8"));
const examplesUrl = new URL("../schema/examples/policy/", import.meta.url);

/** @param {unknown} policy */
const problemPaths = (policy) => policyProblems(policy).map((problem) => problem.path);

test("policyProblems is part of the package's public API, the one the library and the command share", () => {
    assert.equal(publicPolicyProblems, policyProblems);
});

// ---------------------------------------------------------------------------------------------
// The code and the schema say the same thing about a JSON document

/**
 * The entry a problem is about: the first segment of its path, or `contract` for a missing one.
 * @param {string} path
 */
const entryOf = (path) => (path === "" || path === "/" ? "" : path.split("/")[1]);

/**
 * The entries Ajv finds wrong in a document, by name.
 * @param {unknown} document
 */
function ajvEntries(document) {
    return new Set(
        errorsOf(document).map((error) => {
            const [path, ...rest] = error.split(" ");
            return path === "/" ? /'(\w+)'/.exec(rest.join(" "))?.[1] ?? "" : entryOf(path);
        }),
    );
}

/** @param {unknown} document */
const codeEntries = (document) => new Set(problemPaths(document).map(entryOf));

/** Something wrong, or not, in every position a value can be: JSON values of every type. */
const POOL = [
    null, true, false, 0, 1, -1, 0.5, 1.5, 2, "", " ", "x", "fail", "warn", "info", "error", "FAIL", "Warn", "end-entity", "ca", "30d", "30", "72h", "0d", "1000000d", "999999d",
    "serverAuth", "ServerAuth", "1.3.6.1.5.5.7.3.1", "1.", "a.example.com", "10.0.0.1", "1.2.3", "*.example.com", "ab".repeat(32), "AB".repeat(32),
    [], [""], ["serverAuth"], ["serverAuth", ""], ["a.example.com", "1.2.3"], ["2001:db8::1", "10.0.0.1"], ["ab".repeat(32)], {}, { value: 1 }, { severity: "fail" }, [[]],
];

/** A value each entry accepts, to build a document that is wrong in one place only. */
const VALID_VALUE = /** @type {Record<string, unknown>} */ ({
    expiresWithin: "30d",
    maxLifetimeUsed: 0.5,
    expectEku: ["serverAuth"],
    ekuAllows: ["serverAuth"],
    rejectEku: ["clientAuth"],
    expectSan: ["a.example.com"],
    expectFingerprint: "ab".repeat(32),
    expectKind: "end-entity",
});

/** Every document of the corpus, each wrong (or not) in one place. */
function corpus() {
    /** @type {{ name: string, document: unknown }[]} */
    const documents = [];
    for (const contract of [...POOL, undefined]) documents.push({ name: `contract ${JSON.stringify(contract)}`, document: contract === undefined ? {} : { contract } });
    for (const [entry] of ENTRIES) {
        for (const value of POOL) {
            documents.push({ name: `${entry} is ${JSON.stringify(value)}`, document: { contract: 1, [entry]: value } });
            documents.push({ name: `${entry} has value ${JSON.stringify(value)}`, document: { contract: 1, [entry]: { value } } });
            documents.push({ name: `${entry} has severity ${JSON.stringify(value)}`, document: { contract: 1, [entry]: { ...(entry in VALID_VALUE ? { value: VALID_VALUE[entry] } : {}), severity: value } } });
        }
        documents.push({ name: `${entry} is empty`, document: { contract: 1, [entry]: {} } });
        documents.push({ name: `${entry} is valid`, document: { contract: 1, [entry]: { ...(entry in VALID_VALUE ? { value: VALID_VALUE[entry] } : {}), severity: "warn" } } });
    }
    documents.push({ name: "unknown entry", document: { contract: 1, futureRule: { value: 1 } } });
    documents.push({ name: "unknown property in an entry", document: { contract: 1, expectKind: { value: "end-entity", note: [] } } });
    documents.push({ name: "an array", document: [] });
    documents.push({ name: "null", document: null });
    documents.push({ name: "a string", document: "contract" });
    return documents;
}

test("policyProblems agrees with the schema on whether a policy is valid, over every example and a corpus of wrong values in every position", () => {
    const documents = corpus();
    for (const name of readdirSync(examplesUrl).filter((file) => file.endsWith(".json"))) {
        documents.push({ name: `example ${name}`, document: JSON.parse(readFileSync(new URL(name, examplesUrl), "utf8")) });
    }
    assert.ok(documents.length > 1000, `only ${documents.length} documents`);
    let valid = 0;
    for (const { name, document } of documents) {
        const byCode = policyProblems(document).length === 0;
        const bySchema = errorsOf(document).length === 0;
        assert.equal(byCode, bySchema, `${name}: the code says ${byCode ? "valid" : "invalid"}, the schema ${bySchema ? "valid" : "invalid"}`);
        if (bySchema) valid += 1;
    }
    // The comparison is only worth something if both outcomes are common in it.
    assert.ok(valid > 30 && valid < documents.length - 300, `${valid} valid of ${documents.length}`);
});

test("policyProblems and the schema find the same entry wrong, not only the same verdict", () => {
    for (const { name, document } of corpus()) {
        if (typeof document !== "object" || document === null || Array.isArray(document)) continue;
        assert.deepEqual([...codeEntries(document)].sort(), [...ajvEntries(document)].sort(), name);
    }
});

test("a policy of no entries, with a contract of 1, has no problems", () => {
    assert.deepEqual(policyProblems({ contract: 1 }), []);
    assert.deepEqual(errorsOf({ contract: 1 }), []);
});

test("a policy that is not a JSON object is refused as a whole, and so is one with another contract number", () => {
    for (const value of [null, undefined, 1, "x", true, [], [{ contract: 1 }], () => ({ contract: 1 }), new Map(), new Date(0), 10n]) {
        assert.deepEqual(policyProblems(value), [{ path: "", message: "the policy must be a JSON object" }], String(value));
    }
    assert.deepEqual(policyProblems({}), [{ path: "/contract", message: "is required" }]);
    assert.deepEqual(policyProblems({ contract: 2 }), [{ path: "/contract", message: "contract 2 is not one this version knows: it must be 1" }]);
    assert.deepEqual(policyProblems({ contract: "1" }), [{ path: "/contract", message: "contract is not one this version knows: it must be 1" }]);
    assert.deepEqual(policyProblems({ contract: 1.0 }), []);
    assert.deepEqual(policyProblems({ contract: Object.create(null) }).map((problem) => problem.path), ["/contract"]);
});

test("a policy built without a prototype, or parsed from JSON, is read like any other", () => {
    const bare = Object.assign(Object.create(null), { contract: 1, expectKind: Object.assign(Object.create(null), { value: "end-entity" }) });
    assert.deepEqual(policyProblems(bare), []);
    assert.deepEqual(policyProblems(JSON.parse(readFileSync(new URL("every-rule.json", examplesUrl), "utf8"))), []);
});

test("an object whose prototype is not Object.prototype is not a policy, so an inherited contract is not read", () => {
    assert.deepEqual(policyProblems(Object.create({ contract: 1 })).map((problem) => problem.path), [""]);
    class Policy { contract = 1; }
    assert.deepEqual(policyProblems(new Policy()).map((problem) => problem.path), [""]);
    const inheritedEntry = Object.assign(Object.create({ expectKind: { value: "ca" } }), { contract: 1 });
    assert.deepEqual(policyProblems(inheritedEntry).map((problem) => problem.path), [""]);
    // An own property that only looks inherited is read: entries come from the object itself.
    assert.deepEqual(policyProblems({ contract: 1, toString: { value: 1 }, constructor: 1, hasOwnProperty: null }), []);
});

// ---------------------------------------------------------------------------------------------
// What JSON cannot hold, which the schema cannot see because a JSON document never has it

test("a function, an undefined, a non-finite number, a BigInt, a symbol or a non-plain object is refused at any depth and under any key", () => {
    const cases = /** @type {[string, unknown, string][]} */ ([
        ["a function", () => 1, "a function"],
        ["undefined", undefined, "undefined"],
        ["NaN", Number.NaN, "not a finite number"],
        ["Infinity", Number.POSITIVE_INFINITY, "not a finite number"],
        ["a BigInt", 1n, "a bigint"],
        ["a symbol", Symbol("s"), "a symbol"],
        ["a Date", new Date(0), "not a plain object"],
        ["a Map", new Map(), "not a plain object"],
        ["a class instance", new (class Rule {})(), "not a plain object"],
        ["a typed array", new Uint8Array(1), "not a plain object"],
    ]);
    for (const [name, bad, reason] of cases) {
        for (const [where, build, path] of /** @type {[string, (value: unknown) => unknown, string][]} */ ([
            ["an unknown key", (value) => ({ contract: 1, rule: value }), "/rule"],
            ["an unknown key, nested", (value) => ({ contract: 1, a: { b: [1, { c: value }] } }), "/a/b/1/c"],
            ["a known entry's value", (value) => ({ contract: 1, expectKind: { value } }), "/expectKind/value"],
            ["an unknown property of an entry", (value) => ({ contract: 1, expiresWithin: { value: "1d", own: value } }), "/expiresWithin/own"],
            ["a list of usages", (value) => ({ contract: 1, expectEku: { value: ["serverAuth", value] } }), "/expectEku/value/1"],
        ])) {
            const problems = policyProblems(build(bad));
            assert.ok(problems.some((problem) => problem.path === path && problem.message.includes(reason)), `${name} in ${where}: ${JSON.stringify(problems)}`);
        }
    }
});

test("a function put in a policy for an own rule is refused, while the schema, which only ever sees JSON, would let the document through", () => {
    const policy = { contract: 1, tlsVersion: () => true };
    assert.deepEqual(policyProblems(policy), [{ path: "/tlsVersion", message: "is a function, which JSON cannot hold" }]);
    // Ajv accepts it: this is the one place the two differ, on purpose. JSON.stringify would drop it.
    assert.deepEqual(errorsOf(policy), []);
    assert.equal(JSON.stringify(policy), '{"contract":1}');
});

test("an accessor is a problem and is never called", () => {
    let calls = 0;
    const getter = (/** @type {unknown} */ value) => ({ enumerable: true, get() { calls += 1; return value; } });

    const policy = { contract: 1 };
    Object.defineProperties(policy, { expectKind: getter({ value: "end-entity" }), extra: getter(1) });
    assert.deepEqual(policyProblems(policy).map((problem) => problem.path), ["/expectKind", "/extra"]);
    assert.ok(policyProblems(policy).every((problem) => problem.message.includes("accessor")));

    const entry = { value: "end-entity" };
    Object.defineProperty(entry, "severity", getter("warn"));
    const values = Object.defineProperty({}, "value", getter(["serverAuth"]));
    const nested = { contract: 1, nested: { entry }, expectEku: values };
    const problems = policyProblems(nested);
    assert.ok(problems.some((problem) => problem.path === "/nested/entry/severity" && problem.message.includes("accessor")));
    assert.ok(problems.some((problem) => problem.path === "/expectEku/value"), "a value behind an accessor is a problem, and is not read");
    assert.equal(calls, 0, "no accessor was called");
});

test("a policy that contains itself is refused, and one that repeats a value is not", () => {
    const cyclic = /** @type {any} */ ({ contract: 1, a: { b: [] } });
    cyclic.a.b.push(cyclic.a);
    assert.deepEqual(policyProblems(cyclic), [{ path: "/a/b/0", message: "contains itself, which JSON cannot hold" }]);

    const shared = { value: ["serverAuth"] };
    assert.deepEqual(policyProblems({ contract: 1, expectEku: shared, ekuAllows: shared, other: { again: shared, twice: shared } }), []);

    const root = /** @type {any} */ ({ contract: 1 });
    root.self = root;
    assert.deepEqual(policyProblems(root), [{ path: "/self", message: "contains itself, which JSON cannot hold" }]);
});

test("a list with a gap is refused, because JSON has no holes", () => {
    // eslint-disable-next-line no-sparse-arrays
    const gap = [1, , 3];
    assert.deepEqual(policyProblems({ contract: 1, x: gap }), [{ path: "/x/1", message: "is missing from a list that has a gap here" }]);
    assert.deepEqual(policyProblems({ contract: 1, expectEku: { value: new Array(2) } }).map((problem) => problem.path).includes("/expectEku/value"), true);
});

test("an object that throws when it is read is a problem, not an exception", () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    assert.deepEqual(policyProblems(proxy), [{ path: "", message: "the policy cannot be read as a JSON object" }]);
    assert.deepEqual(policyProblems({ contract: 1, nested: proxy }), [{ path: "", message: "the policy cannot be read as a JSON object" }]);
    const hostile = new Proxy({ contract: 1 }, { getPrototypeOf() { throw new Error("no"); } });
    assert.deepEqual(policyProblems(hostile).map((problem) => problem.path), [""]);
});

test("nesting far deeper than the call stack is read without an exception, and a bad value at the bottom is found", () => {
    /** @type {unknown} */
    let deep = [];
    for (let level = 0; level < 200_000; level += 1) deep = [deep];
    assert.deepEqual(policyProblems({ contract: 1, anything: deep }), []);
    assert.throws(() => { const walk = (/** @type {any} */ value) => (Array.isArray(value) ? value.forEach(walk) : 0); walk(deep); }, RangeError, "a recursive walk does not survive this depth");

    /** @type {unknown} */
    let object = () => 1;
    for (let level = 0; level < 200_000; level += 1) object = { a: object };
    const problems = policyProblems({ contract: 1, anything: object });
    assert.equal(problems.length, 1);
    assert.equal(problems[0].path, `/anything${"/a".repeat(200_000)}`);
});

test("at most 100 problems from values JSON cannot hold are listed, so a hostile policy cannot make a long answer", () => {
    const many = Object.fromEntries(Array.from({ length: 5000 }, (_, index) => [`rule${index}`, () => index]));
    const problems = policyProblems({ contract: 1, ...many });
    assert.equal(problems.length, 100);
    assert.equal(new Set(problems.map((problem) => problem.path)).size, 100);
});

test("the same policy gives the same problems whatever order it was built in", () => {
    const one = { contract: 1, b: () => 1, a: () => 2, expectKind: { value: "ca", severity: "no" }, expiresWithin: { value: "1" } };
    const other = { expiresWithin: { value: "1" }, expectKind: { severity: "no", value: "ca" }, a: () => 2, b: () => 1, contract: 1 };
    assert.deepEqual(policyProblems(other), policyProblems(one));
});

test("problem paths are JSON Pointers: a key with a slash or a tilde is escaped", () => {
    assert.deepEqual(problemPaths({ contract: 1, "a/b": { "c~d": () => 1 } }), ["/a~1b/c~0d"]);
    assert.deepEqual(problemPaths({ contract: 1, "": () => 1 }), ["/"]);
});

test("a problem never quotes a value of the policy, since a value in the wrong place may be a secret", () => {
    const secret = "hunter2-correct-horse";
    const policy = {
        contract: secret,
        expiresWithin: { value: secret, severity: secret },
        maxLifetimeUsed: { value: secret },
        expectEku: { value: [secret] },
        ekuAllows: { value: [secret, "serverAuth"] },
        rejectEku: secret,
        expectSan: { value: [secret + " space"] },
        expectFingerprint: { value: secret },
        expectKind: { value: secret },
        matchesPrivateKey: { severity: secret, passphrase: secret },
        unknown: { deep: [secret, () => secret] },
    };
    const problems = policyProblems(policy);
    assert.ok(problems.length >= 10, `${problems.length} problems`);
    assert.doesNotMatch(JSON.stringify(problems), new RegExp(secret));
    // A number is the one value quoted, because "contract 2" is what a reader needs to see.
    assert.match(policyProblems({ contract: 7 })[0].message, /contract 7 /);
});

test("a key, a passphrase or any other property in matchesPrivateKey is tolerated by both checks, and policyProblems does not touch the policy", () => {
    const policy = Object.freeze({
        contract: 1,
        matchesPrivateKey: Object.freeze({
            severity: "warn",
            key: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            passphrase: "hunter2",
            nested: Object.freeze({ keyFile: "/etc/ssl/private/key.pem" }),
        }),
        misspelledEntry: Object.freeze({ value: ["serverAuth"] }),
    });
    const before = JSON.stringify(policy);
    assert.deepEqual(policyProblems(policy), []);
    assert.deepEqual(errorsOf(JSON.parse(before)), []);
    assert.equal(JSON.stringify(policy), before);
});

test("today an entry with a misspelled name is tolerated by both checks, so it checks nothing", () => {
    // Not the rule: the contract tolerates what it does not know, which also means a typo is not
    // an error. Evaluating a policy with nothing else in it gives the POLICY_EMPTY warning.
    for (const entry of ["expectSAN", "expect_san", "ExpectSan", "expectsan"]) {
        const policy = { contract: 1, [entry]: { value: ["a.example.com"] } };
        assert.deepEqual(policyProblems(policy), [], entry);
        assert.deepEqual(errorsOf(policy), [], entry);
    }
});

test("an own __proto__ key from JSON.parse is an unknown property, not the prototype", () => {
    const parsed = JSON.parse('{"contract":1,"__proto__":{"expectKind":{"value":"ca"}},"expectKind":{"value":"end-entity"}}');
    assert.deepEqual(policyProblems(parsed), []);
    assert.deepEqual(errorsOf(parsed), []);
    assert.deepEqual(problemPaths(JSON.parse('{"contract":1,"__proto__":{"a":1},"expiresWithin":{"value":"x"}}')), ["/expiresWithin/value"]);
    assert.equal(/** @type {any} */ ({}).expectKind, undefined);
    assert.deepEqual(problemPaths(JSON.parse('{"contract":1,"expectKind":{"__proto__":{"value":"end-entity"}}}')), ["/expectKind/value"]);
});

test("a very long string is refused in the time of a short one", () => {
    const long = "a".repeat(2_000_000);
    const started = performance.now();
    assert.equal(sanItem(long), null);
    assert.equal(sanItem(`${"a.".repeat(100_000)}1`), null);
    assert.equal(policyProblems({ contract: 1, expectSan: { value: [long, `${long}.`] }, expiresWithin: { value: long }, expectFingerprint: { value: long } }).length, 3);
    assert.ok(errorsOf({ contract: 1, expectSan: { value: [long] } }).length > 0);
    assert.ok(performance.now() - started < 1000, "refusing long strings took a second");
});

// ---------------------------------------------------------------------------------------------
// The patterns the code and the schema share are the same text

test("the code's patterns are the schema's, character for character", () => {
    assert.equal(schema.properties.expiresWithin.properties.value.pattern, DURATION.source);
    assert.equal(observationSchema.$defs.sha256.pattern, SHA256.source);
    assert.equal(schema.properties.expectSan.properties.value.items.anyOf[1].pattern, DNS_NAME.source);
    assert.equal(schema.properties.expectSan.properties.value.items.maxLength, DNS_NAME_LENGTH);
    const names = Object.keys(EXTENDED_KEY_USAGE_OIDS).join("|");
    assert.equal(schema.$defs.usages.items.pattern, `^(?:${names}|${OID.source.slice(1, -1)})$`);
});

test("the six names the schema accepts are the six the observation uses", () => {
    assert.deepEqual(
        schema.$defs.usages.items.pattern.match(/^\^\(\?:([A-Za-z|]+)\|/)[1].split("|"),
        Object.keys(EXTENDED_KEY_USAGE_OIDS),
    );
    assert.deepEqual(Object.keys(EXTENDED_KEY_USAGE_OIDS), ["serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "OCSPSigning"]);
});

// ---------------------------------------------------------------------------------------------
// expectSan: what is an IP address, what is a name and what is refused

/** The two patterns of the schema for an item, and the length it allows. */
const [IP_PATTERN, DNS_PATTERN] = schema.properties.expectSan.properties.value.items.anyOf.map((/** @type {{ pattern: string }} */ branch) => new RegExp(branch.pattern, "u"));
const SAN_LENGTH = schema.properties.expectSan.properties.value.items.maxLength;

/**
 * How the schema reads an item: an address, a name, or nothing.
 * @param {string} text
 */
function schemaKind(text) {
    const ip = IP_PATTERN.test(text);
    const dns = text.length <= SAN_LENGTH && DNS_PATTERN.test(text);
    assert.ok(!(ip && dns), `${JSON.stringify(text)} is read as an address and as a name`);
    return ip ? "ip" : dns ? "dns" : "refused";
}

/** @param {string} text */
const codeKind = (text) => policyProblems({ contract: 1, expectSan: { value: [text] } }).length > 0 ? "refused" : (sanItem(text)?.kind ?? "refused");

/** @param {string} text */
const addressKind = (text) => (canonicalAddress(text) !== null ? "ip" : null);

/** Every spelling the corpus tries and what each is: an address (compared canonical), a name, or refused. */
const SPELLINGS = /** @type {[string, "ip" | "dns" | "refused", string?][]} */ ([
    // IPv4
    ["10.0.0.1", "ip", "10.0.0.1"], ["0.0.0.0", "ip", "0.0.0.0"], ["255.255.255.255", "ip", "255.255.255.255"], ["192.0.2.10", "ip", "192.0.2.10"],
    ["010.0.0.1", "refused"], ["10.0.0.01", "refused"], ["00.0.0.1", "refused"], ["256.0.0.1", "refused"], ["10.0.0", "refused"], ["10.0.0.1.1", "refused"],
    ["10.0.0.1.", "refused"], [".10.0.0.1", "refused"], ["10.0.0.-1", "refused"], ["1.2.3", "refused"], ["127.1", "refused"], ["0x7f.0.0.1", "refused"],
    ["2130706433", "refused"], ["0177.0.0.1", "refused"], [" 10.0.0.1", "refused"], ["10.0.0.1 ", "refused"], ["10.0.0.1\n", "refused"], ["10.0.0.1/24", "refused"],
    ["10.0.0.1:443", "refused"], ["１０.0.0.1", "refused"],
    // IPv6
    ["2001:db8::1", "ip", "2001:db8::1"], ["2001:DB8::1", "ip", "2001:db8::1"], ["2001:0db8:0000:0000:0000:0000:0000:0001", "ip", "2001:db8::1"],
    ["2001:db8:0:0:0:0:0:1", "ip", "2001:db8::1"], ["::", "ip", "::"], ["::1", "ip", "::1"], ["1::", "ip", "1::"], ["::ffff:192.0.2.1", "ip", "::ffff:c000:201"],
    ["::FFFF:C000:201", "ip", "::ffff:c000:201"], ["64:ff9b::192.0.2.33", "ip", "64:ff9b::c000:221"], ["fe80::1", "ip", "fe80::1"],
    ["1:2:3:4:5:6:7:8", "ip", "1:2:3:4:5:6:7:8"], ["1:2:3:4:5:6:1.2.3.4", "ip", "1:2:3:4:5:6:102:304"], ["1:0:0:2:0:0:0:3", "ip", "1:0:0:2::3"],
    ["fe80::1%eth0", "refused"], ["fe80::1%25eth0", "refused"], ["fe80::1%", "refused"], ["[::1]", "refused"], ["::1/128", "refused"], [":::", "refused"], [":1", "refused"],
    ["1:2:3:4:5:6:7:8:9", "refused"], ["1:2:3:4:5:6:7", "refused"], ["1::2::3", "refused"], ["12345::1", "refused"], ["g::1", "refused"], ["::1.2.3", "refused"],
    ["1.2.3.4::", "refused"], ["::1.2.3.4:1", "refused"], ["1:2:3:4:5:6:7:8::", "refused"], ["::ffff:010.0.0.1", "refused"], ["::ffff:256.0.0.1", "refused"],
    // Names
    ["a.example.com", "dns", "a.example.com"], ["A.Example.COM", "dns", "a.example.com"], ["example", "dns", "example"], ["a-b.example", "dns", "a-b.example"],
    ["_dmarc.example.com", "dns", "_dmarc.example.com"], ["xn--bcher-kva.example", "dns", "xn--bcher-kva.example"], ["a.1b", "dns", "a.1b"], ["a.b1", "dns", "a.b1"],
    ["1.example", "dns", "1.example"], ["10.0.0.example", "dns", "10.0.0.example"], ["a.1e1", "dns", "a.1e1"], ["a.0xz", "dns", "a.0xz"], ["a".repeat(63) + ".example", "dns", "a".repeat(63) + ".example"],
    ["*.example.com", "dns", "*.example.com"], ["*.EXAMPLE.com", "dns", "*.example.com"], ["*.a.example.com", "dns", "*.a.example.com"], ["*.example", "dns", "*.example"],
    ["*", "refused"], ["*.", "refused"], ["a.*.example.com", "refused"], ["*.*.example.com", "refused"], ["**.example.com", "refused"], ["*a.example.com", "refused"], ["a*.example.com", "refused"],
    ["*example.com", "refused"], [".*.example.com", "refused"], ["*.1", "refused"], ["*.0x7f", "refused"],
    ["example.com.", "refused"], [".example.com", "refused"], ["a..example.com", "refused"], ["-a.example.com", "refused"], ["a-.example.com", "refused"], ["a b.example.com", "refused"],
    ["", "refused"], [" ", "refused"], ["a.example.com ", "refused"], [" a.example.com", "refused"], ["a.example.com\n", "refused"], ["a.example.com\u0000", "refused"],
    ["a@example.com", "refused"], ["https://a.example.com", "refused"], ["a.example.com:443", "refused"], ["a.example.com/x", "refused"], ["bücher.example", "refused"],
    ["a.example.com​", "refused"], ["ａ.example.com", "refused"], ["1", "refused"], ["0x7f", "refused"], ["0x", "refused"], ["0X1F", "refused"], ["1234567890", "refused"], ["a.1", "refused"],
    ["a.0x", "refused"], ["a.0XFF", "refused"], ["localhost.1", "refused"], ["a".repeat(64) + ".example", "refused"], [`${"a.".repeat(126)}a`, "dns", `${"a.".repeat(126)}a`], [`${"a.".repeat(126)}ab`, "refused"],
]);

test("every spelling is read the same by the schema's patterns, by policyProblems and by canonicalAddress: an address, a name or refused", () => {
    assert.ok(SPELLINGS.length > 100, `${SPELLINGS.length} spellings`);
    for (const [text, kind, name] of SPELLINGS) {
        const label = JSON.stringify(text.length > 40 ? `${text.slice(0, 40)}…(${text.length})` : text);
        assert.equal(schemaKind(text), kind, `schema: ${label}`);
        assert.equal(codeKind(text), kind, `policyProblems: ${label}`);
        // Whatever is an address for the schema is one for canonicalAddress, and the other way round.
        assert.equal(addressKind(text) === "ip", kind === "ip", `canonicalAddress: ${label}`);
        assert.equal(sanItem(text)?.name, name, `compared as: ${label}`);
        assert.equal(sanItem(text)?.kind ?? "refused", kind, `sanItem: ${label}`);
        assert.equal(errorsOf({ contract: 1, expectSan: { value: [text] } }).length === 0, kind !== "refused", `Ajv: ${label}`);
    }
});

test("the spellings cover addresses, names and refusals, and an address is always compared in the form the observation writes", () => {
    const kinds = new Set(SPELLINGS.map(([, kind]) => kind));
    assert.deepEqual([...kinds].sort(), ["dns", "ip", "refused"]);
    for (const [text, kind, name] of SPELLINGS) if (kind === "ip") assert.equal(canonicalAddress(/** @type {string} */ (name)), name, `${text} is compared as ${name}, which is already canonical`);
});

test("a name whose last label is a number is refused, as the host of a connection is, so it is not a name that could never be listed", () => {
    for (const text of ["010.0.0.1", "1.2.3", "256.0.0.1", "example.1", "example.0x1F", "123"]) assert.equal(sanItem(text), null, text);
    assert.equal(sanItem("example.1a")?.kind, "dns");
});

test("a wildcard is compared as written: *.example.com is one name, not a pattern that a.example.com satisfies", () => {
    assert.deepEqual(sanItem("*.Example.com"), { kind: "dns", name: "*.example.com" });
    assert.notEqual(sanItem("*.example.com")?.name, sanItem("a.example.com")?.name);
});

/** Every name the certificates among the fixtures list, with the file it is in. */
function listedNames() {
    const fixtures = new URL("fixtures/", import.meta.url);
    /** @type {{ kind: "dns" | "ip", name: string, file: string }[]} */
    const names = [];
    for (const file of readdirSync(fixtures).filter((name) => /\.(pem|der)$/.test(name)).sort()) {
        let observation;
        try {
            observation = inspect(readFileSync(new URL(file, fixtures)), { at: new Date("2026-09-15T14:02:11Z") });
        } catch {
            continue; // A bundle with two possible targets has no observation.
        }
        for (const certificate of observation.certificates) {
            for (const name of certificate.san.dns) names.push({ kind: "dns", name, file });
            for (const name of certificate.san.ip) names.push({ kind: "ip", name, file });
        }
    }
    return names;
}

test("every address and every host name a fixture lists can be expected as it is listed", () => {
    const names = listedNames();
    assert.ok(names.filter((found) => found.kind === "dns").length > 20 && names.some((found) => found.kind === "ip"), `${names.length} names`);
    for (const { kind, name, file } of names) {
        if (kind === "dns" && /[^A-Za-z0-9._*-]/.test(name)) continue; // Not a host name, see the next test.
        assert.deepEqual(sanItem(name), { kind, name }, `${name} in ${file}`);
        assert.deepEqual(policyProblems({ contract: 1, expectSan: { value: [name] } }), [], `${name} in ${file}`);
        assert.deepEqual(errorsOf({ contract: 1, expectSan: { value: [name] } }), [], `${name} in ${file}`);
    }
    // The upper case spelling of a listed name is the same expectation.
    for (const { kind, name } of names.filter((found) => found.kind === "dns" && /^[a-z0-9.-]+$/.test(found.name))) {
        assert.equal(sanItem(name.toUpperCase())?.name, name);
    }
    assert.equal(sanItem("2001:DB8::1")?.name, names.find((found) => found.kind === "ip" && found.name.startsWith("2001:"))?.name);
});

// Today's behaviour, not the rule: a certificate can list a DNS entry that is not a host name
// (the fixtures list one with a comma and one with a quote), and expectSan, which accepts only
// what a connection could be made to, has no way to ask for it.
test("today a DNS entry that is not a host name, as a certificate may list one, cannot be expected", () => {
    const odd = listedNames().filter((found) => found.kind === "dns" && /[^A-Za-z0-9._*-]/.test(found.name));
    assert.deepEqual(odd.map((found) => found.name).sort(), ['a, b.example', 'q"uote.example']);
    for (const { name } of odd) {
        assert.equal(sanItem(name), null, name);
        assert.deepEqual(problemPaths({ contract: 1, expectSan: { value: [name] } }), ["/expectSan/value"], name);
    }
});

/**
 * A deterministic sequence of numbers: the corpus must be the same on every run.
 * @param {number} seed
 */
function random(seed) {
    let state = seed;
    return () => {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        return state / 2 ** 32;
    };
}

test("the schema's address pattern and canonicalAddress agree on every structured spelling and on random ones", () => {
    let checked = 0;
    /** @param {string} text */
    const agree = (text) => {
        checked += 1;
        assert.equal(IP_PATTERN.test(text), canonicalAddress(text) !== null, JSON.stringify(text));
    };

    // Every way to write up to six groups, each a short group, a full one, an IPv4 tail or nothing,
    // with `::` at every position, and without.
    /** @param {number} length @returns {Generator<string[]>} */
    function* sequences(length) {
        if (length === 0) { yield []; return; }
        for (const rest of sequences(length - 1)) for (const piece of ["0", "ffff", "1.2.3.4", ""]) yield [...rest, piece];
    }
    for (let length = 0; length <= 5; length += 1) {
        for (const sequence of sequences(length)) {
            agree(sequence.join(":"));
            for (let at = 0; at <= sequence.length; at += 1) agree([...sequence.slice(0, at), "", ...sequence.slice(at)].join(":"));
        }
    }
    // Every count of groups on either side of `::`, with and without a tail, up to past the limit.
    for (let left = 0; left <= 9; left += 1) {
        for (let right = 0; right <= 9; right += 1) {
            for (const tail of ["", "1.2.3.4"]) {
                const before = Array(left).fill("a").join(":");
                const after = [...Array(right).fill("b"), ...(tail === "" ? [] : [tail])].join(":");
                agree(`${before}::${after}`);
                agree(`${before}:${after}`);
            }
        }
    }
    // Random strings from the alphabet of addresses, and addresses with one character changed.
    const next = random(1);
    const alphabet = "0123456789abcdefABCDEF:.:.:g%/ ";
    for (let index = 0; index < 20_000; index += 1) {
        const length = 1 + Math.floor(next() * 24);
        agree(Array.from({ length }, () => alphabet[Math.floor(next() * alphabet.length)]).join(""));
    }
    const seeds = ["2001:db8::1", "::ffff:192.0.2.1", "1:2:3:4:5:6:7:8", "10.0.0.1", "::", "1:2:3:4:5:6:1.2.3.4", "fe80::1"];
    for (let index = 0; index < 5000; index += 1) {
        const seed = seeds[index % seeds.length];
        const at = Math.floor(next() * (seed.length + 1));
        agree(seed.slice(0, at) + alphabet[Math.floor(next() * alphabet.length)] + seed.slice(at + (index % 2)));
    }
    assert.ok(checked > 30_000, `${checked} spellings`);
});

// ---------------------------------------------------------------------------------------------
// The production code has no validator

/** Every JavaScript file under a directory, as a repository-relative path. */
const sources = (/** @type {string} */ directory) =>
    readdirSync(new URL(`../${directory}/`, import.meta.url), { recursive: true, encoding: "utf8" })
        .filter((path) => /\.[cm]?js$/.test(path))
        .map((path) => `${directory}/${path}`);

test("nothing in src/ or bin/ imports a JSON Schema validator, and the package has no production dependency", () => {
    const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(manifest.dependencies, undefined);
    assert.equal(manifest.peerDependencies, undefined);
    assert.equal(manifest.optionalDependencies, undefined);
    assert.ok("ajv" in manifest.devDependencies, "Ajv is a development dependency, which the tests use");

    const files = [...sources("src"), ...sources("bin")];
    assert.ok(files.includes("src/policy.js") && files.includes("bin/cli.js"), files.join(", "));
    const validators = /["'`](?:ajv|ajv\/[^"'`]*|@cfworker\/json-schema|jsonschema|json-schema|is-my-json-valid|z-schema|tv4|djv|@hyperjump\/json-schema|zod|yup|joi)["'`]/;
    for (const path of files) {
        assert.doesNotMatch(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"), validators, `${path} imports a validator`);
    }
});
