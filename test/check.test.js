import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { entryOfCode, evaluate, inspect, serializeCheckResult } from "../src/index.js";
import { CHECK_OPTIONS, exitOf, nowOf, presentCheck } from "../bin/check.js";
import { CWD, fixture, run, runMain, targetOf, typed } from "./helpers/command.js";
import { validatorFor } from "./helpers/schema.js";

// The command is run as a child process, the way a person runs it. It always evaluates at the real
// current time unless --as-of says otherwise, and the fixtures' validity dates move with the day
// `npm run fixtures` ran, so no assertion here depends on the clock: an exit code is shown with an
// instant taken from the fixture's own dates, with a fixture whose dates are fixed in the past, or
// with the two validity rules made warnings and a rule every fixture passes.

const errorsOf = validatorFor("check-result");
const ESC = String.fromCharCode(27);
const COLOUR = new RegExp(`${ESC}\\[[0-9;]*m`, "g");
const policyUrl = (/** @type {string} */ name) => new URL(`../schema/examples/policy/${name}.json`, import.meta.url);
const policyPath = (/** @type {string} */ name) => `schema/examples/policy/${name}.json`;

/**
 * Two rules every fixture passes at any date once the validity rules cannot fail the check.
 * Nothing in the fixtures lists code signing.
 */
const ALWAYS_PASSES = ["--warn-only", "EXPIRED", "--warn-only", "NOT_YET_VALID", "--reject-eku", "codeSigning"];

/** @param {string[]} args @param {import("./helpers/command.js").RunOptions} [options] */
const check = (args, options) => run(["check", ...args], options);

/** The JSON a run printed, which must be the whole of standard output. @param {import("./helpers/command.js").Result} result */
function jsonOf(result) {
    assert.equal(result.stderr, "", result.stderr);
    return JSON.parse(result.stdout);
}

/** The instant at which a fixture's target has started and not ended. @param {string} name */
const startOf = (name) => targetOf(name).certificate.notBefore;

/** @param {string} instant @param {number} seconds */
function shifted(instant, seconds) {
    return new Date(Date.parse(instant) + seconds * 1000).toISOString().replace(".000Z", "Z");
}

/** @param {import("node:test").TestContext} t */
function scratch(t) {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    return dir;
}

/** The part of a check result that does not depend on the clock. @param {any} printed */
function withoutObservation(printed) {
    const { observation: _observation, ...rest } = printed;
    return rest;
}

/**
 * What the library says for a fixture, a policy and an instant, as the command prints it.
 * @param {string} name
 * @param {unknown} policy
 * @param {string} now
 */
function expectedFor(name, policy, now) {
    const { select } = targetOf(name);
    const observation = select.length > 0 ? inspect(fixture(name), { select: select[1] }) : inspect(fixture(name));
    return withoutObservation(JSON.parse(serializeCheckResult(evaluate(observation, /** @type {any} */ (policy), { now }))));
}

// ---------------------------------------------------------------------------------------------
// Reading the material and the options

test("check reads a PEM file, a DER file and standard input (-) as inspect does and prints one line per rule", async () => {
    const start = startOf("leaf-p256.pem");
    const args = ["--as-of", start, "--reject-eku", "codeSigning"];
    const sha256 = inspect(fixture("leaf-p256.pem")).certificates[0].sha256;

    for (const [how, result] of /** @type {[string, import("./helpers/command.js").Result][]} */ ([
        ["a PEM file", await check(["--json", ...args, typed("leaf-p256.pem")])],
        ["a DER file", await check(["--json", ...args, typed("leaf-p256.der")])],
        ["standard input, PEM", await check(["--json", ...args, "-"], { input: fixture("leaf-p256.pem") })],
        ["standard input, DER", await check(["--json", ...args, "-"], { input: fixture("leaf-p256.der") })],
    ])) {
        assert.equal(result.code, 0, `${how}: ${result.stderr}`);
        const printed = jsonOf(result);
        assert.equal(printed.observation.certificates[0].sha256, sha256, how);
        assert.deepEqual(printed.results.map((/** @type {{ rule: { name: string } }} */ one) => one.rule.name), ["validityStarted", "validityNotEnded", "rejectEku"], how);
    }
    const file = jsonOf(await check(["--json", ...args, typed("leaf-p256.pem")]));
    assert.deepEqual(file.observation.observation.source, { kind: "file", ref: typed("leaf-p256.pem") });
    const piped = jsonOf(await check(["--json", ...args, "-"], { input: fixture("leaf-p256.pem") }));
    assert.deepEqual(piped.observation.observation.source, { kind: "stdin", ref: "-" });

    // One line for each rule, between the first line and the summary.
    const text = await check([...args, typed("leaf-p256.pem")]);
    const lines = text.stdout.split("\n");
    assert.match(lines[0], new RegExp(`^${typed("leaf-p256.pem")}  checked at ${start}$`));
    assert.deepEqual(lines.slice(1, 4).map((line) => line.trim().split(/ {2,}/).slice(0, 2)), [["OK", "validityStarted"], ["OK", "validityNotEnded"], ["OK", "rejectEku"]]);
});

test("every flag check takes is accepted, and the ones that can be repeated add up", async () => {
    const { certificate } = targetOf("leaf-p256.pem");
    const pairs = certificate.sha256.toUpperCase().match(/../g) ?? [];
    const result = await check([
        "--as-of", certificate.notBefore,
        "--expect-eku", "serverAuth", "--expect-eku", "1.3.6.1.5.5.7.3.2",
        "--eku-allows", "serverAuth",
        "--reject-eku", "codeSigning", "--reject-eku", "timeStamping",
        "--expect-san", "p256.example",
        "--expect-fingerprint", pairs.join(":"),
        "--expires-within", "1d",
        "--lifetime-used", "100%",
        "--warn-only", "EXPIRED", "--warn-only", "NOT_YET_VALID",
        "--select", certificate.sha256.slice(0, 10),
        "--json",
        typed("leaf-p256.pem"),
    ]);
    assert.equal(result.code, 0, result.stderr);
    const printed = jsonOf(result);
    assert.deepEqual(errorsOf(printed), []);
    assert.deepEqual(printed.policy.expectEku, { value: ["serverAuth", "1.3.6.1.5.5.7.3.2"], severity: "fail" });
    assert.deepEqual(printed.policy.rejectEku.value, ["codeSigning", "timeStamping"]);
    assert.equal(printed.policy.expectFingerprint.value, certificate.sha256);
    assert.deepEqual([printed.policy.validityStarted.severity, printed.policy.validityNotEnded.severity], ["warn", "warn"]);
    assert.equal(printed.summary.fail, 0);

    // -q and -h are the short forms of --quiet and --help.
    const quiet = await check(["-q", ...ALWAYS_PASSES, typed("leaf-p256.pem")]);
    assert.deepEqual([quiet.code, quiet.stdout, quiet.stderr], [0, "", ""]);
    const help = await check(["-h"]);
    assert.deepEqual([help.code, help.stderr], [0, ""]);
    assert.match(help.stdout, /^certdrift check decides/);
});

test("check has no --query, --host, --servername, --timeout or --verbose: each is an unknown option and misuse", async () => {
    for (const flags of [["--query", "observation.at"], ["--host", "example.com"], ["--servername", "example.com"], ["--timeout", "5"], ["--verbose"], ["-v"]]) {
        const result = await check([...flags, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
        assert.deepEqual([flags.join(" "), result.code, result.stdout], [flags.join(" "), 2, ""]);
        assert.match(result.stderr, new RegExp(`^certdrift: Unknown option '${flags[0]}'`), flags.join(" "));
        assert.match(result.stderr, /Usage: certdrift check /);
        assert.doesNotMatch(result.stderr, /certdrift inspect/);
    }
});

test("a flag that takes one value and is given twice is exit 2", async () => {
    const sha256 = "ab".repeat(32);
    /** @type {[string, string[]][]} */
    const rows = [
        ["expect-fingerprint", [sha256, sha256]],
        ["expires-within", ["30d", "60d"]],
        ["lifetime-used", ["50%", "60%"]],
        ["policy", [policyPath("empty"), policyPath("empty")]],
        ["as-of", ["2026-03-01", "2026-03-02"]],
        ["select", ["ab", "ab"]],
    ];
    for (const [flag, values] of rows) {
        const result = await check(["--reject-eku", "codeSigning", `--${flag}`, values[0], `--${flag}`, values[1], typed("leaf-p256.pem")]);
        assert.deepEqual([flag, result.code, result.stdout], [flag, 2, ""]);
        assert.match(result.stderr, new RegExp(`^certdrift: --${flag} was given more than once\\n`), flag);
    }
    // The same value twice is no better: the second would be dropped without a word otherwise.
    const same = await check(["--select=ab", "--select=ab", "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
    assert.equal(same.code, 2);
});

test("the options that can be repeated take every value, and the same one twice twice", async () => {
    const result = await check(["--as-of", startOf("leaf-p256.pem"), "--json", "--expect-san", "p256.example", "--expect-san", "p256.example", "--expect-eku", "serverAuth", "--expect-eku", "serverAuth", typed("leaf-p256.pem")]);
    const printed = jsonOf(result);
    assert.deepEqual(printed.policy.expectSan.value, ["p256.example", "p256.example"]);
    assert.deepEqual(printed.policy.expectEku.value, ["serverAuth", "serverAuth"]);
});

test("no path, two paths, an empty --select and a flag in place of the value are misuse", async () => {
    const rows = /** @type {[string[], RegExp][]} */ ([
        [["--reject-eku", "codeSigning"], /^certdrift: no path given; use "-" to read standard input\n/],
        [["--reject-eku", "codeSigning", "a.pem", "b.pem"], /^certdrift: expected one path, got 2\n/],
        [["--reject-eku", "codeSigning", "--select=", "a.pem"], /^certdrift: --select needs the start of a sha256, and it is empty\n/],
        [["--expect-eku", "--json", "a.pem"], /^certdrift: Option '--expect-eku(?: <value>)?' argument is ambiguous/],
    ]);
    for (const [args, message] of rows) {
        const result = await check(args);
        assert.deepEqual([args.join(" "), result.code, result.stdout], [args.join(" "), 2, ""]);
        assert.match(result.stderr, message, args.join(" "));
        assert.match(result.stderr, /Usage: certdrift check .*<path \| ->\nRun certdrift check --help for the options\.\n$/s);
    }
});

// ---------------------------------------------------------------------------------------------
// The flags become a policy, and the command applies none of it

test("the flags become the policy that --json shows, and the results are what evaluate gives for that policy and instant", async () => {
    const name = "leaf-p256.pem";
    const { certificate } = targetOf(name);
    const now = shifted(certificate.notBefore, 30 * 86400);
    const args = ["--expect-eku", "serverAuth", "--eku-allows", "clientAuth", "--reject-eku", "codeSigning", "--expect-san", "P256.example", "--expect-san", "192.0.2.1", "--expect-fingerprint", certificate.sha256.toUpperCase(), "--expires-within", "72h", "--lifetime-used", "20%"];
    const result = await check(["--json", "--as-of", now, ...args, typed(name)]);
    assert.equal(result.code, 1, result.stderr);
    const printed = jsonOf(result);
    assert.deepEqual(errorsOf(printed), []);

    const policy = {
        contract: 1,
        expectEku: { value: ["serverAuth"] },
        ekuAllows: { value: ["clientAuth"] },
        rejectEku: { value: ["codeSigning"] },
        expectSan: { value: ["P256.example", "192.0.2.1"] },
        expectFingerprint: { value: certificate.sha256 },
        expiresWithin: { value: "72h" },
        maxLifetimeUsed: { value: 0.2 },
    };
    assert.deepEqual(withoutObservation(printed), expectedFor(name, policy, now));
    // 192.0.2.1 is not listed and 20% is below the 33% of the lifetime gone, so the check failed twice.
    assert.deepEqual(printed.results.filter((/** @type {{ status: string }} */ one) => one.status === "fail").map((/** @type {{ code: string }} */ one) => one.code), ["LIFETIME_USED_EXCEEDED", "SAN_MISSING"]);
});

test("--lifetime-used 66.3% is the threshold Number(\"0.663\"), and 66% is 0.66", async () => {
    const start = startOf("leaf-p256.pem");
    for (const [text, value] of /** @type {[string, number][]} */ ([["66.3%", Number("0.663")], ["66%", 0.66], ["57%", Number("0.57")], ["7%", 0.07], ["0%", 0], ["100%", 1]])) {
        const printed = jsonOf(await check(["--json", "--as-of", start, "--lifetime-used", text, typed("leaf-p256.pem")]));
        assert.equal(printed.policy.maxLifetimeUsed.value, value, text);
        assert.equal(printed.results.at(-1).expected, value, text);
    }
    assert.notEqual(66.3 / 100, Number("0.663"));
});

test("--lifetime-used refuses what is not N or N.M followed by %, and a number the policy refuses names the flag", async () => {
    const start = startOf("leaf-p256.pem");
    for (const text of ["66", "%", ".5%", "5.%", "1e2%", "+5%", "٣%", "", " 5%", "5 %", "abc"]) {
        const result = await check(["--as-of", start, `--lifetime-used=${text}`, typed("leaf-p256.pem")]);
        assert.deepEqual([JSON.stringify(text), result.code, result.stdout], [JSON.stringify(text), 2, ""]);
        assert.ok(result.stderr.startsWith(`certdrift: --lifetime-used needs a percentage such as 66% or 66.3%, and got ${JSON.stringify(text)}\n`), result.stderr);
    }
    // parseArgs does not take a value that starts with a dash, unless it is written with the equals sign.
    const negative = await check(["--lifetime-used=-5%", typed("leaf-p256.pem")]);
    assert.equal(negative.code, 2);
    assert.match(negative.stderr, /^certdrift: --lifetime-used needs a percentage/);
    const spaced = await check(["--lifetime-used", "-5%", typed("leaf-p256.pem")]);
    assert.equal(spaced.code, 2);
    assert.match(spaced.stderr, /^certdrift: Option '--lifetime-used(?: <value>)?' argument is ambiguous/);

    for (const text of ["150%", "100.5%", "1000%"]) {
        const result = await check(["--as-of", start, "--lifetime-used", text, typed("leaf-p256.pem")]);
        assert.equal(result.code, 2, text);
        assert.match(result.stderr, /^certdrift: the requirement options are not valid: 1 problem\n  --lifetime-used: must be a number from 0 to 1\n/, text);
    }
});

test("--expect-fingerprint accepts upper case and colon-separated pairs, and a value that is not a SHA-256 is exit 2 naming the flag", async () => {
    const { certificate } = targetOf("leaf-p256.pem");
    const pairs = certificate.sha256.toUpperCase().match(/../g) ?? [];
    for (const text of [certificate.sha256, certificate.sha256.toUpperCase(), pairs.join(":"), pairs.join(":").toLowerCase()]) {
        const printed = jsonOf(await check(["--json", "--as-of", certificate.notBefore, "--expect-fingerprint", text, typed("leaf-p256.pem")]));
        assert.equal(printed.policy.expectFingerprint.value, certificate.sha256, text);
        assert.equal(printed.results.at(-1).status, "pass", text);
    }
    for (const text of [certificate.sha256.slice(1), `${certificate.sha256}00`, `${certificate.sha256}:`, pairs.slice(1).join(":"), pairs.join("::"), "zz".repeat(32), ""]) {
        const result = await check([`--expect-fingerprint=${text}`, typed("leaf-p256.pem")]);
        assert.deepEqual([text, result.code, result.stdout], [text, 2, ""]);
        assert.match(result.stderr, /^certdrift: the requirement options are not valid: 1 problem\n  --expect-fingerprint: must be 64 lowercase hexadecimal characters\n/, text);
    }
    // A fingerprint of another certificate is a failed check and not misuse.
    const other = await check(["--json", "--as-of", certificate.notBefore, "--expect-fingerprint", "ab".repeat(32), typed("leaf-p256.pem")]);
    assert.equal(other.code, 1);
    assert.equal(jsonOf(other).results.at(-1).code, "FINGERPRINT_MISMATCH");
});

test("a value an option cannot take is exit 2 and the message names the option, never a path inside a policy", async () => {
    /** @type {[string, string][]} */
    const rows = [
        ["--expect-eku", "bogus"],
        ["--eku-allows", ""],
        ["--reject-eku", "1"],
        ["--expect-san", "not a name"],
        ["--expect-fingerprint", "abc"],
        ["--expires-within", "30"],
        ["--expires-within", "0d"],
        ["--expires-within", "30D"],
        ["--lifetime-used", "101%"],
    ];
    for (const [flag, value] of rows) {
        const result = await check([`${flag}=${value}`, typed("leaf-p256.pem")]);
        assert.deepEqual([flag, value, result.code, result.stdout], [flag, value, 2, ""]);
        const lines = result.stderr.split("\n");
        assert.equal(lines[0], "certdrift: the requirement options are not valid: 1 problem");
        assert.ok(lines[1].startsWith(`  ${flag}: `), lines[1]);
        assert.doesNotMatch(result.stderr, /\/(expect|eku|reject|max|expires)\w*(\/value)?[: ]/, "no path of a policy");
        assert.match(lines[2], /^Usage: certdrift check /);
    }
});

test("a bad value of a repeated option is named as it was typed, escaped, and the good ones are not", async () => {
    const result = await check(["--expect-san", "a.example", "--expect-san", "second one", "--expect-san", `bad${ESC}[31m‮name`, "--expect-san", "c.example", typed("leaf-p256.pem")]);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, "");
    assert.deepEqual(result.stderr.split("\n").slice(0, 4), [
        "certdrift: the requirement options are not valid: 2 problems",
        '  --expect-san: "second one" is not a value this flag accepts',
        '  --expect-san: "bad\\u001b[31m\\u{202E}name" is not a value this flag accepts',
        "Usage: certdrift check [requirements] [--policy <file>] [--as-of <date>] [--select <sha256>] [--json | --quiet] <path | ->",
    ]);
});

test("several bad options are listed together, each under its own flag", async () => {
    const result = await check(["--expires-within=x", "--lifetime-used=200%", "--expect-eku=bogus", "--expect-fingerprint=zz", typed("leaf-p256.pem")]);
    assert.equal(result.code, 2);
    const lines = result.stderr.split("\n");
    assert.equal(lines[0], "certdrift: the requirement options are not valid: 4 problems");
    assert.deepEqual(lines.slice(1, 5).map((line) => line.split(":")[0]), ["  --expires-within", "  --lifetime-used", "  --expect-eku", "  --expect-fingerprint"]);
});

// ---------------------------------------------------------------------------------------------
// --policy

/**
 * A policy file in a scratch directory.
 * @param {string} dir
 * @param {string} name
 * @param {string | Uint8Array} content
 */
function written(dir, name, content) {
    const path = join(dir, name);
    writeFileSync(path, content);
    return path;
}

test("a policy file that cannot be opened is exit 3: missing, a directory, an empty path", async (t) => {
    const dir = scratch(t);
    mkdirSync(join(dir, "directory"));
    for (const path of [join(dir, "missing.json"), join(dir, "directory"), ""]) {
        const result = await check(["--policy", path, typed("leaf-p256.pem")]);
        assert.deepEqual([path, result.code, result.stdout], [path, 3, ""]);
        assert.ok(result.stderr.startsWith(`certdrift: cannot read ${path === "" ? "" : path}: `), result.stderr);
    }
});

test("a policy file that is not JSON is exit 3, and the message holds none of what the file holds", async (t) => {
    const dir = scratch(t);
    const secret = "PRIVATE-WORDS-THAT-MUST-NOT-APPEAR";
    /** @type {[string, string | Uint8Array][]} */
    const files = [
        ["empty", ""],
        ["text", `${secret} is not json`],
        ["half", `{"contract": 1, "note": "${secret}"`],
        ["certificate", fixture("leaf-p256.pem")],
        ["key", fixture("leaf-p256.key")],
        ["utf16", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"contract":1}', "utf16le")])],
        ["invalid utf-8", Buffer.concat([Buffer.from('{"contract":1,"note":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')])],
        ["two byte order marks", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]), Buffer.from('{"contract":1}')])],
        ["trailing text", '{"contract":1} and more'],
    ];
    for (const [name, content] of files) {
        const path = written(dir, `${name}.json`, content);
        const result = await check(["--policy", path, typed("leaf-p256.pem")]);
        assert.deepEqual([name, result.code, result.stdout], [name, 3, ""]);
        assert.equal(result.stderr, `certdrift: ${path}: the policy is not valid JSON\n`, name);
    }
});

test("a byte order mark before the JSON of a policy file is ignored", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "bom.json", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"contract":1,"expectKind":{"value":"end-entity"}}')]));
    const printed = jsonOf(await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", path, typed("leaf-p256.pem")]));
    assert.deepEqual(printed.policy.expectKind, { value: "end-entity", severity: "fail" });
});

test("a policy read from standard input is called standard input in what is said about it, as is a certificate read from it", async () => {
    const shape = await check(["--policy", "-", typed("leaf-p256.pem")], { input: '{"contract":2}' });
    assert.equal(shape.code, 2);
    assert.match(shape.stderr, /^certdrift: standard input: the policy is not valid: 1 problem\n {2}\/contract: /);
    const clash = await check(["--policy", "-", "--expect-eku", "serverAuth", typed("leaf-p256.pem")], { input: '{"contract":1,"expectEku":{"value":["serverAuth"]}}' });
    assert.equal(clash.code, 2);
    assert.match(clash.stderr, /^certdrift: standard input: the options and the policy file give the same entry\n/);
    const material = await check([...ALWAYS_PASSES, "-"], { input: fixture("leaf-p256.pem") });
    assert.equal(material.code, 0, material.stderr);
    assert.match(material.stdout.split("\n")[0], /^standard input {2}checked at /);
});

test("a policy file the library refuses is exit 2, with each problem and its path, and so is a contract it does not know", async (t) => {
    const dir = scratch(t);
    /** @type {[string, string, string[]][]} */
    const rows = [
        ["a value of the wrong kind", '{"contract":1,"expiresWithin":{"value":30}}', ["/expiresWithin/value: must be a whole number of days or hours, such as 30d or 72h, of at most six digits"]],
        ["a severity that is not one", '{"contract":1,"expectKind":{"value":"end-entity","severity":"loud"}}', ['/expectKind/severity: must be "fail" or "warn"']],
        ["an unknown contract", '{"contract":2}', ["/contract: contract 2 is not one this version knows: it must be 1"]],
        ["no contract", "{}", ["/contract: is required"]],
        ["an array", "[]", ["(the policy): the policy must be a JSON object"]],
        ["null", "null", ["(the policy): the policy must be a JSON object"]],
        ["a number", "5", ["(the policy): the policy must be a JSON object"]],
        ["two problems", '{"contract":1,"maxLifetimeUsed":{"value":2},"expectEku":{"value":[]}}', ["/maxLifetimeUsed/value: must be a number from 0 to 1", "/expectEku/value: must be a list with at least one item"]],
    ];
    for (const [name, content, details] of rows) {
        const path = written(dir, "policy.json", content);
        const result = await check(["--policy", path, typed("leaf-p256.pem")]);
        assert.deepEqual([name, result.code, result.stdout], [name, 2, ""]);
        const lines = result.stderr.split("\n");
        assert.equal(lines[0], `certdrift: ${path}: the policy is not valid: ${details.length} problem${details.length === 1 ? "" : "s"}`, name);
        assert.deepEqual(lines.slice(1, 1 + details.length), details.map((line) => `  ${line}`), name);
    }
});

test("the options add entries to the policy file", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "policy.json", '{"contract":1,"expectKind":{"value":"end-entity"},"rejectEku":{"value":["codeSigning"],"severity":"warn"}}');
    const { certificate } = targetOf("leaf-p256.pem");
    const printed = jsonOf(await check(["--json", "--as-of", certificate.notBefore, "--policy", path, "--expect-eku", "serverAuth", typed("leaf-p256.pem")]));
    assert.deepEqual(printed.results.map((/** @type {{ rule: { name: string } }} */ one) => one.rule.name), ["validityStarted", "validityNotEnded", "expectEku", "rejectEku", "expectKind"]);
    assert.deepEqual(printed.policy.rejectEku, { value: ["codeSigning"], severity: "warn" });
    assert.deepEqual(printed.policy.expectEku, { value: ["serverAuth"], severity: "fail" });
});

test("an option that gives an entry the policy file has is exit 2 and says which, whatever its value", async (t) => {
    const dir = scratch(t);
    /** @type {[string, string, string, string][]} */
    const rows = [
        ["expect-eku", "serverAuth", "expectEku", '{"value":["clientAuth"]}'],
        ["eku-allows", "serverAuth", "ekuAllows", '{"value":["serverAuth"]}'],
        ["reject-eku", "codeSigning", "rejectEku", '{"value":["codeSigning"]}'],
        ["expect-san", "a.example", "expectSan", '{"value":["b.example"]}'],
        ["expect-fingerprint", "ab".repeat(32), "expectFingerprint", `{"value":"${"ab".repeat(32)}"}`],
        ["expires-within", "30d", "expiresWithin", '{"value":"30d"}'],
        ["lifetime-used", "50%", "maxLifetimeUsed", '{"value":0.5}'],
    ];
    for (const [flag, value, entry, content] of rows) {
        const path = written(dir, "policy.json", `{"contract":1,"${entry}":${content}}`);
        const result = await check(["--policy", path, `--${flag}`, value, typed("leaf-p256.pem")]);
        assert.deepEqual([flag, result.code, result.stdout], [flag, 2, ""]);
        const lines = result.stderr.split("\n");
        assert.equal(lines[0], `certdrift: ${path}: the options and the policy file give the same entry`, flag);
        assert.ok(lines[1].startsWith(`  --${flag} gives ${entry}, which the policy file has: use --warn-only`), lines[1]);
    }
    // Only the entry the file has is a conflict: the others are added.
    const path = written(dir, "policy.json", '{"contract":1,"expectEku":{"value":["serverAuth"]}}');
    const fine = await check(["--policy", path, "--reject-eku", "codeSigning", ...ALWAYS_PASSES.slice(0, 4), typed("leaf-p256.pem")]);
    assert.equal(fine.code, 0, fine.stderr);
});

test("--warn-only is the way to soften a rule the policy file has, and a flag never changes the file's policy", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "policy.json", '{"contract":1,"expectEku":{"value":["codeSigning"],"severity":"fail"}}');
    const strict = await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", path, typed("leaf-p256.pem")]);
    assert.equal(strict.code, 1);
    const soft = await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", path, "--warn-only", "EKU_MISSING", typed("leaf-p256.pem")]);
    assert.equal(soft.code, 0, soft.stderr);
    const printed = jsonOf(soft);
    assert.deepEqual(printed.policy.expectEku, { value: ["codeSigning"], severity: "warn" });
    assert.equal(printed.results.at(-1).status, "warn");
    assert.equal(printed.summary.status, "warn");
    // The file is not rewritten.
    assert.equal(readFileSync(path, "utf8"), '{"contract":1,"expectEku":{"value":["codeSigning"],"severity":"fail"}}');
});

test("--policy - reads the policy from standard input, and a certificate and a policy cannot both come from it", async () => {
    const start = startOf("leaf-p256.pem");
    const result = await check(["--json", "--as-of", start, "--policy", "-", typed("leaf-p256.pem")], { input: '{"contract":1,"expectKind":{"value":"end-entity"}}' });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(jsonOf(result).policy.expectKind, { value: "end-entity", severity: "fail" });

    const both = await check(["--policy", "-", "-"], { input: '{"contract":1}' });
    assert.deepEqual([both.code, both.stdout], [2, ""]);
    assert.match(both.stderr, /^certdrift: --policy - and the path - both read standard input, which can be read once\n/);
    // Misuse comes before anything is read, so a standard input that never closes is not waited for.
    const open = await check(["--policy", "-", "-"], { openStdin: true });
    assert.equal(open.code, 2);

    const bad = await check(["--policy", "-", typed("leaf-p256.pem")], { input: "nope" });
    assert.equal(bad.code, 3);
    assert.equal(bad.stderr, "certdrift: standard input: the policy is not valid JSON\n");
});

test("today: a policy file with the same entry twice checks only the second, because JSON.parse keeps the last", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "twice.json", '{"contract":1,"expectEku":{"value":["codeSigning"]},"expectEku":{"value":["serverAuth"]}}');
    const result = await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", path, typed("leaf-p256.pem")]);
    assert.equal(result.code, 0);
    assert.deepEqual(jsonOf(result).policy.expectEku.value, ["serverAuth"]);
});

test("today: a __proto__ key in a policy file is an unknown property that changes nothing, and unknown properties are not repeated in the result", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "proto.json", '{"contract":1,"__proto__":{"expectKind":{"value":"end-entity"},"expectEku":{"value":["codeSigning"]}},"secret":{"note":"x"},"expectKind":{"value":"end-entity","extra":"y"}}');
    const printed = jsonOf(await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", path, typed("leaf-p256.pem")]));
    assert.deepEqual(Object.keys(printed.policy).sort(), ["contract", "expectKind", "validityNotEnded", "validityStarted"]);
    assert.deepEqual(printed.policy.expectKind, { value: "end-entity", severity: "fail" });
    assert.equal(printed.results.length, 3);
    assert.doesNotMatch(JSON.stringify(printed.policy), /secret|extra/);
});

test("a policy nested far deeper than the call stack allows is refused as a policy and does not crash the command", async (t) => {
    const dir = scratch(t);
    const depth = 100_000;
    const path = written(dir, "deep.json", `{"contract":1,"expectEku":{"value":${"[".repeat(depth)}${"]".repeat(depth)}}}`);
    const result = await check(["--policy", path, typed("leaf-p256.pem")]);
    assert.deepEqual([result.code, result.stdout], [2, ""]);
    assert.match(result.stderr, /^certdrift: .*: the policy is not valid: 1 problem\n  \/expectEku\/value: item 0 is not one this entry accepts\n/);
});

test("a certificate given as the policy is not JSON, and a policy given as the certificate is not a certificate", async () => {
    const asPolicy = await check(["--policy", typed("leaf-p256.pem"), typed("leaf-p256.pem")]);
    assert.equal(asPolicy.code, 3);
    assert.match(asPolicy.stderr, /the policy is not valid JSON\n$/);
    const asCertificate = await check(["--policy", policyPath("empty"), policyPath("empty")]);
    assert.equal(asCertificate.code, 3);
    assert.match(asCertificate.stderr, /^certdrift: schema\/examples\/policy\/empty\.json: the material holds no certificate/);
});

// ---------------------------------------------------------------------------------------------
// --warn-only

test("--warn-only sets the severity of the entry of a flag, of the file and of a validity rule to warn, and the check does not fail", async (t) => {
    const dir = scratch(t);
    // leaf-expired ended in 2025, whatever day this runs: EXPIRED fails and --warn-only softens it.
    const failing = await check(["--reject-eku", "codeSigning", typed("leaf-expired.pem")]);
    assert.equal(failing.code, 1);
    assert.match(failing.stdout, /^ {2}FAIL {2}validityNotEnded +EXPIRED /m);

    const soft = await check(["--warn-only", "EXPIRED", "--reject-eku", "codeSigning", typed("leaf-expired.pem")]);
    assert.equal(soft.code, 0, soft.stderr);
    assert.match(soft.stdout, /^ {2}WARN {2}validityNotEnded +EXPIRED /m);
    assert.match(soft.stdout, /\n0 failed · exit 0\n$/);

    // An entry of a flag, and an entry of the file.
    const flagged = await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--warn-only", "EKU_MISSING", "--expect-eku", "codeSigning", typed("leaf-p256.pem")]);
    assert.equal(flagged.code, 0, flagged.stderr);
    assert.deepEqual(jsonOf(flagged).policy.expectEku, { value: ["codeSigning"], severity: "warn" });
    const filed = await check(["--json", "--as-of", startOf("root-ca.pem"), "--warn-only", "TARGET_NOT_END_ENTITY", "--policy", written(dir, "kind.json", '{"contract":1,"expectKind":{"value":"end-entity"}}'), typed("root-ca.pem")]);
    assert.equal(filed.code, 0, filed.stderr);
    assert.equal(jsonOf(filed).results.at(-1).status, "warn");

    // A code twice is harmless; both validity codes together are warnings.
    const both = await check(["--warn-only", "EXPIRED", "--warn-only", "EXPIRED", "--warn-only", "NOT_YET_VALID", "--reject-eku", "codeSigning", "--as-of", "0001-01-01", typed("leaf-p256.pem")]);
    assert.equal(both.code, 0, both.stderr);
    assert.match(both.stdout, /^ {2}WARN {2}validityStarted +NOT_YET_VALID /m);
});

test("--warn-only finds the entry of a code with the library's entryOfCode: a code is accepted exactly when it has an entry and the entry is part of the run", async () => {
    /** The flag that puts an entry in the run, with a value it accepts, and the codes of that entry. @type {[string, string, string[]][]} */
    const rows = [
        ["--expect-eku", "serverAuth", ["EKU_MISSING"]],
        ["--eku-allows", "serverAuth", ["EKU_NOT_PERMITTED"]],
        ["--reject-eku", "codeSigning", ["EKU_FORBIDDEN"]],
        ["--expect-san", "p256.example", ["SAN_MISSING"]],
        ["--expect-fingerprint", "ab".repeat(32), ["FINGERPRINT_MISMATCH"]],
        ["--expires-within", "1d", ["EXPIRES_SOON"]],
        ["--lifetime-used", "100%", ["LIFETIME_USED_EXCEEDED"]],
    ];
    const start = startOf("leaf-p256.pem");
    for (const [flag, value, codes] of rows) {
        for (const code of codes) {
            assert.notEqual(entryOfCode(code), null, code);
            const active = await check(["--as-of", start, flag, value, "--warn-only", code, typed("leaf-p256.pem")]);
            assert.notEqual(active.code, 2, `${code} with ${flag}: ${active.stderr}`);
            const inactive = await check(["--as-of", start, "--warn-only", code, "--policy", policyPath("empty"), typed("leaf-p256.pem")]);
            assert.equal(inactive.code, 2, code);
            assert.match(inactive.stderr, new RegExp(`^certdrift: --warn-only names a rule this run does not check\\n  --warn-only: ${code} belongs to ${entryOfCode(code)}, which this run does not check: give ${flag} or list ${entryOfCode(code)} in the policy\\n`), code);
        }
    }
    // The codes of the two validity entries are always part of a run, and so is the entry of a code that a policy file lists.
    for (const code of ["EXPIRED", "NOT_YET_VALID"]) {
        const result = await check(["--as-of", start, "--warn-only", code, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
        assert.equal(result.code, 0, result.stderr);
    }
    const onlyContract = await check(["--as-of", start, "--warn-only", "EXPIRED", "--policy", policyPath("empty"), typed("leaf-p256.pem")]);
    assert.equal(onlyContract.code, 0, onlyContract.stderr);
    const fromFile = await check(["--as-of", start, "--warn-only", "EKU_MISSING", "--policy", policyPath("server"), typed("leaf-p256.pem")]);
    assert.notEqual(fromFile.code, 2, fromFile.stderr);
});

test("a code that does not exist, or that has no entry to soften, is exit 2: a mistyped code would leave failing a rule that was meant to be softened", async () => {
    for (const code of ["NOPE", "expired", "Expired", " EXPIRED", "EXPIRED ", "", "POLICY_EMPTY", "RULE_ERROR", "__proto__", "constructor", "toString", "EXPIRES_SOON_"]) {
        const result = await check([`--warn-only=${code}`, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
        assert.deepEqual([JSON.stringify(code), result.code, result.stdout], [JSON.stringify(code), 2, ""]);
        assert.match(result.stderr, /^certdrift: --warn-only needs the reason code of a rule that has a severity\n/, JSON.stringify(code));
        assert.ok(result.stderr.split("\n")[1].includes(JSON.stringify(code).replaceAll("\\", "\\\\")) || code === "", result.stderr);
    }
    // KEY_MISMATCH has an entry, which this command never runs.
    for (const code of ["KEY_MISMATCH", "KEY_UNREADABLE"]) {
        const result = await check(["--warn-only", code, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
        assert.equal(result.code, 2);
        assert.match(result.stderr, new RegExp(`--warn-only: ${code} belongs to matchesPrivateKey, which this run does not check: list matchesPrivateKey in the policy\\n`));
    }
});

test("--warn-only alone and --as-of alone are not something to check, and the options with a policy that has only contract are", async () => {
    for (const args of [[], ["--warn-only", "EXPIRED"], ["--as-of", "2026-03-01"], ["--json"], ["--select", "ab"], ["--warn-only", "EXPIRED", "--as-of", "2026-03-01", "--json"]]) {
        const result = await check([...args, typed("leaf-p256.pem")]);
        assert.deepEqual([args.join(" "), result.code, result.stdout], [args.join(" "), 2, ""]);
        assert.match(result.stderr, /^certdrift: nothing to check: give a requirement option or --policy\n/, args.join(" "));
    }
    const only = await check(["--as-of", startOf("leaf-p256.pem"), "--policy", policyPath("empty"), typed("leaf-p256.pem")]);
    assert.equal(only.code, 0, only.stderr);
    assert.match(only.stdout, /^ {2}WARN {2}- {17}POLICY_EMPTY /m);
    assert.match(only.stdout, /\n0 failed · exit 0\n$/);
    const json = jsonOf(await check(["--json", "--as-of", startOf("leaf-p256.pem"), "--policy", policyPath("empty"), typed("leaf-p256.pem")]));
    assert.equal(json.results.at(-1).code, "POLICY_EMPTY");
    assert.equal(json.results.at(-1).rule, null);
    assert.equal(json.summary.status, "warn");
});

// ---------------------------------------------------------------------------------------------
// --as-of

test("--as-of YYYY-MM-DD is that day at 00:00:00 UTC, a timestamp with Z is that instant, and the observation's at does not change", async () => {
    const before = Date.now();
    for (const [text, now] of [["2026-03-01", "2026-03-01T00:00:00Z"], ["2026-03-01T14:02:11Z", "2026-03-01T14:02:11Z"], ["0000-01-01", "0000-01-01T00:00:00Z"], ["9999-12-31", "9999-12-31T00:00:00Z"], ["9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"], ["2024-02-29", "2024-02-29T00:00:00Z"]]) {
        const result = await check(["--json", "--as-of", text, "--reject-eku", "codeSigning", ...ALWAYS_PASSES.slice(0, 4), typed("leaf-p256.pem")]);
        assert.equal(result.code, 0, `${text}: ${result.stderr}`);
        const printed = jsonOf(result);
        assert.equal(printed.now, now, text);
        // The observation was made at the real time, in whole seconds.
        const at = Date.parse(printed.observation.observation.at);
        assert.ok(at >= Math.floor(before / 1000) * 1000 && at <= Date.now(), `${text}: ${printed.observation.observation.at}`);
        assert.deepEqual(errorsOf(printed), [], text);
    }
});

test("the first line of the readable output says the instant used, whether it was asked for or not", async () => {
    const asked = await check(["--as-of", "2026-03-01", ...ALWAYS_PASSES, typed("leaf-p256.pem")]);
    assert.equal(asked.stdout.split("\n")[0], `${typed("leaf-p256.pem")}  checked at 2026-03-01T00:00:00Z`);
    const before = Date.now();
    const now = await check([...ALWAYS_PASSES, typed("leaf-p256.pem")]);
    const first = now.stdout.split("\n")[0];
    const match = /^test\/fixtures\/leaf-p256\.pem {2}checked at (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)$/.exec(first);
    assert.ok(match, first);
    assert.ok(Date.parse(match[1]) >= Math.floor(before / 1000) * 1000 - 5000 && Date.parse(match[1]) <= Date.now() + 1000);
});

test("--as-of refuses anything else: an impossible date, T24:00:00Z, no Z, a fraction, a lower case z, an offset, a six-digit year, spaces and nothing", async () => {
    for (const text of ["2026-02-30", "2026-02-29", "2026-13-01", "2026-00-10", "2026-03-32", "2026-1-1", "26-01-01", "2026/03/01", "20260301", "10000-01-01", "+010000-01-01", "010000-01-01", "-000001-01-01", "2026-03-01 ", " 2026-03-01", "",
        "2026-02-30T00:00:00Z", "2026-03-01T24:00:00Z", "2026-03-01T25:00:00Z", "2026-03-01T00:00:00", "2026-03-01T00:00:00.5Z", "2026-03-01T00:00:00.000Z", "2026-03-01T00:00:00z", "2026-03-01t00:00:00Z", "2026-03-01T00:00:00+00:00", "2026-03-01T00:00:60Z", "2026-03-01 00:00:00Z", "010000-01-01T00:00:00Z", "+010000-01-01T00:00:00Z", "tomorrow"]) {
        const result = await check([`--as-of=${text}`, ...ALWAYS_PASSES, typed("leaf-p256.pem")]);
        assert.deepEqual([JSON.stringify(text), result.code, result.stdout], [JSON.stringify(text), 2, ""]);
        assert.ok(result.stderr.startsWith(`certdrift: --as-of needs a date such as 2026-03-01 or a timestamp such as 2026-03-01T00:00:00Z, and got ${JSON.stringify(text)}\n`), result.stderr);
        assert.match(result.stderr, /Usage: certdrift check /);
    }
});

test("what --as-of accepts is what evaluate accepts as now, over a corpus", async () => {
    const corpus = [
        "2026-03-01", "2026-02-30", "2026-02-29", "2024-02-29", "0000-01-01", "9999-12-31", "10000-01-01", "+010000-01-01", "2026-13-01", "2026-1-1", "26-01-01", "", " 2026-03-01", "2026-03-01 ",
        "2026-03-01T00:00:00Z", "2026-03-01T24:00:00Z", "2026-03-01T23:59:59Z", "2026-03-01T00:00:00", "2026-03-01T00:00:00.5Z", "2026-03-01T00:00:00.000Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
        "010000-01-01T00:00:00Z", "+010000-01-01T00:00:00Z", "-000001-01-01T00:00:00Z", "2026-03-01T00:00:00z", "2026-03-01t00:00:00Z", "2026-03-01T00:00:00+00:00", "2026-03-01T00:00:60Z", "2026-02-30T00:00:00Z", "2026-03-01T25:00:00Z", "2026-03-01 00:00:00Z",
    ];
    const observation = inspect(fixture("leaf-p256.pem"));
    const libraryAccepts = (/** @type {string} */ now) => {
        try {
            evaluate(observation, { contract: 1 }, { now });
            return true;
        } catch (error) {
            if (error instanceof TypeError) return false;
            throw error;
        }
    };
    const path = `${CWD}${typed("leaf-p256.pem")}`;
    let accepted = 0;
    for (const text of corpus) {
        const built = /^\d{4}-\d\d-\d\d$/.test(text) ? `${text}T00:00:00Z` : text;
        const result = await runMain(["check", "--as-of", text, ...ALWAYS_PASSES, path]);
        const commandAccepts = result.code !== 2;
        assert.equal(commandAccepts, libraryAccepts(built), JSON.stringify(text));
        assert.equal("now" in nowOf(text), libraryAccepts(built), JSON.stringify(text));
        if (commandAccepts) {
            accepted += 1;
            assert.match(result.stdout.split("\n")[0], new RegExp(`checked at ${built}$`), text);
        }
    }
    assert.ok(accepted >= 8 && accepted < corpus.length - 8, `the corpus has both: ${accepted} accepted of ${corpus.length}`);
});

test("--as-of is checked before anything is read: a missing file and an open standard input do not change the answer", async () => {
    const missing = await check(["--as-of", "2026-02-30", "--reject-eku", "codeSigning", "no-such-file.pem"]);
    assert.equal(missing.code, 2);
    const open = await check(["--as-of", "2026-02-30", "--reject-eku", "codeSigning", "-"], { openStdin: true });
    assert.equal(open.code, 2);
    const policy = await check(["--as-of", "2026-02-30", "--policy", "no-such-policy.json", "no-such-file.pem"]);
    assert.equal(policy.code, 2);
    // A good instant reaches the file, which is missing.
    const reached = await check(["--as-of", "2026-03-01", "--reject-eku", "codeSigning", "no-such-file.pem"]);
    assert.equal(reached.code, 3);
});

// ---------------------------------------------------------------------------------------------
// The output

test("the readable output has a line for each result with its status, the name of the rule, the code and the message, then the failures and the exit code", async () => {
    const { certificate } = targetOf("leaf-p256.pem");
    const now = shifted(certificate.notBefore, 30 * 86400);
    const args = ["--as-of", now, "--expect-eku", "codeSigning", "--expect-san", "p256.example", "--expires-within", "72h"];
    const text = await check([...args, typed("leaf-p256.pem")]);
    const printed = jsonOf(await check(["--json", ...args, typed("leaf-p256.pem")]));
    assert.equal(text.code, 1);
    assert.equal(text.stderr, "");

    const lines = text.stdout.split("\n");
    assert.equal(lines[0], `${typed("leaf-p256.pem")}  checked at ${now}`);
    assert.equal(lines.at(-1), "");
    assert.equal(lines.at(-2), "1 failed · exit 1");
    assert.equal(lines.at(-3), "", "a blank line before the summary");
    const rows = lines.slice(1, -3);
    assert.equal(rows.length, printed.results.length);
    const label = { pass: "OK  ", warn: "WARN", fail: "FAIL" };
    const nameWidth = Math.max(...printed.results.map((/** @type {{ rule: { name: string } }} */ one) => one.rule.name.length));
    const codeWidth = Math.max(...printed.results.map((/** @type {{ code: string }} */ one) => one.code.length));
    printed.results.forEach((/** @type {{ status: "pass" | "warn" | "fail", rule: { name: string }, code: string, message: string }} */ one, /** @type {number} */ index) => {
        assert.equal(rows[index], `  ${label[one.status]}  ${one.rule.name.padEnd(nameWidth)}  ${one.code.padEnd(codeWidth)}  ${one.message}`);
    });
});

test("the summary counts the failures and gives the exit code of the command", async () => {
    const start = startOf("leaf-p256.pem");
    for (const [args, summary, code] of /** @type {[string[], string, number][]} */ ([
        [["--reject-eku", "codeSigning"], "0 failed · exit 0", 0],
        [["--expect-eku", "codeSigning"], "1 failed · exit 1", 1],
        [["--expect-eku", "codeSigning", "--expect-san", "nope.example", "--expires-within", "999999d"], "3 failed · exit 1", 1],
        [["--expect-eku", "codeSigning", "--warn-only", "EKU_MISSING"], "0 failed · exit 0", 0],
    ])) {
        const result = await check(["--as-of", start, ...args, typed("leaf-p256.pem")]);
        assert.equal(result.code, code, args.join(" "));
        assert.ok(result.stdout.endsWith(`\n\n${summary}\n`), `${args.join(" ")}: ${result.stdout}`);
    }
});

test("text from a certificate or a file is escaped as inspect escapes it, and the line breaks of the output are the command's own", () => {
    const observation = inspect(fixture("leaf-p256.pem"));
    const result = evaluate(observation, { contract: 1 });
    const hostile = `evil${ESC}]0;pwned\u0007 a‮b`;
    result.results[0] = { ...result.results[0], code: `CODE${ESC}[31m`, rule: { name: `rule${ESC}[2J` }, message: hostile };
    result.observation.warnings = [{ code: `WARN${ESC}`, certificate: 0, message: `${hostile}\u2028second` }];
    result.now = `2026${ESC}[2J`;
    const text = presentCheck(result, { described: `${ESC}]0;title\u0007path‮.pem`, colour: false });
    assert.equal(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩\u2028\u2029]/.test(text), false, "no control character, mark or separator is left");
    assert.ok(text.includes("\\u{1B}]0;title\\u{7}path\\u{202E}.pem  checked at"), text);
    assert.ok(text.includes("evil\\u{1B}]0;pwned\\u{7} a\\u{202E}b"), text);
    assert.ok(text.includes("CODE\\u{1B}[31m"), text);
    assert.ok(text.includes("rule\\u{1B}[2J"), text);
    assert.ok(text.includes("WARN\\u{1B} [0] "), text);
    assert.ok(text.includes("checked at 2026\\u{1B}[2J\n"), text);
    assert.ok(text.includes("\\u{2028}second"), text);
    assert.equal(text.endsWith("\n"), true);
});

test("a policy file or a path named with control characters is shown escaped", async (t) => {
    const dir = scratch(t);
    const name = `${ESC}]0;pwned\u0007.json`;
    const path = written(dir, name, "not json");
    const result = await check(["--policy", path, typed("leaf-p256.pem")]);
    assert.equal(result.code, 3);
    assert.equal(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(result.stderr), false, result.stderr);
    assert.ok(result.stderr.includes("\\u{1B}]0;pwned\\u{7}.json: the policy is not valid JSON"), result.stderr);

    const missing = await check(["--reject-eku", "codeSigning", `${ESC}]0;x\u0007missing.pem`]);
    assert.equal(missing.code, 3);
    assert.ok(missing.stderr.includes("cannot read \\u{1B}]0;x\\u{7}missing.pem"));
});

/** Makes a standard stream believe it is a terminal that understands colour. */
const TERMINAL = `data:text/javascript,${encodeURIComponent(`
for (const stream of [process.stdin, process.stdout, process.stderr]) {
    Object.defineProperty(stream, "isTTY", { value: true });
    stream.hasColors = () => true;
    stream.getColorDepth = () => 8;
}`)}`;

test("colour follows NO_COLOR and nothing else, and standard error is never coloured", async () => {
    const start = startOf("leaf-p256.pem");
    const args = ["--as-of", start, "--expect-eku", "codeSigning", "--expect-san", "nope.example", "--warn-only", "SAN_MISSING", typed("bundle-duplicates.pem")];
    const coloured = await check(args, { env: { NO_COLOR: undefined } });
    assert.equal(coloured.code, 1, coloured.stderr);
    assert.match(coloured.stdout, COLOUR);
    const plain = coloured.stdout.replace(COLOUR, "");
    assert.equal(plain.includes(ESC), false);
    assert.ok(coloured.stdout.includes(`${ESC}[31mFAIL${ESC}[39m`), "FAIL is red");
    assert.ok(coloured.stdout.includes(`${ESC}[32mOK  ${ESC}[39m`), "OK is green");
    assert.ok(coloured.stdout.includes(`${ESC}[33mWARN${ESC}[39m`), "WARN is yellow");
    assert.ok(coloured.stdout.includes(`${ESC}[1m${typed("bundle-duplicates.pem")}${ESC}[22m`), "the first line is bold");
    assert.ok(coloured.stdout.includes(`${ESC}[1mWarnings${ESC}[22m`));
    assert.ok(coloured.stdout.includes(`${ESC}[33mDUPLICATE_CERTIFICATE${ESC}[39m`));

    // A terminal, a dumb one, an explicit request for colour or against it: nothing changes.
    /** @type {[string, import("./helpers/command.js").RunOptions][]} */
    const same = [
        ["a terminal", { nodeArguments: ["--import", TERMINAL] }],
        ["TERM=dumb", { env: { TERM: "dumb" } }],
        ["FORCE_COLOR=0", { env: { FORCE_COLOR: "0" } }],
        ["NODE_DISABLE_COLORS=1", { env: { NODE_DISABLE_COLORS: "1" } }],
        ["NO_COLOR empty", { env: { NO_COLOR: "" } }],
    ];
    for (const [name, options] of same) {
        const result = await check(args, { ...options, env: { NO_COLOR: undefined, ...options.env } });
        assert.equal(result.stdout.replace(/checked at \S+/, ""), coloured.stdout.replace(/checked at \S+/, ""), name);
    }
    for (const NO_COLOR of ["1", "0", "false", "anything"]) {
        for (const nodeArguments of [[], ["--import", TERMINAL]]) {
            const result = await check(args, { nodeArguments, env: { NO_COLOR } });
            assert.equal(result.stdout.replace(/checked at \S+/, ""), plain.replace(/checked at \S+/, ""), `NO_COLOR=${NO_COLOR}`);
        }
    }
    const failed = await check(["--select", "zz", ...ALWAYS_PASSES, typed("bundle-two-leaves.pem")], { nodeArguments: ["--import", TERMINAL], env: { NO_COLOR: undefined } });
    assert.equal(failed.code, 2);
    assert.equal(failed.stderr.includes(ESC), false);
});

test("--json prints exactly what serializeCheckResult writes and nothing else on standard output, and validates against the check result schema", async () => {
    const { certificate } = targetOf("leaf-p256.pem");
    const result = await check(["--json", "--as-of", certificate.notBefore, "--policy", policyPath("server"), "--warn-only", "EXPIRES_SOON", typed("leaf-p256.pem")], { env: { NO_COLOR: undefined } });
    assert.equal(result.code, 1);
    assert.equal(result.stderr, "");
    const printed = JSON.parse(result.stdout);
    assert.equal(result.stdout, serializeCheckResult(printed));
    assert.equal(result.stdout.endsWith("}\n"), true);
    assert.equal(result.stdout.includes(ESC), false, "no colour in JSON");
    assert.deepEqual(errorsOf(printed), []);

    // A failure prints nothing on standard output, so a pipe never receives half a document.
    for (const args of [["--json", "missing.pem"], ["--json"], ["--json", "--policy", "missing.json", typed("leaf-p256.pem")], ["--json", ...ALWAYS_PASSES, typed("bundle-two-leaves.pem")]]) {
        const failed = await check(args);
        assert.notEqual(failed.code, 0, args.join(" "));
        assert.equal(failed.stdout, "", args.join(" "));
        assert.notEqual(failed.stderr, "", args.join(" "));
    }
});

test("--quiet prints nothing, wins over --json and keeps the exit code", async () => {
    const start = startOf("leaf-p256.pem");
    /** @type {[string[], number][]} */
    const cases = [
        [["-q", "--as-of", start, "--reject-eku", "codeSigning"], 0],
        [["--quiet", "--json", "--as-of", start, "--reject-eku", "codeSigning"], 0],
        [["-q", "--json", "--as-of", start, "--expect-eku", "codeSigning"], 1],
        [["-q", "--expect-eku", "codeSigning", "--as-of", start], 1],
        [["-q", "--as-of", "nope", "--reject-eku", "codeSigning"], 2],
        [["-q", "--reject-eku", "bogus"], 2],
        [["-q", "--warn-only", "NOPE", "--reject-eku", "codeSigning"], 2],
        [["-q", "--policy", "missing.json", "--as-of", start], 3],
        [["-q", "--policy", policyPath("every-rule")], 2],
        [["-q", "--help"], 0],
    ];
    for (const [args, code] of cases) {
        const result = await check([...args, ...(args.includes("--help") ? [] : [typed("leaf-p256.pem")])]);
        assert.deepEqual([args.join(" "), result.code, result.stdout, result.stderr], [args.join(" "), code, "", ""]);
    }
    const missing = await check(["-q", ...ALWAYS_PASSES, "missing.pem"]);
    assert.deepEqual([missing.code, missing.stdout, missing.stderr], [3, "", ""]);
    const ambiguous = await check(["-q", ...ALWAYS_PASSES, typed("bundle-two-leaves.pem")]);
    assert.deepEqual([ambiguous.code, ambiguous.stdout, ambiguous.stderr], [2, "", ""]);
    const stdin = await check(["-q", ...ALWAYS_PASSES, "-"], { input: "not a certificate" });
    assert.deepEqual([stdin.code, stdin.stdout, stdin.stderr], [3, "", ""]);
});

test("--quiet is read leniently for check, so that misuse stays silent under it, and a flag that takes a value takes -q as its value", async () => {
    for (const args of [["-q"], ["-q", "--bogus", "x"], ["-q", "--policy"], ["-q", "a", "b"], ["-qv", "x"], ["--bogus", "-q", "x"], ["-q", "--expect-eku", "--json", "x"]]) {
        const result = await check(args);
        assert.deepEqual([args.join(" "), result.code, result.stdout, result.stderr], [args.join(" "), 2, "", ""]);
    }
    // Today: the parser that reads -q leniently gives it to a flag that takes a value, as inspect does with --select.
    const swallowed = await check(["--warn-only", "-q", typed("leaf-p256.pem")]);
    assert.equal(swallowed.code, 2);
    assert.match(swallowed.stderr, /^certdrift: Option '--warn-only(?: <value>)?' argument is ambiguous/);
});

test("the observation's warnings are printed after the results and before the summary, escaped, so that a rule about the kind never passes in silence", async (t) => {
    // CN bc-twice: basicConstraints critical, CA:TRUE, twice, which is not valid X.509. Made like the
    // certificates of test/kind.test.js, from fixed bytes: Node.js reads it as an end-entity certificate.
    const pem = [
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
    const dir = scratch(t);
    const certificate = written(dir, "twice.pem", pem);
    const policy = written(dir, "kind.json", '{"contract":1,"expectKind":{"value":"end-entity"}}');
    const observation = inspect(pem);
    assert.equal(observation.certificates[0].kind, "end-entity");
    assert.equal(observation.warnings[0].code, "KIND_UNRELIABLE");

    const result = await check(["--as-of", "2026-06-01", "--policy", policy, certificate]);
    assert.equal(result.code, 0, result.stderr);
    const lines = result.stdout.split("\n");
    const ok = lines.findIndex((line) => /^ {2}OK {4}expectKind +TARGET_NOT_END_ENTITY /.test(line));
    const heading = lines.indexOf("Warnings");
    const warning = lines.findIndex((line) => line.startsWith("  KIND_UNRELIABLE [0] "));
    const summary = lines.indexOf("0 failed · exit 0");
    assert.ok(ok > 0 && ok < heading && heading < warning && warning < summary, `${ok} ${heading} ${warning} ${summary}\n${result.stdout}`);
    assert.equal(lines[warning], `  KIND_UNRELIABLE [0] ${observation.warnings[0].message.replace(/[\u0000-\u001f]/g, "")}`);
    assert.equal(lines.at(-2), "0 failed · exit 0", "the summary stays last");
    assert.equal(lines[heading - 1], "", "a blank line before the warnings");
    assert.equal(lines[summary - 1], "", "a blank line before the summary");

    // With none, there is no heading.
    const clean = await check(["--as-of", startOf("leaf-p256.pem"), "--policy", policy, typed("leaf-p256.pem")]);
    assert.doesNotMatch(clean.stdout, /Warnings/);

    // --json carries them in the observation, as it always did.
    const json = jsonOf(await check(["--json", "--as-of", "2026-06-01", "--policy", policy, certificate]));
    assert.equal(json.observation.warnings[0].code, "KIND_UNRELIABLE");
});

// ---------------------------------------------------------------------------------------------
// Exit codes

test("exit 0 when no result fails, even when one is a warning, and exit 1 when one fails", async () => {
    const start = startOf("leaf-p256.pem");
    const warned = await check(["--as-of", start, "--policy", policyPath("empty"), typed("leaf-p256.pem")]);
    assert.equal(warned.code, 0);
    assert.match(warned.stdout, /WARN/);

    // A certificate whose dates are fixed in the past.
    const expired = await check(["--reject-eku", "codeSigning", typed("leaf-expired.pem")]);
    assert.equal(expired.code, 1);
    // An instant a second before the certificate starts, taken from the certificate.
    const early = await check(["--as-of", shifted(start, -1), "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
    assert.equal(early.code, 1);
    assert.match(early.stdout, /^ {2}FAIL {2}validityStarted +NOT_YET_VALID /m);
    // The instant it starts is inside the validity.
    const exact = await check(["--as-of", start, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
    assert.equal(exact.code, 0);
});

test("exit 2 for an ambiguous bundle lists the candidates, and --select resolves it", async () => {
    const result = await check([...ALWAYS_PASSES, typed("bundle-two-leaves.pem")]);
    assert.deepEqual([result.code, result.stdout], [2, ""]);
    for (const name of ["leaf-rsa.pem", "leaf-p256.pem"]) assert.ok(result.stderr.includes(inspect(fixture(name)).certificates[0].sha256), name);
    assert.match(result.stderr, /input block 1: .*\ninput block 2: /);
    assert.match(result.stderr, /Use --select with the start of one sha256 to choose\.\n$/);

    const sha256 = inspect(fixture("leaf-rsa.pem")).certificates[0].sha256;
    const chosen = jsonOf(await check(["--json", "--select", sha256.slice(0, 12), ...ALWAYS_PASSES, typed("bundle-two-leaves.pem")]));
    assert.equal(chosen.observation.certificates[chosen.observation.target].sha256, sha256);
    const none = await check(["--select", "0".repeat(10), ...ALWAYS_PASSES, typed("bundle-two-leaves.pem")]);
    assert.equal(none.code, 2);
    assert.match(none.stderr, /matches no candidate/);
});

test("exit 3 for a certificate that is missing or is not one, and for standard input that holds none", async (t) => {
    const dir = scratch(t);
    const text = written(dir, "text.pem", "this is not a certificate\n");
    for (const [path, options, message] of /** @type {[string, import("./helpers/command.js").RunOptions, RegExp][]} */ ([
        [join(dir, "missing.pem"), {}, /^certdrift: cannot read .*missing\.pem: ENOENT/],
        [text, {}, /^certdrift: .*text\.pem: the material holds no certificate/],
        [typed("leaf-p256.key"), {}, /the material holds no certificate/],
        ["-", { input: "" }, /^certdrift: standard input: /],
        ["-", { input: "hello" }, /^certdrift: standard input: the material holds no certificate/],
    ])) {
        const result = await check([...ALWAYS_PASSES, path], options);
        assert.deepEqual([path, result.code, result.stdout], [path, 3, ""]);
        assert.match(result.stderr, message, path);
    }
});

test("a policy that lists matchesPrivateKey is exit 2, because check is not given a private key", async (t) => {
    const dir = scratch(t);
    const path = written(dir, "key.json", '{"contract":1,"matchesPrivateKey":{}}');
    const result = await check(["--as-of", startOf("leaf-p256.pem"), "--policy", path, typed("leaf-p256.pem")]);
    assert.deepEqual([result.code, result.stdout], [2, ""]);
    assert.equal(result.stderr.split("\n").slice(0, 2).join("\n"), `certdrift: ${path}: the policy is not valid: 1 problem\n  /matchesPrivateKey: needs a private key, and none is given`);
    // The material is read first, so a missing certificate is the first thing said.
    const missing = await check(["--policy", path, "missing.pem"]);
    assert.equal(missing.code, 3);
});

test("a TypeError from evaluate is a bug of the command and exits 4, and only a PolicyError is exit 2", async (t) => {
    const dir = scratch(t);
    for (const entry of ["bin", "src", "schema", "package.json"]) cpSync(new URL(`../${entry}`, import.meta.url).pathname, join(dir, entry), { recursive: true });
    const file = join(dir, "src", "evaluate.js");
    const source = readFileSync(file, "utf8");
    const header = "export function evaluate(observation, policy, options) {\n";
    assert.ok(source.includes(header));
    const script = join(dir, "bin", "certdrift.js");
    const args = ["check", "--reject-eku", "codeSigning", join(CWD, typed("leaf-p256.pem"))];

    writeFileSync(file, source.replace(header, `${header}    throw new TypeError("a bug found in evaluate");\n`));
    const crashed = await run(args, { script, cwd: dir });
    assert.deepEqual([crashed.code, crashed.stdout], [4, ""]);
    assert.match(crashed.stderr, /^TypeError: a bug found in evaluate$/m);
    assert.doesNotMatch(crashed.stderr, /^certdrift: /);

    writeFileSync(file, source.replace(header, `${header}    throw new PolicyError([{ path: "/expectKind", message: "is made up" }]);\n`));
    const policy = await run(args, { script, cwd: dir });
    assert.deepEqual([policy.code, policy.stdout], [2, ""]);
    assert.match(policy.stderr, /^certdrift: the policy is not valid: 1 problem\n {2}\/expectKind: is made up\n/);
});

test("exitOf is 1 exactly when a result failed", () => {
    const observation = inspect(fixture("leaf-p256.pem"));
    const ok = evaluate(observation, { contract: 1 });
    assert.equal(exitOf(ok), 0);
    const failed = evaluate(observation, { contract: 1, expectKind: { value: "end-entity", severity: "fail" }, expectEku: { value: ["codeSigning"] } });
    assert.equal(exitOf(failed), 1);
    const warned = evaluate(observation, { contract: 1, expectEku: { value: ["codeSigning"], severity: "warn" } });
    assert.equal(exitOf(warned), 0);
});

// ---------------------------------------------------------------------------------------------
// Over every fixture and every example policy

const fixtureNames = readdirSync(new URL("fixtures/", import.meta.url)).filter((name) => /\.(pem|der)$/.test(name)).sort();

/**
 * Runs `work` for every certificate fixture, a dozen at a time.
 * @template T
 * @param {(name: string) => Promise<T>} work
 * @returns {Promise<[string, T][]>}
 */
async function overEveryFixture(work) {
    const names = fixtureNames;
    assert.ok(names.length > 30, `found ${names.length} certificate fixtures`);
    /** @type {[string, T][]} */
    const done = [];
    for (let start = 0; start < names.length; start += 12) {
        done.push(...(await Promise.all(names.slice(start, start + 12).map(async (name) => /** @type {[string, T]} */ ([name, await work(name)])))));
    }
    return done;
}

test("--json over every certificate fixture validates against the check result schema, by path and through standard input, and is what evaluate gives", { timeout: 120_000 }, async () => {
    const checked = await overEveryFixture(async (name) => {
        const { certificate, select } = targetOf(name);
        const args = ["--json", "--as-of", certificate.notBefore, "--reject-eku", "codeSigning", ...select];
        const [byPath, byStdin] = await Promise.all([check([...args, typed(name)]), check([...args, "-"], { input: fixture(name) })]);
        return { certificate, byPath, byStdin };
    });
    for (const [name, { certificate, byPath, byStdin }] of checked) {
        for (const [how, result] of /** @type {[string, import("./helpers/command.js").Result][]} */ ([["path", byPath], ["stdin", byStdin]])) {
            assert.equal(result.code, 0, `${name} by ${how}: ${result.stderr}`);
            const printed = jsonOf(result);
            assert.deepEqual(errorsOf(printed), [], `${name} by ${how}`);
            assert.equal(result.stdout, serializeCheckResult(printed), `${name} by ${how}`);
            assert.deepEqual(withoutObservation(printed), expectedFor(name, { contract: 1, rejectEku: { value: ["codeSigning"] } }, certificate.notBefore), `${name} by ${how}`);
        }
    }
});

test("every example policy over every certificate fixture: the empty one gives POLICY_EMPTY, server.json is what evaluate gives, and every-rule.json and pinned.json are exit 2 at /matchesPrivateKey because check takes no private key yet", { timeout: 240_000 }, async () => {
    const checked = await overEveryFixture(async (name) => {
        const { certificate, select } = targetOf(name);
        const run_ = (/** @type {string} */ policy) => check(["--json", "--as-of", certificate.notBefore, "--policy", policyPath(policy), ...select, typed(name)]);
        const [empty, server, everyRule, pinned] = await Promise.all([run_("empty"), run_("server"), run_("every-rule"), run_("pinned")]);
        return { certificate, empty, server, everyRule, pinned };
    });
    const server = JSON.parse(readFileSync(policyUrl("server"), "utf8"));
    for (const [name, { certificate, empty, server: served, everyRule, pinned }] of checked) {
        assert.equal(empty.code, 0, `${name}: ${empty.stderr}`);
        const emptied = jsonOf(empty);
        assert.deepEqual(errorsOf(emptied), [], name);
        assert.deepEqual(emptied.results.map((/** @type {{ code: string }} */ one) => one.code), ["NOT_YET_VALID", "EXPIRED", "POLICY_EMPTY"], name);

        assert.equal(served.code, 1, `${name}: ${served.stderr}`);
        const printed = jsonOf(served);
        assert.deepEqual(errorsOf(printed), [], name);
        assert.deepEqual(withoutObservation(printed), expectedFor(name, server, certificate.notBefore), name);

        for (const [which, result] of /** @type {[string, import("./helpers/command.js").Result][]} */ ([["every-rule", everyRule], ["pinned", pinned]])) {
            assert.deepEqual([name, which, result.code, result.stdout], [name, which, 2, ""]);
            assert.match(result.stderr, new RegExp(`^certdrift: schema/examples/policy/${which}\\.json: the policy is not valid: 1 problem\\n  /matchesPrivateKey: needs a private key, and none is given\\n`), `${name} ${which}`);
        }
    }
});

// ---------------------------------------------------------------------------------------------
// The command line as a whole

test("certdrift --help describes both commands, and says where to find the options of each", async () => {
    const result = await run(["--help"]);
    assert.deepEqual([result.code, result.stderr], [0, ""]);
    assert.match(result.stdout, /^certdrift inspects and checks X\.509 certificates\./);
    assert.match(result.stdout, /^ {2}inspect {2}\S/m);
    assert.match(result.stdout, /^ {2}check {4}\S/m);
    assert.match(result.stdout, /certdrift inspect --help or certdrift check --help/);
    for (const args of [["-h"], ["--help", "inspect"], ["--help", "--bogus"]]) assert.equal((await run(args)).stdout, result.stdout, args.join(" "));
    assert.equal((await run(["-q", "--help"])).stdout, "", "-q before the command is an unknown command, which is silent");
});

test("certdrift check --help lists exactly the flags check takes, each with its own line, and the exit codes 0 to 4", async () => {
    const help = await run(["check", "--help"]);
    assert.deepEqual([help.code, help.stderr], [0, ""]);
    const listed = help.stdout.split("\n").flatMap((line) => {
        const match = /^ {2}(?:-\w, )?--([a-z-]+)[ \n]/.exec(line);
        return match === null ? [] : [match[1]];
    });
    assert.deepEqual([...listed].sort(), Object.keys(CHECK_OPTIONS).sort());
    for (const [name, option] of Object.entries(CHECK_OPTIONS)) {
        if ("short" in option) assert.match(help.stdout, new RegExp(`^  -${option.short}, --${name}[ \\n]`, "m"), name);
    }
    for (const code of [0, 1, 2, 3, 4]) assert.match(help.stdout, new RegExp(`^  ${code}  `, "m"), `exit ${code}`);
    assert.match(help.stdout, /NO_COLOR/);
    assert.match(help.stdout, /^Usage: certdrift check .*<path \| ->$/m);
    assert.match(help.stdout, /POLICY_EMPTY/);
    assert.doesNotMatch(help.stdout, /--query|--host|--servername|--timeout|--verbose/);
    // inspect never exits 1, so its own help does not list it.
    const inspectHelp = await run(["inspect", "--help"]);
    assert.doesNotMatch(inspectHelp.stdout, /^ {2}1 {2}/m);
    assert.match(inspectHelp.stdout, /certdrift check/);
});

test("an unknown command is misuse and names the two that exist, and misuse of each command prints its own usage", async () => {
    const unknown = await run(["frobnicate", "x"]);
    assert.deepEqual([unknown.code, unknown.stdout], [2, ""]);
    assert.match(unknown.stderr, /^certdrift: unknown command "frobnicate"; the commands are inspect and check\nUsage: certdrift inspect .*\n {7}certdrift check .*\nRun certdrift --help for the commands\.\n$/);
    const none = await run([]);
    assert.equal(none.code, 2);
    assert.match(none.stderr, /^certdrift: no command given\nUsage: /);
    // Names that every object has are not commands.
    for (const name of ["constructor", "__proto__", "toString", "Check", "CHECK", "checks", "--check"]) {
        assert.equal((await run([name])).code, 2, name);
    }

    const check_ = await check([]);
    assert.match(check_.stderr, /^certdrift: no path given; use "-" to read standard input\nUsage: certdrift check .*\nRun certdrift check --help for the options\.\n$/);
    assert.doesNotMatch(check_.stderr, /certdrift inspect/);
    const inspected = await run(["inspect"]);
    assert.match(inspected.stderr, /^certdrift: no path given; .*\nUsage: certdrift inspect .*\n.*\nRun certdrift inspect --help for the options\.\n$/s);
    assert.doesNotMatch(inspected.stderr, /certdrift check/);
});

test("--quiet is read for the command that is asked: silent misuse for an unknown command, for check and for inspect", async () => {
    for (const args of [["-q"], ["-q", "frobnicate"], ["frobnicate", "-q"], ["check", "-q"], ["inspect", "-q"], ["check", "-q", "--bogus"], ["inspect", "-q", "--bogus"]]) {
        const result = await run(args);
        assert.deepEqual([args.join(" "), result.code, result.stdout, result.stderr], [args.join(" "), 2, "", ""]);
    }
    // Before the command is known only --quiet is a flag, so a value taken by another command's flag is not taken here.
    const unknown = await run(["frobnicate", "--select", "-q"]);
    assert.deepEqual([unknown.code, unknown.stdout, unknown.stderr], [2, "", ""]);
});

// ---------------------------------------------------------------------------------------------
// What both commands share, the marks and the documentation

const binFiles = readdirSync(new URL("../bin/", import.meta.url)).filter((name) => name.endsWith(".js")).sort();
const binSource = (/** @type {string} */ name) => readFileSync(new URL(`../bin/${name}`, import.meta.url), "utf8");

test("reading a path or -, the library's two errors, the lenient --quiet and the NO_COLOR test are written once, in bin/command.js, and both commands import them", () => {
    assert.ok(binFiles.includes("command.js") && binFiles.includes("check.js") && binFiles.includes("cli.js"), binFiles.join(", "));
    /** What each thing looks like where it is written, and where it may be. @type {[string, RegExp][]} */
    const written_ = [
        ["reading standard input to its end", /for await \(const chunk of/],
        ["the lenient parse of --quiet", /strict: false/],
        ["the NO_COLOR test", /env\.NO_COLOR|\.NO_COLOR/],
        ["the answer to a ParseError", /instanceof ParseError/],
        ["the answer to an AmbiguousTargetError", /instanceof AmbiguousTargetError/],
        ["the line for a warning of the observation", /paint\("yellow", safe\(code\)\)/],
        ["the parser's own complaints", /ERR_PARSE_ARGS_/],
    ];
    for (const [what, pattern] of written_) {
        const where = binFiles.filter((name) => pattern.test(binSource(name)));
        assert.deepEqual(where, ["command.js"], what);
    }
    for (const name of ["cli.js", "check.js"]) assert.match(binSource(name), /from "\.\/command\.js"/, name);
    assert.match(binSource("cli.js"), /from "\.\/check\.js"/);
    assert.doesNotMatch(binSource("check.js"), /from "\.\/cli\.js"/);
    assert.doesNotMatch(binSource("command.js"), /from "\.\/(cli|check|host|query)\.js"/);
});

test("bin/ holds no table of reason codes: the entry of a code is the library's answer", () => {
    const codes = ["EXPIRED", "NOT_YET_VALID", "EXPIRES_SOON", "LIFETIME_USED_EXCEEDED", "EKU_MISSING", "EKU_NOT_PERMITTED", "EKU_FORBIDDEN", "SAN_MISSING", "FINGERPRINT_MISMATCH", "TARGET_NOT_END_ENTITY", "KEY_MISMATCH", "KEY_UNREADABLE", "POLICY_EMPTY", "RULE_ERROR"];
    for (const code of codes) assert.equal(entryOfCode(code) === null, ["POLICY_EMPTY", "RULE_ERROR"].includes(code), code);
    for (const name of binFiles) {
        for (const code of codes) assert.doesNotMatch(binSource(name), new RegExp(`["'\`]${code}["'\`]`), `${name} writes ${code} as a value`);
    }
});

test("no PENDING mark is left, and the help and the README name certdrift check where they said the checking command", async () => {
    for (const name of binFiles) assert.doesNotMatch(binSource(name), /PENDING/, name);
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    assert.doesNotMatch(readme, /PENDING/);
    assert.doesNotMatch(readme, /the checking command/);
    for (const args of [["--help"], ["inspect", "--help"], ["check", "--help"]]) {
        const help = (await run(args)).stdout;
        assert.doesNotMatch(help, /the checking command/, args.join(" "));
        assert.doesNotMatch(help, /PENDING/);
    }
    assert.match((await run(["inspect", "--help"])).stdout.replace(/\s+/g, " "), /To make a decision, use certdrift check/);
});

/** The section of the README that documents check, without the formatting of its code. */
function checkSection() {
    const text = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const start = text.indexOf("\n## Checking a certificate\n");
    assert.notEqual(start, -1, "the README has a section on check");
    return text.slice(start + 1, text.indexOf("\n## ", start + 1));
}

test("the README documents every flag check takes, the output, the exit codes and how a policy file and the options combine", () => {
    const section = checkSection();
    for (const name of Object.keys(CHECK_OPTIONS)) assert.ok(section.includes(`--${name}`), `the README documents --${name}`);
    const flat = section.replaceAll("`", "").replace(/\s+/g, " ");
    for (const part of [
        "exits with 1", "An option that gives an entry the file already has is exit 2", "--warn-only <code> is how a rule of the file", "nothing to check", "POLICY_EMPTY",
        "YYYY-MM-DD", "never changes the observation's at", "checked at", "KIND_UNRELIABLE", "NO_COLOR", "--quiet prints nothing and wins over --json", "66.3% is the threshold 0.663",
    ]) assert.ok(flat.includes(part), `the README says: ${part}`);
    const exits = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    assert.match(exits, /^\| `1` \| A check failed/m);
});

test("the README examples of check run against fixtures and end with an exit code the README documents", { timeout: 120_000 }, async (t) => {
    const dir = scratch(t);
    // What the files named in the README stand for.
    writeFileSync(join(dir, "server.pem"), fixture("leaf-p256.pem"));
    writeFileSync(join(dir, "policy.json"), readFileSync(policyUrl("server")));
    const sh = [...checkSection().matchAll(/```sh\n([\s\S]*?)```/g)].flatMap((block) => block[1].split("\n")).filter((line) => line.startsWith("certdrift check"));
    assert.ok(sh.length >= 5, `the README has ${sh.length} examples of check`);

    for (const line of sh) {
        const redirect = /^(.*) < (\S+)$/.exec(line);
        const words = (redirect === null ? line : redirect[1]).split(" ").slice(1);
        for (const word of words) assert.doesNotMatch(word, /['"$|;&]/, `the example ${line} uses only plain words`);
        const files = words.filter((word) => /\.(pem|json)$/.test(word));
        for (const file of files) assert.ok(["server.pem", "policy.json"].includes(file), `${line} names ${file}, which this test does not know`);
        const result = await run(words, { cwd: dir, ...(redirect === null ? {} : { input: readFileSync(join(dir, redirect[2])) }) });
        assert.ok(result.code === 0 || result.code === 1, `${line}: exit ${result.code}\n${result.stderr}`);
        if (words.includes("--json")) assert.deepEqual(errorsOf(JSON.parse(result.stdout)), [], line);
        else assert.ok(result.stdout.endsWith(`exit ${result.code}\n`), `${line}\n${result.stdout}`);
    }
    // The commands the README shows with the output it shows.
    const shown = checkSection().match(/```text\n([\s\S]*?)```/);
    assert.ok(shown, "the README shows an output");
    assert.match(shown[1], /^server\.pem {2}checked at \S+\n {2}OK {2} {2}validityStarted/);
});

// ---------------------------------------------------------------------------------------------
// Cases the criteria do not name and the purpose of the command covers

test("a name, an address and a usage are compared the way the observation writes them: case, IPv6 forms and an OID for a name", async () => {
    const { certificate } = targetOf("leaf-san-kinds.pem");
    assert.deepEqual(certificate.san.ip, ["192.0.2.10", "2001:db8::1"]);
    const result = await check(["--json", "--as-of", certificate.notBefore, "--expect-san", "KINDS.Example", "--expect-san", "192.0.2.10", "--expect-san", "2001:DB8:0:0:0:0:0:1", "--expect-eku", "1.3.6.1.5.5.7.3.1", "--reject-eku", "1.3.6.1.5.5.7.3.3", typed("leaf-san-kinds.pem")]);
    assert.equal(result.code, 0, result.stderr);
    const printed = jsonOf(result);
    assert.deepEqual(printed.results.at(-1).expected, { dns: ["kinds.example"], ip: ["192.0.2.10", "2001:db8::1"] });
    assert.deepEqual(printed.results.at(-3).expected, ["serverAuth"], "an OID is the same usage as its name");
    assert.deepEqual(printed.results.at(-2).expected, ["codeSigning"]);

    // A wildcard is compared as written: a certificate that lists a name does not satisfy it.
    const wildcard = await check(["--as-of", certificate.notBefore, "--expect-san", "*.example", typed("leaf-san-kinds.pem")]);
    assert.equal(wildcard.code, 1);
    assert.match(wildcard.stdout, /the certificate does not list \*\.example/);
});

test("today: an email address or a URI is not a value --expect-san accepts, because a name is a DNS name or an address", async () => {
    for (const value of ["ops@example.com", "https://example.com/service"]) {
        const result = await check([`--expect-san=${value}`, typed("leaf-san-kinds.pem")]);
        assert.equal(result.code, 2, value);
        assert.match(result.stderr, /^certdrift: the requirement options are not valid: 1 problem\n {2}--expect-san: /);
    }
});

test("a value with a line break in it cannot add a line to the message that names it", async () => {
    const result = await check(["--expect-san", "a\nUsage: forged", "--expect-san", "x y", typed("leaf-p256.pem")]);
    assert.equal(result.code, 2);
    assert.deepEqual(result.stderr.split("\n").slice(0, 3), [
        "certdrift: the requirement options are not valid: 2 problems",
        '  --expect-san: "a\\nUsage: forged" is not a value this flag accepts',
        '  --expect-san: "x\\u{2028}y" is not a value this flag accepts',
    ]);
    const code = await check(["--warn-only", "A\nB", "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
    assert.equal(code.code, 2);
    assert.equal(code.stderr.split("\n")[1], '  "A\\nB" is not one');
});

test("a duration of seven digits is refused, and one of six is accepted", async () => {
    const start = startOf("leaf-p256.pem");
    assert.equal((await check(["--as-of", start, "--expires-within", "1000000d", typed("leaf-p256.pem")])).code, 2);
    const six = await check(["--json", "--as-of", start, "--expires-within", "999999h", typed("leaf-p256.pem")]);
    assert.equal(six.code, 1, "more hours are asked for than the certificate has");
    assert.equal(jsonOf(six).results.at(-1).code, "EXPIRES_SOON");
});

test("flags may come before or after the path, and -- lets a path start with a dash", async (t) => {
    const start = startOf("leaf-p256.pem");
    const before = await check(["--json", "--as-of", start, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]);
    const after = await check([typed("leaf-p256.pem"), "--reject-eku", "codeSigning", "--as-of", start, "--json"]);
    assert.deepEqual(withoutObservation(jsonOf(before)), withoutObservation(jsonOf(after)));

    const dir = scratch(t);
    writeFileSync(join(dir, "-x.pem"), fixture("leaf-p256.pem"));
    writeFileSync(join(dir, "-"), fixture("leaf-p256.pem"));
    const dashed = await check(["--json", "--as-of", start, "--reject-eku", "codeSigning", "--", "-x.pem"], { cwd: dir });
    assert.deepEqual(jsonOf(dashed).observation.observation.source, { kind: "file", ref: "-x.pem" });
    const named = await check(["--json", "--as-of", start, "--reject-eku", "codeSigning", "./-"], { cwd: dir });
    assert.deepEqual(jsonOf(named).observation.observation.source, { kind: "file", ref: "./-" });
});

test("standard input that is closed, or that holds nothing, is exit 3 for the certificate and for the policy", async () => {
    const closed = await check([...ALWAYS_PASSES, "-"]);
    assert.deepEqual([closed.code, closed.stdout, closed.stderr], [3, "", "certdrift: standard input: the material is empty\n"]);
    const policy = await check(["--policy", "-", typed("leaf-p256.pem")], { input: "" });
    assert.deepEqual([policy.code, policy.stderr], [3, "certdrift: standard input: the policy is not valid JSON\n"]);
});

test("a policy file with a number JSON cannot hold, or a contract that is text, is exit 2 and says so under its path", async (t) => {
    const dir = scratch(t);
    const infinite = written(dir, "infinite.json", '{"contract":1,"maxLifetimeUsed":{"value":1e999}}');
    const result = await check(["--policy", infinite, typed("leaf-p256.pem")]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /\n {2}\/maxLifetimeUsed\/value: is not a finite number, which JSON cannot hold\n/);
    const text = written(dir, "text.json", '{"contract":"1"}');
    const contract = await check(["--policy", text, typed("leaf-p256.pem")]);
    assert.equal(contract.code, 2);
    assert.match(contract.stderr, /\n {2}\/contract: contract is not one this version knows: it must be 1\n/);
});

test("the policy file and the certificate may be the same file: a policy is not read as a certificate, and a bundle is not read as a policy", async () => {
    const result = await check(["--policy", typed("bundle-ordered.pem"), typed("bundle-ordered.pem")]);
    assert.equal(result.code, 3);
    assert.match(result.stderr, /the policy is not valid JSON/);
});

test("when several mistakes are made at once, the one reported is the first of a fixed order, and nothing is read before the options are settled", async (t) => {
    const dir = scratch(t);
    const invalid = written(dir, "invalid.json", '{"contract":1,"expectEku":{"value":5}}');
    const withEku = written(dir, "eku.json", '{"contract":1,"expectEku":{"value":["serverAuth"]}}');
    const certificate = typed("leaf-p256.pem");
    // Each line breaks two rules, and the message is the one of the rule that comes first: what the
    // parser refuses, a flag given twice, a path, an empty --select, standard input twice, --as-of, the
    // form of --lifetime-used, nothing to check, the values the policy refuses, a --warn-only code that
    // names no entry, and, once the files are read, the policy file, a flag that gives an entry the file
    // has, a --warn-only code whose rule is not checked, and last the certificate.
    /** @type {[string, string[], number, RegExp][]} */
    const table = [
        ["an unknown option before a repeated flag", ["--bogus", "--select", "a", "--select", "a", certificate], 2, /^certdrift: Unknown option '--bogus'/],
        ["a repeated flag before a missing path", ["--expires-within", "30d", "--expires-within", "30d"], 2, /^certdrift: --expires-within was given more than once\n/],
        ["a repeated --as-of before a repeated --select", ["--select", "a", "--select", "a", "--as-of", "x", "--as-of", "x", certificate], 2, /^certdrift: --as-of was given more than once\n/],
        ["a repeated --policy before a repeated --as-of", ["--as-of", "x", "--as-of", "x", "--policy", "p", "--policy", "p", certificate], 2, /^certdrift: --policy was given more than once\n/],
        ["a missing path before an empty --select", ["--select=", "--reject-eku", "codeSigning"], 2, /^certdrift: no path given; /],
        ["two paths before an empty --select", ["--select=", "--reject-eku", "codeSigning", "a.pem", "b.pem"], 2, /^certdrift: expected one path, got 2\n/],
        ["an empty --select before standard input twice", ["--select=", "--policy", "-", "-"], 2, /^certdrift: --select needs the start of a sha256, and it is empty\n/],
        ["standard input twice before a bad --as-of", ["--policy", "-", "--as-of", "x", "-"], 2, /^certdrift: --policy - and the path - both read standard input/],
        ["a bad --as-of before a bad percentage", ["--as-of", "x", "--lifetime-used=abc", certificate], 2, /^certdrift: --as-of needs a date/],
        ["a bad --as-of before nothing to check", ["--as-of", "x", certificate], 2, /^certdrift: --as-of needs a date/],
        ["a bad percentage before a value the policy refuses", ["--lifetime-used=abc", "--expect-eku", "bogus", certificate], 2, /^certdrift: --lifetime-used needs a percentage/],
        ["nothing to check before a --warn-only code that names no entry", ["--warn-only", "NOPE", certificate], 2, /^certdrift: nothing to check: /],
        ["a value the policy refuses before a --warn-only code that names no entry", ["--expect-eku", "bogus", "--warn-only", "NOPE", certificate], 2, /^certdrift: the requirement options are not valid: 1 problem\n/],
        ["a --warn-only code that names no entry before a policy file that is missing", ["--warn-only", "NOPE", "--policy", "missing.json", certificate], 2, /^certdrift: --warn-only needs the reason code /],
        ["a policy file that is missing before a certificate that is missing", ["--policy", "missing.json", "missing.pem"], 3, /^certdrift: cannot read missing\.json: /],
        ["a policy file that is not JSON before a flag that conflicts", ["--policy", written(dir, "nojson.json", "{"), "--expect-eku", "serverAuth", certificate], 3, /the policy is not valid JSON\n$/],
        ["a policy file that is not valid before a flag that conflicts", ["--policy", invalid, "--expect-eku", "serverAuth", certificate], 2, /the policy is not valid: 1 problem\n {2}\/expectEku\/value: /],
        ["a flag that conflicts before a --warn-only code whose rule is not checked", ["--policy", withEku, "--expect-eku", "clientAuth", "--warn-only", "SAN_MISSING", certificate], 2, /the options and the policy file give the same entry\n/],
        ["a --warn-only code whose rule is not checked before a certificate that is missing", ["--warn-only", "SAN_MISSING", "--policy", policyPath("empty"), "missing.pem"], 2, /^certdrift: --warn-only names a rule this run does not check\n/],
        ["a certificate that is missing before a policy that needs a key", ["--policy", policyPath("pinned"), "missing.pem"], 3, /^certdrift: cannot read missing\.pem: /],
    ];
    for (const [name, args, code, message] of table) {
        const result = await check(args, { input: "" });
        assert.deepEqual([name, result.code, result.stdout], [name, code, ""]);
        assert.match(result.stderr, message, name);
    }
});
