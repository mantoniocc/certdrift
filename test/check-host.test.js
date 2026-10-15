import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { AmbiguousTargetError, inspect } from "../src/index.js";
import { CHECK_OPTIONS } from "../bin/check.js";
import { HOST_OPTIONS } from "../bin/host.js";
import { fixture, run, runMain, targetOf } from "./helpers/command.js";
import { validatorFor } from "./helpers/schema.js";
import { closedPort, serveChain, serveSilent, serveWith } from "./helpers/tls.js";

// `certdrift check --host`: the same requirements applied to the certificates a server sends. The
// host code is shared and tested in host.test.js and cli.test.js; what is shown here is what
// `check` does with it. Every server is local and every run names the instant it evaluates at, so
// nothing depends on the clock, on the network or on the bytes of a fixture.

const errorsOf = validatorFor("check-result");
const SERVED = ["leaf-p256.pem", "intermediate.pem"];
const LEAF = targetOf("leaf-p256.pem").certificate;
const RSA = targetOf("leaf-rsa.pem").certificate;
/** An instant at which the served leaf has started and not ended. */
const AT = LEAF.notBefore;
/** The two rules every certificate passes at any instant, so that a run's exit code is about something else. */
const ALWAYS_PASSES = ["--warn-only", "EXPIRED", "--warn-only", "NOT_YET_VALID", "--reject-eku", "codeSigning"];

/** The path of a fixture, which does not depend on where the tests are run from. @param {string} name */
const typed = (name) => new URL(`fixtures/${name}`, import.meta.url).pathname;

/** @param {{ port: number }} server */
const hostOf = (server) => `127.0.0.1:${server.port}`;

/** @param {string[]} args @param {{ input?: string | Uint8Array }} [options] */
const checkMain = (args, options) => runMain(["check", ...args], options);

/** @param {string[]} args @param {import("./helpers/command.js").RunOptions} [options] */
const check = (args, options) => run(["check", ...args], options);

/** The JSON a run printed, which must be the whole of standard output. @param {import("./helpers/command.js").Result} result */
function jsonOf(result) {
    assert.equal(result.stderr, "", result.stderr);
    return JSON.parse(result.stdout);
}

/** @param {any} printed */
function withoutObservation(printed) {
    const { observation: _observation, ...rest } = printed;
    return rest;
}

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

/** @param {string} dir @param {string} name @param {string | Uint8Array} content */
function written(dir, name, content) {
    const path = join(dir, name);
    writeFileSync(path, content);
    return path;
}

/** The SHA-256 of both candidates of a material with two end-entity certificates. @param {string} name */
function candidatesOf(name) {
    try {
        inspect(fixture(name));
    } catch (error) {
        if (error instanceof AmbiguousTargetError) return error.candidates.map(({ sha256 }) => sha256);
        throw error;
    }
    throw new Error(`${name} is not ambiguous`);
}

// ---------------------------------------------------------------------------------------------
// The flags

test("check --host takes the flags of check on a file and the three flags of inspect --host, defined once, and checks the certificate the server sent as inspect --host chooses it, --select included", async (t) => {
    for (const name of /** @type {const} */ (["host", "servername", "timeout"])) {
        assert.equal(CHECK_OPTIONS[name], HOST_OPTIONS[name], `check takes ${name} from HOST_OPTIONS`);
    }

    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    const result = await checkMain([
        "--host", host, "--servername", "named.example", "--timeout", "5000",
        "--as-of", AT, "--expect-eku", "serverAuth", "--eku-allows", "serverAuth", "--reject-eku", "codeSigning",
        "--expect-san", "p256.example", "--expect-fingerprint", LEAF.sha256, "--expires-within", "1d", "--lifetime-used", "100%",
        "--warn-only", "EXPIRED", "--select", LEAF.sha256.slice(0, 10), "--json",
    ]);
    assert.equal(result.code, 0, result.stderr);
    const printed = jsonOf(result);
    assert.deepEqual(errorsOf(printed), []);
    assert.deepEqual(server.names, ["named.example"], "the server name was sent");
    assert.deepEqual(printed.observation.observation.source, { kind: "host", ref: host, servername: "named.example" });

    // The certificate is the one inspect --host picks.
    const inspected = JSON.parse((await runMain(["inspect", "--json", "--host", host])).stdout);
    assert.equal(printed.observation.certificates[printed.observation.target].sha256, inspected.certificates[inspected.target].sha256);

    // A server with two end-entity certificates is ambiguous, as for a file, and --select chooses.
    const two = await serveChain(t, { certs: ["leaf-p256.pem", "leaf-rsa.pem"] });
    const ambiguous = await checkMain(["--host", hostOf(two), ...ALWAYS_PASSES]);
    assert.deepEqual([ambiguous.code, ambiguous.stdout], [2, ""]);
    assert.ok(ambiguous.stderr.startsWith(`certdrift: ${hostOf(two)}: `), ambiguous.stderr);
    for (const { sha256 } of [LEAF, RSA]) assert.ok(ambiguous.stderr.includes(sha256), "lists both candidates");
    assert.match(ambiguous.stderr, /Use --select/);
    for (const { sha256 } of [LEAF, RSA]) {
        const chosen = await checkMain(["--host", hostOf(two), "--json", "--select", sha256.slice(0, 12), ...ALWAYS_PASSES]);
        const observation = jsonOf(chosen).observation;
        assert.equal(observation.certificates[observation.target].sha256, sha256);
    }
});

// ---------------------------------------------------------------------------------------------
// The rules about the host flags

test("the rules about the host flags are inspect's and written once: misuse is exit 2 before the host is contacted, and the first line is the one inspect gives", async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    /** @type {string[][]} */
    const table = [
        ["--host", host, "--host", host],
        ["--host", host, "--servername", "a", "--servername", "a"],
        ["--host", host, "--timeout", "5", "--timeout", "5"],
        ["--host", host, "a.pem"],
        ["--host", host, "-"],
        ["--host", host, "--timeout", "0"],
        ["--host", host, "--timeout", "1e3"],
        ["--host", host, "--timeout", "010"],
        ["--servername", "a.example", "a.pem"],
        ["--timeout", "5", "a.pem"],
    ];
    for (const args of table) {
        const checked = await checkMain([...args, "--reject-eku", "codeSigning"]);
        const inspected = await runMain(["inspect", ...args]);
        assert.deepEqual([args.join(" "), checked.code, checked.stdout], [args.join(" "), 2, ""]);
        assert.equal(checked.stderr.split("\n")[0], inspected.stderr.split("\n")[0], args.join(" "));
        assert.match(checked.stderr, /\nUsage: certdrift check /, "check's own usage");
    }
    // --quiet keeps it silent, and the exit code.
    const quiet = await checkMain(["-q", "--host", host, "--host", host]);
    assert.deepEqual([quiet.code, quiet.stdout, quiet.stderr], [2, "", ""]);
    await sleep(50);
    assert.equal(server.accepted(), 0, "none of these connected");
});

test("when several mistakes are made at once, check reports the first of a fixed order that starts with the rules inspect has, and reads and contacts nothing before the command line is settled", async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    const dir = scratch(t);
    const validPolicy = written(dir, "policy.json", '{"contract":1}');
    const withFingerprint = written(dir, "fingerprint.json", `{"contract":1,"expectFingerprint":{"value":"${"ab".repeat(32)}"}}`);
    const twoLeaves = written(dir, "two-leaves.pem", fixture("bundle-two-leaves.pem"));
    const missing = join(dir, "missing");
    const flagged = ["--reject-eku", "codeSigning"];
    const sha = "ab".repeat(32);
    /** @type {[string, string[], number, RegExp][]} */
    const table = [
        ["an unknown option before a repeated host", ["--bogus", "--host", host, "--host", host], 2, /^certdrift: Unknown option '--bogus'/],
        ["a repeated --host before a repeated --servername", ["--host", host, "--host", host, "--servername", "a", "--servername", "a"], 2, /^certdrift: --host was given more than once\n/],
        ["a repeated --servername before a repeated --timeout", ["--host", host, "--servername", "a", "--servername", "a", "--timeout", "5", "--timeout", "5"], 2, /^certdrift: --servername was given more than once\n/],
        ["a path before a bad timeout", ["--host", host, "--timeout", "0", "a.pem"], 2, /^certdrift: --host takes no path and no "-"/],
        ["a bad timeout before a repeated --select", ["--host", host, "--timeout", "0", "--select", "a", "--select", "b"], 2, /^certdrift: --timeout needs a positive whole number of milliseconds, and got "0"\n/],
        ["a server name without a host before a repeated --select", ["--servername", "a", "--select", "a", "--select", "b", "a.pem"], 2, /^certdrift: --servername is sent to a host, so it needs --host\n/],
        ["a server name without a host before a repeated --expect-fingerprint-of", ["--servername", "a", "--expect-fingerprint-of", "x", "--expect-fingerprint-of", "y", "a.pem"], 2, /^certdrift: --servername is sent to a host, so it needs --host\n/],
        ["a repeated --expect-fingerprint-of before a missing path", ["--expect-fingerprint-of", "a", "--expect-fingerprint-of", "a"], 2, /^certdrift: --expect-fingerprint-of was given more than once\n/],
        ["a missing path before an empty --select", ["--select=", ...flagged], 2, /^certdrift: no path given; /],
        ["an empty --select before standard input twice", ["--host", host, "--select=", "--policy", "-", "--expect-fingerprint-of", "-"], 2, /^certdrift: --select needs the start of a sha256, and it is empty\n/],
        ["standard input twice before the two fingerprint options", ["--host", host, "--policy", "-", "--expect-fingerprint-of", "-", "--expect-fingerprint", sha], 2, /^certdrift: --policy - and --expect-fingerprint-of - both read standard input/],
        ["the two fingerprint options before --key -", ["--host", host, "--expect-fingerprint-of", "a.pem", "--expect-fingerprint", sha, "--key", "-"], 2, /^certdrift: the options give the same entry\n {2}--expect-fingerprint and --expect-fingerprint-of both give expectFingerprint/],
        ["--key - before a bad --as-of", ["--host", host, "--key", "-", "--as-of", "x", ...flagged], 2, /^certdrift: --key - would read the key/],
        ["a bad --as-of before nothing to check", ["--host", host, "--as-of", "x"], 2, /^certdrift: --as-of needs a date/],
        ["nothing to check before a target the module refuses", ["--host", "a b"], 2, /^certdrift: nothing to check: /],
        ["a value the policy refuses before a target the module refuses", ["--host", "a b", "--expect-eku", "bogus"], 2, /^certdrift: the requirement options are not valid: 1 problem\n/],
        ["a --warn-only code that names no entry before a target the module refuses", ["--host", "a b", "--warn-only", "NOPE", ...flagged], 2, /^certdrift: --warn-only needs the reason code /],
        ["a target the module refuses before a policy file that is missing", ["--host", "a b", "--policy", missing, ...flagged], 2, /^certdrift: target "a b" cannot be read: /],
        ["a target the module refuses before a key that is missing", ["--host", "a b", "--key", missing, ...flagged], 2, /^certdrift: target "a b" cannot be read: /],
        ["a target the module refuses before a fingerprint file that is missing", ["--host", "a b", "--expect-fingerprint-of", missing], 2, /^certdrift: target "a b" cannot be read: /],
        ["a server name the module refuses before a timeout it refuses", ["--host", host, "--servername", "192.0.2.1", "--timeout", "2147483648", ...flagged], 2, /^certdrift: options\.servername must be a host name in ASCII, not an IP address\n/],
        ["a policy file that is missing before a key and a fingerprint file that are missing", ["--host", host, "--policy", missing, "--key", missing, "--expect-fingerprint-of", missing], 3, /^certdrift: cannot read .*missing: /],
        ["an option that conflicts with the policy file before a key that is missing", ["--host", host, "--policy", withFingerprint, "--expect-fingerprint-of", typed("leaf-p256.pem"), "--key", missing], 2, /^certdrift: .*fingerprint\.json: the options and the policy file give the same entry\n {2}--expect-fingerprint-of gives expectFingerprint, which the policy file has/],
        ["a key that is missing before a fingerprint file that is missing", ["--host", host, "--policy", validPolicy, "--key", missing, "--expect-fingerprint-of", missing], 3, /^certdrift: cannot read .*missing: /],
        ["a fingerprint file with two candidates before a host that cannot be reached", ["--host", `127.0.0.1:${await closedPort()}`, "--expect-fingerprint-of", twoLeaves], 2, /two-leaves\.pem: 2 certificates in the material sign no other one/],
        ["a fingerprint file that is missing before a host that cannot be reached", ["--host", `127.0.0.1:${await closedPort()}`, "--expect-fingerprint-of", missing], 3, /^certdrift: cannot read .*missing: /],
    ];
    for (const [name, args, code, message] of table) {
        const result = await checkMain(args, { input: "" });
        assert.deepEqual([name, result.code, result.stdout], [name, code, ""]);
        assert.match(result.stderr, message, name);
        if (code === 3) assert.match(result.stderr, /^certdrift: cannot read /, `${name}: a file, not the host`);
    }
    await sleep(50);
    assert.equal(server.accepted(), 0, "none of these connected: every file an option names is read before the host");
});

test("a target the module refuses is exit 2 at once, and standard input left open is not waited on", { timeout: 40_000 }, async (t) => {
    const dir = scratch(t);
    for (const args of [
        ["--host", "a b", "--reject-eku", "codeSigning", "--policy", "-"],
        ["--host", "a b", "--expect-fingerprint-of", "-"],
        ["--host", "a b", "--reject-eku", "codeSigning", "--policy", join(dir, "missing.json")],
    ]) {
        const result = await check(args, { openStdin: true, killAfterMs: 15_000 });
        assert.deepEqual([args.join(" "), result.code, result.stdout], [args.join(" "), 2, ""]);
        assert.match(result.stderr, /^certdrift: target "a b" cannot be read: /);
    }
});

// ---------------------------------------------------------------------------------------------
// A host that cannot be checked

test("a host that does not answer, refuses the connection, does not speak TLS or answers too late is exit 3 with the headline of inspect --host, and an IP address target gets the hint about --servername", async (t) => {
    const plain = await serveWith(t, (socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
    const silent = await serveSilent(t);
    const closed = await closedPort();
    /** @type {[string, string[], RegExp][]} */
    const cases = [
        // A multicast address is refused by the system before any packet leaves: no network is needed.
        ["cannot be reached", ["--host", "224.0.0.1"], /^certdrift: 224\.0\.0\.1: cannot be reached: /],
        ["refuses the connection", ["--host", `127.0.0.1:${closed}`], new RegExp(`^certdrift: 127\\.0\\.0\\.1:${closed}: connection refused: `)],
        ["does not speak TLS", ["--host", hostOf(plain)], /^certdrift: 127\.0\.0\.1:\d+: the TLS handshake failed \(the host may not speak TLS\): wrong version number\nAn IP address sends no server name, [^\n]*try --servername <name>\.\n$/],
        ["does not answer in time", ["--host", hostOf(silent), "--timeout", "300"], /^certdrift: 127\.0\.0\.1:\d+: did not answer in time: no answer from /],
    ];
    for (const [name, args, message] of cases) {
        const checked = await checkMain([...args, ...ALWAYS_PASSES]);
        const inspected = await runMain(["inspect", ...args]);
        assert.deepEqual([name, checked.code, checked.stdout], [name, 3, ""]);
        assert.match(checked.stderr, message, name);
        assert.equal(checked.stderr, inspected.stderr, `${name}: the message of inspect --host`);
        assert.deepEqual(await checkMain(["-q", ...args, ...ALWAYS_PASSES]).then(({ code, stdout, stderr }) => [code, stdout, stderr]), [3, "", ""], `${name}: --quiet`);
        // --json changes nothing about a host that cannot be reached.
        const json = await checkMain(["--json", ...args, ...ALWAYS_PASSES]);
        assert.deepEqual([json.code, json.stdout, json.stderr], [3, "", checked.stderr], name);
    }
    // Given a server name the hint is not true, and is not given.
    const named = await checkMain(["--host", hostOf(plain), "--servername", "named.example", ...ALWAYS_PASSES]);
    assert.equal(named.code, 3);
    assert.equal(named.stderr.trimEnd().split("\n").length, 1, named.stderr);
});

// ---------------------------------------------------------------------------------------------
// --expect-fingerprint-of

test("--expect-fingerprint-of requires the target certificate of the file to be the one the host serves: it compares the sha256 of the host's target with the file's", async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    const dir = scratch(t);
    const same = written(dir, "same.pem", fixture("leaf-p256.pem"));
    const fullchain = written(dir, "fullchain.pem", Buffer.concat(SERVED.map(fixture)));
    const der = written(dir, "same.der", fixture("leaf-p256.der"));
    // The target of this file is its second certificate, and that is the one that counts.
    const shuffled = written(dir, "shuffled.pem", fixture("bundle-shuffled.pem"));
    assert.equal(targetOf("bundle-shuffled.pem").certificate.sha256, LEAF.sha256);
    assert.notEqual(inspect(fixture("bundle-shuffled.pem")).target, 0);
    const other = written(dir, "other.pem", fixture("leaf-rsa.pem"));
    const base = ["--host", host, "--as-of", AT, "--json"];

    // The file's target, whether the file is a single certificate, a chain or DER.
    for (const file of [same, fullchain, der, shuffled]) {
        const result = await checkMain([...base, "--expect-fingerprint-of", file]);
        assert.equal(result.code, 0, `${file}: ${result.stderr}`);
        const printed = jsonOf(result);
        assert.deepEqual(errorsOf(printed), []);
        assert.deepEqual(printed.policy.expectFingerprint, { value: LEAF.sha256, severity: "fail" });
        assert.deepEqual(printed.results.at(-1), {
            code: "FINGERPRINT_MISMATCH",
            status: "pass",
            rule: { name: "expectFingerprint", value: LEAF.sha256 },
            message: "the certificate has the expected fingerprint",
            actual: LEAF.sha256,
            expected: LEAF.sha256,
        }, file);
    }

    // Another certificate is a failed result, not an error of the command.
    const different = await checkMain([...base, "--expect-fingerprint-of", other]);
    assert.equal(different.code, 1);
    const last = jsonOf(different).results.at(-1);
    assert.deepEqual([last.code, last.status, last.actual, last.expected], ["FINGERPRINT_MISMATCH", "fail", LEAF.sha256, RSA.sha256]);
    // --warn-only softens it as it does for --expect-fingerprint, because the option gives the same rule.
    const softened = await checkMain([...base, "--expect-fingerprint-of", other, "--warn-only", "FINGERPRINT_MISMATCH"]);
    assert.equal(softened.code, 0, softened.stderr);
    assert.equal(jsonOf(softened).results.at(-1).status, "warn");

    // The option alone is something to check.
    const readable = await checkMain(["--host", host, "--as-of", AT, "--expect-fingerprint-of", same]);
    assert.equal(readable.code, 0, readable.stderr);
    assert.match(readable.stdout, /^ {2}OK {4}expectFingerprint {2}FINGERPRINT_MISMATCH {2}the certificate has the expected fingerprint$/m);

    // A file that cannot be read is exit 3, and so is one that holds no certificate.
    for (const path of [join(dir, "missing.pem"), dir, typed("leaf-p256.key"), written(dir, "empty.pem", "")]) {
        const result = await checkMain([...base, "--expect-fingerprint-of", path]);
        assert.deepEqual([path, result.code, result.stdout], [path, 3, ""]);
        assert.match(result.stderr, /^certdrift: /);
    }
    assert.match((await checkMain([...base, "--expect-fingerprint-of", join(dir, "missing.pem")])).stderr, /^certdrift: cannot read .*missing\.pem: ENOENT/);
    assert.equal((await checkMain([...base, "--expect-fingerprint-of="])).code, 3, "an empty path is a file that cannot be read");

    // A file with several candidates for its target is exit 2 and lists them.
    const twoLeaves = written(dir, "two-leaves.pem", fixture("bundle-two-leaves.pem"));
    const ambiguous = await checkMain([...base, "--expect-fingerprint-of", twoLeaves]);
    assert.deepEqual([ambiguous.code, ambiguous.stdout], [2, ""]);
    assert.ok(ambiguous.stderr.startsWith(`certdrift: ${twoLeaves}: `), ambiguous.stderr);
    for (const sha256 of candidatesOf("bundle-two-leaves.pem")) assert.ok(ambiguous.stderr.includes(sha256), "lists every candidate");
    assert.match(ambiguous.stderr, /--expect-fingerprint-of needs a file where the certificate it is about is one/);
    assert.doesNotMatch(ambiguous.stderr, /Use --select with the start/, "--select is not offered where it does not choose");

    // Both options fill one rule, so the two together are misuse, and so is the file's entry.
    const together = await checkMain([...base, "--expect-fingerprint-of", same, "--expect-fingerprint", LEAF.sha256]);
    assert.deepEqual([together.code, together.stdout], [2, ""]);
    assert.match(together.stderr, /^certdrift: the options give the same entry\n {2}--expect-fingerprint and --expect-fingerprint-of both give expectFingerprint: give only one of them\n/);
    const policy = written(dir, "policy.json", `{"contract":1,"expectFingerprint":{"value":"${"ab".repeat(32)}"}}`);
    const conflict = await checkMain([...base, "--policy", policy, "--expect-fingerprint-of", same]);
    assert.deepEqual([conflict.code, conflict.stdout], [2, ""]);
    assert.match(conflict.stderr, /the options and the policy file give the same entry\n {2}--expect-fingerprint-of gives expectFingerprint, which the policy file has/);
    assert.match(conflict.stderr, /Usage: certdrift check /);

    await sleep(50);
    assert.equal(server.accepted(), 7, "only the runs that got as far as the host connected");
});

test("--expect-fingerprint-of works without --host, comparing the certificate of one file with the certificate of another", async (t) => {
    const dir = scratch(t);
    const same = written(dir, "same.pem", fixture("leaf-p256.pem"));
    const other = written(dir, "other.pem", fixture("leaf-rsa.pem"));
    const matching = await checkMain(["--as-of", AT, "--expect-fingerprint-of", same, typed("leaf-p256.pem")]);
    assert.equal(matching.code, 0, matching.stderr);
    const differing = await checkMain(["--as-of", AT, "--json", "--expect-fingerprint-of", other, typed("leaf-p256.pem")]);
    assert.equal(differing.code, 1);
    assert.equal(jsonOf(differing).results.at(-1).code, "FINGERPRINT_MISMATCH");
});

test("today: --select does not choose in the file of --expect-fingerprint-of, so a file with two end-entity certificates cannot be given to it", async (t) => {
    const dir = scratch(t);
    const twoLeaves = written(dir, "two-leaves.pem", fixture("bundle-two-leaves.pem"));
    const [first] = candidatesOf("bundle-two-leaves.pem");
    const result = await checkMain(["--as-of", AT, "--select", first.slice(0, 12), "--expect-fingerprint-of", twoLeaves, typed("leaf-p256.pem")]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /two-leaves\.pem: 2 certificates in the material sign no other one/);
});

// ---------------------------------------------------------------------------------------------
// Standard input

test("with --host standard input holds no certificate, so --policy - or --expect-fingerprint-of - may read it, once", async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    const policy = '{"contract":1,"rejectEku":{"value":["codeSigning"]}}';

    const policyFromInput = await checkMain(["--host", host, "--as-of", AT, "--policy", "-", "--json"], { input: policy });
    assert.equal(policyFromInput.code, 0, policyFromInput.stderr);
    assert.deepEqual(jsonOf(policyFromInput).policy.rejectEku.value, ["codeSigning"]);

    const fingerprintFromInput = await checkMain(["--host", host, "--as-of", AT, "--expect-fingerprint-of", "-", "--json"], { input: fixture("leaf-p256.pem") });
    assert.equal(fingerprintFromInput.code, 0, fingerprintFromInput.stderr);
    assert.equal(jsonOf(fingerprintFromInput).policy.expectFingerprint.value, LEAF.sha256);

    // Standard input is read once: two options that read it are misuse, whatever it holds.
    const both = await checkMain(["--host", host, "--as-of", AT, "--policy", "-", "--expect-fingerprint-of", "-"], { input: policy });
    assert.equal(both.code, 2);
    assert.match(both.stderr, /^certdrift: --policy - and --expect-fingerprint-of - both read standard input, which can be read once\n/);

    // Without a host the path can be -, and then neither option may be.
    const withPath = await checkMain(["--as-of", AT, "--expect-fingerprint-of", "-", "-"], { input: fixture("leaf-p256.pem") });
    assert.equal(withPath.code, 2);
    assert.match(withPath.stderr, /^certdrift: --expect-fingerprint-of - and the path - both read standard input, which can be read once\n/);
    const policyAndPath = await checkMain(["--policy", "-", "--reject-eku", "codeSigning", "-"], { input: policy });
    assert.match(policyAndPath.stderr, /^certdrift: --policy - and the path - both read standard input, which can be read once\n/);

    // With a host there is no path, and a "-" is misuse as it is for inspect.
    const dashed = await checkMain(["--host", host, "-", ...ALWAYS_PASSES]);
    assert.equal(dashed.code, 2);
    assert.match(dashed.stderr, /^certdrift: --host takes no path and no "-"/);
});

test("with --host standard input is neither read nor waited for unless an option names it", { timeout: 40_000 }, async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const open = await check(["--host", hostOf(server), "--as-of", AT, "--json", ...ALWAYS_PASSES], { openStdin: true, killAfterMs: 20_000 });
    assert.equal(open.code, 0, open.stderr);
    const closed = await check(["--host", `127.0.0.1:${await closedPort()}`, ...ALWAYS_PASSES], { openStdin: true, killAfterMs: 20_000 });
    assert.equal(closed.code, 3);
    const piped = await check(["--host", hostOf(server), "--as-of", AT, "--json", ...ALWAYS_PASSES], { input: fixture("leaf-rsa.pem") });
    const printed = jsonOf(piped);
    assert.equal(printed.observation.certificates[printed.observation.target].sha256, LEAF.sha256, "what the server sent, not what was piped in");
});

// ---------------------------------------------------------------------------------------------
// The output

test("the readable output, --json, --quiet, --as-of and the exit codes are those of a file, and the observation's source is the host's, with its target and server name", async (t) => {
    const server = await serveChain(t, { certs: SERVED });
    const host = hostOf(server);
    const dir = scratch(t);
    const served = written(dir, "served.pem", Buffer.concat(SERVED.map(fixture)));
    const requirements = ["--expect-san", "p256.example", "--expect-eku", "serverAuth", "--reject-eku", "codeSigning", "--expires-within", "1d"];
    const after = shifted(LEAF.notAfter, 1);

    for (const asOf of [AT, after]) {
        const viaHost = await checkMain(["--host", host, "--as-of", asOf, ...requirements]);
        const viaFile = await checkMain([served, "--as-of", asOf, ...requirements]);
        assert.equal(viaHost.code, viaFile.code, asOf);
        assert.equal(viaHost.code, asOf === AT ? 0 : 1, `${asOf}: ${viaHost.stderr}`);
        assert.equal(viaHost.stderr, "");
        const [first, ...rest] = viaHost.stdout.split("\n");
        assert.equal(first, `${host}  checked at ${asOf}`, "the first line names the host and the instant");
        assert.deepEqual(rest, viaFile.stdout.split("\n").slice(1), "the same lines after it");

        const jsonHost = jsonOf(await checkMain(["--host", host, "--json", "--as-of", asOf, ...requirements]));
        const jsonFile = jsonOf(await checkMain([served, "--json", "--as-of", asOf, ...requirements]));
        assert.deepEqual(errorsOf(jsonHost), []);
        assert.deepEqual(withoutObservation(jsonHost), withoutObservation(jsonFile));
        assert.equal(jsonHost.now, asOf, "the instant used is --as-of");
        assert.notEqual(jsonHost.observation.observation.at, asOf, "the observation's at is not changed by it");
        assert.deepEqual(jsonHost.observation.certificates.map((/** @type {{ sha256: string }} */ one) => one.sha256), jsonFile.observation.certificates.map((/** @type {{ sha256: string }} */ one) => one.sha256));
        assert.equal(jsonHost.observation.target, jsonFile.observation.target);
        assert.deepEqual(jsonHost.observation.observation.source, { kind: "host", ref: host, servername: null });

        // --quiet prints nothing and keeps the exit code, and wins over --json.
        for (const flags of [["--quiet"], ["-q", "--json"]]) {
            const quiet = await checkMain(["--host", host, ...flags, "--as-of", asOf, ...requirements]);
            assert.deepEqual([quiet.code, quiet.stdout, quiet.stderr], [viaHost.code, "", ""], flags.join(" "));
        }
    }

    // The server name is part of the source, as it is for inspect.
    const named = jsonOf(await checkMain(["--host", host, "--servername", "Api.Example.com", "--json", "--as-of", AT, ...requirements]));
    assert.deepEqual(named.observation.observation.source, { kind: "host", ref: host, servername: "Api.Example.com" });
    assert.deepEqual(server.names, ["Api.Example.com"]);
});

test("a local server with one chain is checked against the matching fingerprint and a wrong one, with --as-of after the certificate's end, and with --key for the key of the served certificate and for another one", async (t) => {
    const server = await serveChain(t, { certs: SERVED, key: "leaf-p256.key" });
    const host = hostOf(server);
    const run_ = async (/** @type {string[]} */ ...args) => checkMain(["--host", host, "--json", ...args]);
    const lastOf = (/** @type {import("./helpers/command.js").Result} */ result) => jsonOf(result).results.at(-1);

    const matching = await run_("--as-of", AT, "--expect-fingerprint", LEAF.sha256);
    assert.equal(matching.code, 0, matching.stderr);
    assert.deepEqual([lastOf(matching).code, lastOf(matching).status], ["FINGERPRINT_MISMATCH", "pass"]);

    const wrong = await run_("--as-of", AT, "--expect-fingerprint", "ab".repeat(32));
    assert.equal(wrong.code, 1);
    assert.deepEqual([lastOf(wrong).code, lastOf(wrong).status, lastOf(wrong).actual], ["FINGERPRINT_MISMATCH", "fail", LEAF.sha256]);

    const expired = await run_("--as-of", shifted(LEAF.notAfter, 1), "--reject-eku", "codeSigning");
    assert.equal(expired.code, 1);
    assert.equal(jsonOf(expired).results.find((/** @type {{ code: string }} */ one) => one.code === "EXPIRED").status, "fail");

    const own = await run_("--as-of", AT, "--key", typed("leaf-p256.key"));
    assert.equal(own.code, 0, own.stderr);
    assert.deepEqual([lastOf(own).code, lastOf(own).status, lastOf(own).actual], ["KEY_MISMATCH", "pass", LEAF.spkiSha256]);

    const another = await run_("--as-of", AT, "--key", typed("leaf-p256.mismatch.key"));
    assert.equal(another.code, 1);
    assert.deepEqual([lastOf(another).code, lastOf(another).status], ["KEY_MISMATCH", "fail"]);
    assert.equal(server.accepted(), 5);
});

// ---------------------------------------------------------------------------------------------
// The help and the README

test("the help and the README document check --host, --servername, --timeout and --expect-fingerprint-of, with an example of confirming an installation", async () => {
    const help = (await runMain(["check", "--help"])).stdout;
    for (const flag of ["--host <host[:port]>", "--servername <name>", "--timeout <ms>", "--expect-fingerprint-of <file>"]) {
        assert.ok(help.split("\n").some((line) => line.startsWith(`  ${flag} `)), `the options list has ${flag}`);
    }
    assert.match(help, /^Usage: certdrift check .*<path \| ->\n {7}certdrift check \[same options\] .*--host <host\[:port\]>$/m);
    const flat = help.replace(/\s+/g, " ");
    for (const part of [
        "Checking a server:", "chosen as certdrift inspect --host chooses it", "443 unless given", "certdrift inspect --help",
        "Every file an option names (--policy, --key, --expect-fingerprint-of) is read before the host is contacted",
        "--select does not choose in it", "--expect-fingerprint-of does",
        "does not answer in time",
    ]) assert.ok(flat.includes(part), `the help says: ${part}`);
    assert.doesNotMatch(help, /PENDING/);

    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const start = readme.indexOf("\n### A server\n");
    assert.notEqual(start, -1, "the README has a section on a server");
    const section = readme.slice(start + 1, readme.indexOf("\n### ", start + 1));
    const text = section.replaceAll("`", "").replace(/\s+/g, " ");
    for (const part of ["--host <host[:port]>", "--servername", "--timeout", "--expect-fingerprint-of <file>", "chosen as inspect --host chooses it", "exit 2", "exit 3", "is read before the host is contacted", "standard input is read once", "--select chooses only in what the host sends"]) {
        assert.ok(text.includes(part), `the README says: ${part}`);
    }
    const examples = [...section.matchAll(/```sh\n([\s\S]*?)```/g)].flatMap((block) => block[1].split("\n")).filter((line) => line.startsWith("certdrift check"));
    assert.ok(examples.some((line) => line.includes("--host") && line.includes("--expect-fingerprint-of") && line.includes("--expires-within")), examples.join("\n"));
});
