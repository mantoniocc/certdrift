import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, inspect, serializeCheckResult } from "../src/index.js";
import { CHECK_OPTIONS } from "../bin/check.js";
import { fixture, run, runMain, targetOf, typed } from "./helpers/command.js";
import { PASSPHRASE, REASON } from "./helpers/keys.js";
import { validatorFor } from "./helpers/schema.js";

// `certdrift check --key`: the key of a certificate from the command line. The command only reads
// the file and the variable and hands them to the library, so what is shown here is the command's
// own part: the options, their rules and exit codes, the reading, and what is printed. Whether a
// key matches is decided and tested in the library. Nothing depends on the clock or on the bytes
// of a fixture: every run names the instant it evaluates at.

const errorsOf = validatorFor("check-result");
const absolute = (/** @type {string} */ name) => new URL(`fixtures/${name}`, import.meta.url).pathname;

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

/** The instant at which a fixture's target has started and not ended. @param {string} name */
const startOf = (name) => targetOf(name).certificate.notBefore;

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

/**
 * What the library says for a certificate fixture, a policy, a key file and an instant, as the
 * command prints it.
 * @param {string} name The certificate.
 * @param {unknown} policy
 * @param {{ material: Uint8Array, passphrase?: string }} privateKey
 * @param {string} now
 */
function expectedFor(name, policy, privateKey, now) {
    const { select } = targetOf(name);
    const observation = select.length > 0 ? inspect(fixture(name), { select: select[1] }) : inspect(fixture(name));
    return withoutObservation(JSON.parse(serializeCheckResult(evaluate(observation, /** @type {any} */ (policy), { now, privateKey }))));
}

/**
 * Runs `work` for each item, a dozen at a time.
 * @template T, R
 * @param {T[]} items
 * @param {(item: T) => Promise<R>} work
 * @returns {Promise<[T, R][]>}
 */
async function inBatches(items, work) {
    /** @type {[T, R][]} */
    const done = [];
    for (let start = 0; start < items.length; start += 12) {
        done.push(...(await Promise.all(items.slice(start, start + 12).map(async (item) => /** @type {[T, R]} */ ([item, await work(item)])))));
    }
    return done;
}

/** The certificates that have a key and another key that is not theirs. */
const keyed = readdirSync(new URL("fixtures/", import.meta.url))
    .filter((name) => name.endsWith(".mismatch.key"))
    .map((name) => name.slice(0, -".mismatch.key".length))
    .sort();

// ---------------------------------------------------------------------------------------------
// --key adds the rule

test("--key adds the rule matchesPrivateKey to the results and to the verdict: the key of the certificate passes and another key fails, for every algorithm the fixtures have", { timeout: 120_000 }, async () => {
    for (const algorithm of ["leaf-rsa", "leaf-rsa-pss", "leaf-p256", "leaf-p384", "leaf-p521", "leaf-brainpool", "leaf-ed25519", "leaf-ml-dsa-44", "leaf-sm2"]) {
        assert.ok(keyed.includes(algorithm), `${algorithm} has a key that is not its own among the fixtures`);
    }
    const checked = await inBatches(keyed, async (base) => {
        const { certificate, select } = targetOf(`${base}.pem`);
        const args = ["--json", "--as-of", certificate.notBefore, ...select, typed(`${base}.pem`)];
        const [own, other] = await Promise.all([check(["--key", typed(`${base}.key`), ...args]), check(["--key", typed(`${base}.mismatch.key`), ...args])]);
        return { certificate, own, other };
    });
    for (const [base, { certificate, own, other }] of checked) {
        assert.equal(own.code, 0, `${base}: ${own.stderr}`);
        const matched = jsonOf(own);
        assert.deepEqual(errorsOf(matched), [], base);
        assert.deepEqual(matched.results.map((/** @type {{ code: string }} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "KEY_MISMATCH"], base);
        assert.deepEqual(matched.results.at(-1), {
            code: "KEY_MISMATCH",
            status: "pass",
            rule: { name: "matchesPrivateKey" },
            message: "the private key corresponds to the certificate's public key",
            actual: certificate.spkiSha256,
            expected: certificate.spkiSha256,
        }, base);
        assert.deepEqual(matched.policy.matchesPrivateKey, { severity: "fail" }, base);
        assert.deepEqual(withoutObservation(matched), expectedFor(`${base}.pem`, { contract: 1 }, { material: fixture(`${base}.key`) }, certificate.notBefore), base);

        assert.equal(other.code, 1, `${base}: ${other.stderr}`);
        const mismatched = jsonOf(other);
        assert.deepEqual(errorsOf(mismatched), [], base);
        const last = mismatched.results.at(-1);
        assert.deepEqual([last.code, last.status, last.expected], ["KEY_MISMATCH", "fail", certificate.spkiSha256], base);
        assert.notEqual(last.actual, certificate.spkiSha256, base);
        assert.equal(mismatched.summary.status, "fail", base);
    }
});

test("--key is something to check on its own, with no POLICY_EMPTY, and its result goes after the other rules", async () => {
    const at = startOf("leaf-p256.pem");
    const alone = jsonOf(await check(["--json", "--as-of", at, "--key", typed("leaf-p256.key"), typed("leaf-p256.pem")]));
    assert.deepEqual(alone.results.map((/** @type {{ code: string }} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "KEY_MISMATCH"]);

    const several = jsonOf(await check(["--json", "--as-of", at, "--expect-san", "p256.example", "--reject-eku", "codeSigning", "--key", typed("leaf-p256.key"), "--expect-eku", "serverAuth", typed("leaf-p256.pem")]));
    assert.deepEqual(several.results.map((/** @type {{ rule: { name: string } }} */ result) => result.rule.name), ["validityStarted", "validityNotEnded", "expectEku", "rejectEku", "expectSan", "matchesPrivateKey"]);
    assert.equal(several.summary.pass, 6);

    // The same without --key does not run the rule.
    const without = jsonOf(await check(["--json", "--as-of", at, "--reject-eku", "codeSigning", typed("leaf-p256.pem")]));
    assert.ok(!without.results.some((/** @type {{ code: string }} */ result) => result.code === "KEY_MISMATCH"));
});

test("the readable output has a line for the key, OK when it is the certificate's and FAIL when it is not or cannot be read, and the exit code follows", async () => {
    const at = startOf("leaf-p256.pem");
    const args = ["--as-of", at, "--reject-eku", "codeSigning"];
    const own = await check([...args, "--key", typed("leaf-p256.key"), typed("leaf-p256.pem")]);
    assert.equal(own.code, 0, own.stderr);
    assert.match(own.stdout, /^ {2}OK {4}matchesPrivateKey +KEY_MISMATCH +the private key corresponds to the certificate's public key$/m);
    assert.match(own.stdout, /\n0 failed · exit 0\n$/);

    const other = await check([...args, "--key", typed("leaf-p256.mismatch.key"), typed("leaf-p256.pem")]);
    assert.equal(other.code, 1);
    assert.match(other.stdout, /^ {2}FAIL {2}matchesPrivateKey +KEY_MISMATCH +the private key does not correspond to the certificate's public key$/m);
    assert.match(other.stdout, /\n1 failed · exit 1\n$/);

    const unreadable = await check([...args, "--key", typed("leaf-rsa.public.key"), typed("leaf-p256.pem")]);
    assert.equal(unreadable.code, 1);
    assert.match(unreadable.stdout, /^ {2}FAIL {2}matchesPrivateKey +KEY_UNREADABLE +the private key could not be read: the file holds a public key$/m);
});

test("the key is read the same whichever way the certificate comes: a DER file, standard input, a file that holds the certificate and its key, and the option before or after the path", async (t) => {
    const at = startOf("leaf-p256.pem");
    const key = typed("leaf-p256.key");
    const der = await check(["--as-of", at, "--reject-eku", "codeSigning", "--key", key, typed("leaf-p256.der")]);
    assert.equal(der.code, 0, der.stderr);
    assert.match(der.stdout, /OK {4}matchesPrivateKey/);

    const stdin = await check(["--as-of", at, "--key", key, "-"], { input: fixture("leaf-p256.pem") });
    assert.equal(stdin.code, 0, stdin.stderr);
    assert.match(stdin.stdout, /^standard input {2}checked at /);
    assert.match(stdin.stdout, /OK {4}matchesPrivateKey/);

    const dir = scratch(t);
    const both = written(dir, "both.pem", Buffer.concat([fixture("leaf-p256.pem"), fixture("leaf-p256.key")]));
    for (const [what, args] of /** @type {[string, string[]][]} */ ([
        ["a file with the certificate and then its key, as the key", ["--key", both, typed("leaf-p256.pem")]],
        ["the same file as the certificate and as the key", ["--key", both, both]],
        ["the option after the path", [typed("leaf-p256.pem"), "--key", key]],
        ["the option as --key=file", [`--key=${key}`, typed("leaf-p256.pem")]],
    ])) {
        const result = await check(["--as-of", at, ...args]);
        assert.equal(result.code, 0, `${what}: ${result.stderr}`);
        assert.match(result.stdout, /OK {4}matchesPrivateKey/, what);
    }
});

test("the severity of the key is fail, or the one the policy file gives matchesPrivateKey, and --warn-only KEY_MISMATCH and --warn-only KEY_UNREADABLE soften it", async (t) => {
    const at = startOf("leaf-p256.pem");
    const dir = scratch(t);
    const warn = written(dir, "warn.json", '{"contract":1,"matchesPrivateKey":{"severity":"warn"}}');
    const fail = written(dir, "fail.json", '{"contract":1,"matchesPrivateKey":{"severity":"fail"}}');
    const base = ["--json", "--as-of", at, "--reject-eku", "codeSigning"];
    const cert = typed("leaf-p256.pem");
    const keys = { mismatch: typed("leaf-p256.mismatch.key"), unreadable: typed("leaf-rsa.truncated.key"), own: typed("leaf-p256.key") };
    /** What the policy says after the run, which is the severity and not the outcome. @type {[string, string[], number, string, "fail" | "warn"][]} */
    const table = [
        ["by default a key that does not match fails", ["--key", keys.mismatch], 1, "fail", "fail"],
        ["by default a key that cannot be read fails", ["--key", keys.unreadable], 1, "fail", "fail"],
        ["the policy file's warn softens a key that does not match", ["--policy", warn, "--key", keys.mismatch], 0, "warn", "warn"],
        ["the policy file's warn softens a key that cannot be read", ["--policy", warn, "--key", keys.unreadable], 0, "warn", "warn"],
        ["the policy file's fail is the default", ["--policy", fail, "--key", keys.mismatch], 1, "fail", "fail"],
        ["--warn-only KEY_MISMATCH softens a key that does not match", ["--warn-only", "KEY_MISMATCH", "--key", keys.mismatch], 0, "warn", "warn"],
        ["--warn-only KEY_UNREADABLE softens a key that cannot be read", ["--warn-only", "KEY_UNREADABLE", "--key", keys.unreadable], 0, "warn", "warn"],
        ["both codes belong to one rule, so either softens both outcomes", ["--warn-only", "KEY_UNREADABLE", "--key", keys.mismatch], 0, "warn", "warn"],
        ["--warn-only softens the rule the policy file lists", ["--policy", fail, "--warn-only", "KEY_MISMATCH", "--key", keys.mismatch], 0, "warn", "warn"],
        ["a key that matches passes under any severity", ["--policy", warn, "--key", keys.own], 0, "pass", "warn"],
    ];
    for (const [what, args, code, status, severity] of table) {
        const result = await check([...base, ...args, cert]);
        assert.equal(result.code, code, `${what}: ${result.stderr}`);
        const printed = jsonOf(result);
        assert.equal(printed.results.at(-1).status, status, what);
        assert.equal(printed.policy.matchesPrivateKey.severity, severity, what);
    }
});

test("a policy file that lists matchesPrivateKey with the options of the file's other entries still takes --key, which is not an entry the file can conflict with", async () => {
    // An option that gives an entry the file has is refused, but --key only asks for the rule and the file gives its severity.
    const at = startOf("leaf-p256.pem");
    for (const policy of ["every-rule", "pinned"]) {
        const { certificate } = targetOf("leaf-p256.pem");
        const result = await check(["--json", "--as-of", at, "--policy", `schema/examples/policy/${policy}.json`, "--key", typed("leaf-p256.key"), typed("leaf-p256.pem")]);
        const printed = jsonOf(result);
        assert.deepEqual(errorsOf(printed), [], policy);
        const given = JSON.parse(readFileSync(new URL(`../schema/examples/policy/${policy}.json`, import.meta.url), "utf8"));
        assert.deepEqual(withoutObservation(printed), expectedFor("leaf-p256.pem", given, { material: fixture("leaf-p256.key") }, certificate.notBefore), policy);
        assert.equal(printed.results.at(-1).code, "KEY_MISMATCH", policy);
        assert.equal(printed.results.at(-1).status, "pass", policy);
    }
});

// ---------------------------------------------------------------------------------------------
// The passphrase

test("--key-passphrase-env takes the passphrase from the variable of the environment the command is given, exactly as it holds it", async () => {
    const at = startOf("leaf-p256.pem");
    /** @param {string} key @param {string} certificate @param {Record<string, string | undefined>} env @param {string[]} [extra] */
    const withEnv = async (key, certificate, env, extra = ["--key-passphrase-env", "KEY_PASS"]) =>
        runMain(["check", "--json", "--as-of", at, "--key", absolute(key), ...extra, absolute(certificate)], { env: { NO_COLOR: "1", ...env } });

    for (const [key, certificate] of [["leaf-p256.pkcs8-encrypted.key", "leaf-p256.pem"], ["leaf-rsa.pkcs1-encrypted.key", "leaf-rsa.pem"]]) {
        const decrypted = await withEnv(key, certificate, { KEY_PASS: PASSPHRASE });
        assert.equal(decrypted.code, 0, `${key}: ${decrypted.stderr}`);
        assert.deepEqual(JSON.parse(decrypted.stdout).results.at(-1).status, "pass", key);

        // Nothing is trimmed, lowered or completed.
        for (const held of ["", " ", ` ${PASSPHRASE}`, `${PASSPHRASE} `, `${PASSPHRASE}\n`, `${PASSPHRASE}\r\n`, PASSPHRASE.toUpperCase(), PASSPHRASE.slice(1)]) {
            const result = await withEnv(key, certificate, { KEY_PASS: held });
            assert.equal(result.code, 1, `${key} ${JSON.stringify(held)}: ${result.stderr}`);
            assert.equal(JSON.parse(result.stdout).results.at(-1).message, REASON.decrypt, `${key} ${JSON.stringify(held)}`);
        }
        // No passphrase at all is another reason from an empty one.
        const none = await withEnv(key, certificate, { KEY_PASS: PASSPHRASE }, []);
        assert.equal(none.code, 1);
        assert.equal(JSON.parse(none.stdout).results.at(-1).message, REASON.encrypted);
    }
    // The command reads the environment it is given and not the one of the process.
    process.env.CERTDRIFT_TEST_ONLY_VARIABLE = PASSPHRASE;
    try {
        const absent = await withEnv("leaf-p256.pkcs8-encrypted.key", "leaf-p256.pem", {}, ["--key-passphrase-env", "CERTDRIFT_TEST_ONLY_VARIABLE"]);
        assert.equal(absent.code, 2);
    } finally {
        delete process.env.CERTDRIFT_TEST_ONLY_VARIABLE;
    }
    // A key that is not encrypted is read with any passphrase, as the library says.
    const plain = await withEnv("leaf-p256.key", "leaf-p256.pem", { KEY_PASS: "not the passphrase of anything" });
    assert.equal(plain.code, 0, plain.stderr);
});

test("a flag that takes the passphrase itself is refused as an unknown option, and the message names the option and never what it was given", async () => {
    const secret = "hunter2-flag-secret";
    const forms = [[`--key-passphrase=${secret}`], ["--key-passphrase", secret], [`--passphrase=${secret}`], ["--passphrase", secret], ["-p", secret], [`-p${secret}`], [`--key-password=${secret}`], [`--key-pass=${secret}`], [`--key-passphrase-env-value=${secret}`]];
    for (const form of forms) {
        const result = await check(["--key", typed("leaf-p256.pkcs8-encrypted.key"), ...form, typed("leaf-p256.pem")], { env: { KEY_PASS: PASSPHRASE } });
        assert.deepEqual([form.join(" "), result.code, result.stdout], [form.join(" "), 2, ""]);
        assert.match(result.stderr, /^certdrift: Unknown option '-{1,2}[a-z-]+'/, form.join(" "));
        assert.ok(!(result.stderr + result.stdout).includes(secret), form.join(" "));
        assert.match(result.stderr, /Usage: certdrift check /);
    }
    // The help names no such flag either.
    assert.doesNotMatch((await check(["--help"])).stdout, /--key-passphrase(?!-env)|--passphrase|--key-password/);
});

test("a variable that is not defined is exit 2, and so is --key-passphrase-env without --key; neither message repeats the name", async () => {
    const at = startOf("leaf-p256.pem");
    const key = typed("leaf-p256.pkcs8-encrypted.key");
    const cert = typed("leaf-p256.pem");
    for (const name of ["NOPE_NOT_DEFINED", "constructor", "toString", "__proto__", "hasOwnProperty", PASSPHRASE]) {
        const result = await check(["--as-of", at, "--key", key, `--key-passphrase-env=${name}`, cert], { env: { KEY_PASS: PASSPHRASE } });
        assert.deepEqual([name, result.code, result.stdout], [name, 2, ""]);
        assert.match(result.stderr, /^certdrift: --key-passphrase-env names an environment variable that is not defined\nUsage: /, name);
        assert.ok(!result.stderr.includes(name), name);
    }
    const empty = await check(["--as-of", at, "--key", key, "--key-passphrase-env=", cert], { env: { KEY_PASS: PASSPHRASE } });
    assert.deepEqual([empty.code, empty.stdout], [2, ""]);
    assert.match(empty.stderr, /^certdrift: --key-passphrase-env names an environment variable that is not defined\n/);

    for (const name of ["KEY_PASS", "NOPE_NOT_DEFINED"]) {
        const result = await check(["--as-of", at, "--key-passphrase-env", name, "--reject-eku", "codeSigning", cert], { env: { KEY_PASS: PASSPHRASE } });
        assert.deepEqual([name, result.code, result.stdout], [name, 2, ""]);
        assert.match(result.stderr, /^certdrift: --key-passphrase-env needs --key\nUsage: certdrift check /, name);
    }
    // A variable that is defined and empty is an empty passphrase, which decrypts nothing here and is not misuse.
    const emptyValue = await check(["--as-of", at, "--key", key, "--key-passphrase-env", "KEY_EMPTY", cert], { env: { KEY_EMPTY: "" } });
    assert.equal(emptyValue.code, 1, emptyValue.stderr);
    assert.match(emptyValue.stdout, /KEY_UNREADABLE +the private key could not be read: it could not be decrypted with the passphrase given/);
});

// ---------------------------------------------------------------------------------------------
// Misuse of the options

test("--key and --key-passphrase-env given twice are exit 2, as the other options that take one value are, even with the same value", async () => {
    const cert = typed("leaf-p256.pem");
    const key = typed("leaf-p256.key");
    for (const [flag, values] of /** @type {[string, string[]][]} */ ([["key", [key, typed("leaf-p256.mismatch.key")]], ["key", [key, key]], ["key-passphrase-env", ["A", "B"]], ["key-passphrase-env", ["A", "A"]]])) {
        const args = flag === "key" ? [`--${flag}`, values[0], `--${flag}`, values[1]] : ["--key", key, `--${flag}`, values[0], `--${flag}`, values[1]];
        const result = await check([...args, cert], { env: { A: "x", B: "y" } });
        assert.deepEqual([flag, values.join(","), result.code, result.stdout], [flag, values.join(","), 2, ""]);
        assert.match(result.stderr, new RegExp(`^certdrift: --${flag} was given more than once\\n`), flag);
    }
    // Repeated is reported before what the repeated value would be refused for.
    const dash = await check(["--key", "-", "--key", "-", cert]);
    assert.match(dash.stderr, /^certdrift: --key was given more than once\n/);
});

test("--key - is exit 2 and never reads standard input", async () => {
    const cert = typed("leaf-p256.pem");
    // Standard input is left open and never written to: a command that read it would wait for it.
    const open = await check(["--key", "-", cert], { openStdin: true, killAfterMs: 15_000 });
    assert.deepEqual([open.code, open.stdout], [2, ""]);
    assert.match(open.stderr, /^certdrift: --key - would read the key from standard input, which is not supported: give a file\nUsage: certdrift check /);
    const given = await check(["--key", "-", "-"], { input: fixture("leaf-p256.key") });
    assert.equal(given.code, 2);
    assert.match(given.stderr, /^certdrift: --key - would read the key from standard input/);
    assert.equal((await check(["--key=-", "--key-passphrase-env", "X", cert], { env: { X: "y" } })).code, 2);
    // A file called "-" is no concern of this option: only the one name is standard input.
    const dash = await check(["--key", "./-", "--reject-eku", "codeSigning", cert]);
    assert.equal(dash.code, 3);
    assert.match(dash.stderr, /^certdrift: cannot read \.\/-: ENOENT/);
});

test("--key needs a value: given last or before another option it is misuse, and the message does not repeat what follows", async () => {
    const cert = typed("leaf-p256.pem");
    for (const args of [[cert, "--key"], ["--key"], ["--key", "--json", cert], ["--key", "-q", cert]]) {
        const result = await check(args, { env: { KEY_PASS: PASSPHRASE } });
        assert.equal(result.code, 2, args.join(" "));
    }
});

// ---------------------------------------------------------------------------------------------
// A file that cannot be opened and one that holds no key

test("a key file that cannot be opened is exit 3 as a certificate file is, and nothing is printed on standard output", async (t) => {
    const dir = scratch(t);
    const cert = typed("leaf-p256.pem");
    for (const [what, path, message] of /** @type {[string, string, RegExp][]} */ ([
        ["a file that does not exist", join(dir, "missing.key"), /^certdrift: cannot read .*missing\.key: ENOENT/],
        ["a directory", dir, /^certdrift: cannot read .*: EISDIR/],
        ["an empty path", "", /^certdrift: cannot read : ENOENT/],
        ["a path through a file", `${typed("leaf-p256.key")}/x`, /^certdrift: cannot read .*: ENOTDIR/],
    ])) {
        const result = await check(["--reject-eku", "codeSigning", `--key=${path}`, cert]);
        assert.deepEqual([what, result.code, result.stdout], [what, 3, ""]);
        assert.match(result.stderr, message, what);
        const same = await check(["--reject-eku", "codeSigning", path === "" ? "" : path], {});
        assert.equal(same.code, 3, `${what}: as a certificate it is exit 3 too`);
    }
    // The message for a certificate and the one for a key are the same sentence.
    const asKey = await check(["--reject-eku", "codeSigning", "--key", join(dir, "missing.key"), cert]);
    const asCertificate = await check(["--reject-eku", "codeSigning", join(dir, "missing.key")]);
    assert.equal(asKey.stderr, asCertificate.stderr);
});

test("a file that opens and holds no readable private key is not a crash and not misuse: it is the result KEY_UNREADABLE with its reason, a failed check, exit 1", async (t) => {
    const at = startOf("leaf-rsa.pem");
    const dir = scratch(t);
    /** @type {[string, string, string][]} */
    const files = [
        ["an empty file", typed("empty.key"), REASON.noKey],
        ["a block that is not a key", typed("not-a-key.key"), REASON.unsupported],
        ["a truncated key", typed("leaf-rsa.truncated.key"), REASON.unsupported],
        ["a public key", typed("leaf-rsa.public.key"), REASON.publicKey],
        ["a certificate", typed("leaf-rsa.certificate.key"), REASON.certificate],
        ["the certificate itself", typed("leaf-rsa.pem"), REASON.certificate],
        ["two keys", typed("two-keys.key"), REASON.several],
        ["an encrypted key and no passphrase", typed("leaf-rsa.pkcs8-encrypted.key"), REASON.encrypted],
        ["a traditional encrypted key and no passphrase", typed("leaf-rsa.pkcs1-encrypted.key"), REASON.encrypted],
        ["a key as DER", written(dir, "key.der", fixture("leaf-p256.der")), REASON.unsupported],
        ["text", written(dir, "words.txt", "these are my keys\n"), REASON.noKey],
    ];
    for (const [what, path, reason] of files) {
        const result = await check(["--json", "--as-of", at, "--key", path, typed("leaf-rsa.pem")]);
        assert.deepEqual([what, result.code, result.stderr], [what, 1, ""]);
        const printed = jsonOf(result);
        assert.deepEqual(errorsOf(printed), [], what);
        const last = printed.results.at(-1);
        assert.deepEqual(last, { code: "KEY_UNREADABLE", status: "fail", rule: { name: "matchesPrivateKey" }, message: reason }, what);
        assert.equal(printed.summary.status, "fail", what);
        // The reason is on the line of the readable output, too.
        const readable = await check(["--as-of", at, "--key", path, typed("leaf-rsa.pem")]);
        assert.equal(readable.code, 1, what);
        assert.ok(readable.stdout.includes(`KEY_UNREADABLE  ${reason}\n`), `${what}\n${readable.stdout}`);
    }
});

test("a key that cannot be read does not stop the rest: the other rules are still results, and a certificate that is missing is still exit 3", async () => {
    const at = startOf("leaf-p256.pem");
    const printed = jsonOf(await check(["--json", "--as-of", at, "--reject-eku", "codeSigning", "--key", typed("empty.key"), typed("leaf-p256.pem")]));
    assert.deepEqual(printed.results.map((/** @type {{ code: string }} */ result) => result.code), ["NOT_YET_VALID", "EXPIRED", "EKU_FORBIDDEN", "KEY_UNREADABLE"]);
    const missing = await check(["--key", typed("empty.key"), "missing.pem"]);
    assert.equal(missing.code, 3);
    assert.match(missing.stderr, /^certdrift: cannot read missing\.pem: /);
});

// ---------------------------------------------------------------------------------------------
// A policy that asks for a key

test("a policy file that lists matchesPrivateKey and a run with no --key is exit 2 and says the policy asks for a private key, in the words of the library's PolicyError", async () => {
    for (const name of ["every-rule", "pinned"]) {
        const path = `schema/examples/policy/${name}.json`;
        for (const mode of [[], ["--json"]]) {
            const result = await check([...mode, "--policy", path, typed("leaf-p256.pem")]);
            assert.deepEqual([name, result.code, result.stdout], [name, 2, ""]);
            assert.equal(
                result.stderr.split("\n").slice(0, 2).join("\n"),
                `certdrift: ${path}: the policy is not valid: 1 problem\n  /matchesPrivateKey: needs a private key, and none is given`,
                name,
            );
            assert.match(result.stderr, /\nUsage: certdrift check .*--key <file>/);
        }
    }
    // A key that is not given is no key: --key-passphrase-env alone does not give one.
    const onlyVariable = await check(["--policy", "schema/examples/policy/pinned.json", "--key-passphrase-env", "KEY_PASS", typed("leaf-p256.pem")], { env: { KEY_PASS: "x" } });
    assert.equal(onlyVariable.code, 2);
    assert.match(onlyVariable.stderr, /^certdrift: --key-passphrase-env needs --key\n/);
});

// ---------------------------------------------------------------------------------------------
// The order of mistakes

test("with the key options, the mistake reported is the first of a fixed order, and the key file is read after the policy file and before the certificate", async (t) => {
    const dir = scratch(t);
    const cert = typed("leaf-p256.pem");
    const key = typed("leaf-p256.key");
    const withEku = written(dir, "eku.json", '{"contract":1,"expectEku":{"value":["serverAuth"]}}');
    const invalid = written(dir, "invalid.json", '{"contract":1,"expectEku":{"value":5}}');
    const missingKey = join(dir, "missing.key");
    // Each line breaks two rules, and the message is the one of the rule that comes first.
    /** @type {[string, string[], number, RegExp][]} */
    const table = [
        ["a repeated --key before --key -", ["--key", "-", "--key", "-", cert], 2, /^certdrift: --key was given more than once\n/],
        ["a repeated --key-passphrase-env before --key-passphrase-env without --key", ["--key-passphrase-env", "A", "--key-passphrase-env", "A", cert], 2, /^certdrift: --key-passphrase-env was given more than once\n/],
        ["a missing path before --key -", ["--key", "-"], 2, /^certdrift: no path given; /],
        ["an empty --select before --key -", ["--select=", "--key", "-", cert], 2, /^certdrift: --select needs the start of a sha256, and it is empty\n/],
        ["standard input twice before --key -", ["--policy", "-", "--key", "-", "-"], 2, /^certdrift: --policy - and the path - both read standard input/],
        ["--key - before --key-passphrase-env that is not defined", ["--key", "-", "--key-passphrase-env", "NOPE", cert], 2, /^certdrift: --key - would read the key/],
        ["--key - before a bad --as-of", ["--key", "-", "--as-of", "x", cert], 2, /^certdrift: --key - would read the key/],
        ["--key-passphrase-env without --key before a variable that is not defined", ["--key-passphrase-env", "NOPE", cert], 2, /^certdrift: --key-passphrase-env needs --key\n/],
        ["--key-passphrase-env without --key before a bad --as-of", ["--key-passphrase-env", "A", "--as-of", "x", cert], 2, /^certdrift: --key-passphrase-env needs --key\n/],
        ["a variable that is not defined before a bad --as-of", ["--key", key, "--key-passphrase-env", "NOPE", "--as-of", "x", cert], 2, /^certdrift: --key-passphrase-env names an environment variable that is not defined\n/],
        ["a bad --as-of before a missing key file", ["--as-of", "x", "--key", missingKey, cert], 2, /^certdrift: --as-of needs a date/],
        ["a bad percentage before a missing key file", ["--lifetime-used=abc", "--key", missingKey, cert], 2, /^certdrift: --lifetime-used needs a percentage/],
        ["a value the policy refuses before a missing key file", ["--expect-eku", "bogus", "--key", missingKey, cert], 2, /^certdrift: the requirement options are not valid: 1 problem\n/],
        ["a --warn-only code that names no entry before a missing key file", ["--warn-only", "NOPE", "--key", missingKey, cert], 2, /^certdrift: --warn-only needs the reason code /],
        ["a policy file that is missing before a missing key file", ["--policy", join(dir, "missing.json"), "--key", missingKey, cert], 3, /^certdrift: cannot read .*missing\.json: /],
        ["a policy file that is not valid before a missing key file", ["--policy", invalid, "--key", missingKey, cert], 2, /the policy is not valid: 1 problem\n {2}\/expectEku\/value: /],
        ["a flag that conflicts before a missing key file", ["--policy", withEku, "--expect-eku", "clientAuth", "--key", missingKey, cert], 2, /the options and the policy file give the same entry\n/],
        ["a --warn-only code of a rule that is not checked before a missing key file", ["--warn-only", "SAN_MISSING", "--policy", policyFile("empty"), "--key", missingKey, cert], 2, /^certdrift: --warn-only names a rule this run does not check\n/],
        ["a key file that is missing before a certificate that is missing", ["--key", missingKey, "missing.pem"], 3, /^certdrift: cannot read .*missing\.key: /],
        ["a key that cannot be read before nothing: the certificate that is missing is what is said", ["--key", typed("empty.key"), "missing.pem"], 3, /^certdrift: cannot read missing\.pem: /],
        ["a missing key file before standard input that holds no certificate", ["--key", missingKey, "-"], 3, /^certdrift: cannot read .*missing\.key: /],
    ];
    for (const [name, args, code, message] of table) {
        const result = await check(args, { input: "" });
        assert.deepEqual([name, result.code, result.stdout], [name, code, ""]);
        assert.match(result.stderr, message, name);
    }
});

/** @param {string} name */
function policyFile(name) {
    return `schema/examples/policy/${name}.json`;
}

// ---------------------------------------------------------------------------------------------
// The help and the README

test("the help and the README document --key and --key-passphrase-env, say that the passphrase is read from the environment on purpose, and show a full renewal check with a key", () => {
    assert.ok("key" in CHECK_OPTIONS && "key-passphrase-env" in CHECK_OPTIONS);
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const start = readme.indexOf("\n### A private key\n");
    assert.notEqual(start, -1, "the README has a section on the private key");
    const section = readme.slice(start + 1, readme.indexOf("\n### ", start + 1));
    const flat = (/** @type {string} */ text) => text.replaceAll("`", "").replaceAll("*", "").replace(/\s+/g, " ");
    for (const part of [
        "--key <file>", "--key-passphrase-env <VAR>", "There is no option that takes the passphrase itself, on purpose", "the list of processes", "environment",
        "KEY_UNREADABLE", "--warn-only KEY_MISMATCH", "exit 3", "--key - is misuse", "exactly as the variable holds it", "never appear on standard output",
    ]) assert.ok(flat(section).includes(part), `the README says: ${part}`);
    // A renewal check with a key: the key and several requirements in one command.
    const renewal = [...section.matchAll(/```sh\n([\s\S]*?)```/g)].flatMap((block) => block[1].split("\n")).filter((line) => line.startsWith("certdrift check") && line.includes("--key "));
    assert.ok(renewal.some((line) => ["--expect-san", "--expect-eku", "--expires-within"].every((flag) => line.includes(flag))), renewal.join("\n"));
    assert.ok(renewal.some((line) => line.includes("--key-passphrase-env")), renewal.join("\n"));
    // The tables of exit codes say where the key goes.
    assert.match(readme, /^\| `1` \|.*`KEY_UNREADABLE`/m);
    assert.match(readme, /^\| `3` \|.*key file/m);
});

test("certdrift check --help documents both options in their own paragraph, says why the passphrase is in the environment, and says where each exit code of the key goes", async () => {
    const help = (await check(["--help"])).stdout;
    assert.match(help, /^ {2}--key <file> {2}/m);
    assert.match(help, /^ {2}--key-passphrase-env <VAR> {2}/m);
    const flat = help.replace(/\s+/g, " ");
    for (const part of ["No option takes the passphrase itself, on purpose", "list of processes", "an empty variable is an empty passphrase", "KEY_MISMATCH", "KEY_UNREADABLE", "The key is never printed", "--warn-only KEY_MISMATCH", "the key file"]) {
        assert.ok(flat.includes(part), `the help says: ${part}`);
    }
    assert.match(help, /^Usage: certdrift check .*--key <file> \[--key-passphrase-env <VAR>\]/m);
    assert.doesNotMatch(help, /PENDING/);
});
