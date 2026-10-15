import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixture, run, targetOf, typed } from "./helpers/command.js";
import { PASSPHRASE, bodyLines, piecesOf, text } from "./helpers/keys.js";
import { validatorFor } from "./helpers/schema.js";

// The key and the passphrase never appear on standard output, on standard error, in the JSON or in
// any message of the real command, in readable output, in --json and with --quiet, for each way a
// check with a key can end, and for the mistakes a person makes with the paths and the options.
//
// What is searched for is every line of every key file among the fixtures, a slice of the middle of
// each, and the first ten characters of each: V8 quotes exactly ten characters of the start of a
// text it cannot parse, and a piece of sixteen would never find that. The passphrases are searched
// for as they were given, in the environment and, for the mistakes, on the command line.

const errorsOf = validatorFor("check-result");
const WRONG = "hunter2-wrong-passphrase";
const IN_FLAG = "hunter2-flag-secret";
const AT = targetOf("leaf-p256.pem").certificate.notBefore;
const ENV = { KEY_PASS: PASSPHRASE, KEY_WRONG: WRONG };

/** @param {string} key */
const startsOf = (key) => bodyLines(key).flatMap((line) => (line.length >= 10 ? [line.slice(0, 10)] : []));

const directory = mkdtempSync(join(tmpdir(), "certdrift-"));
test.after(() => rmSync(directory, { recursive: true, force: true }));

/**
 * A copy of a key file with something in front of it or without its boundary lines, which are the
 * files for which V8 quotes the start of what it was asked to parse as JSON.
 * @param {string} name
 * @param {string} content
 */
function variant(name, content) {
    const path = join(directory, name);
    writeFileSync(path, content);
    return path;
}

const KEYS = ["leaf-p256.key", "leaf-p256.pkcs8-encrypted.key", "leaf-rsa.pkcs1-encrypted.key"];
/** @type {[string, string][]} */
const VARIANTS = KEYS.flatMap((name) => {
    const key = text(name);
    return /** @type {[string, string][]} */ ([
        [`${name} as the body alone`, variant(`body-${name}`, `${bodyLines(key).join("\n")}\n`)],
        [`${name} after the attributes openssl pkcs12 writes`, variant(`bag-${name}`, `Bag Attributes\n    friendlyName: server\n${key}`)],
        [`${name} with a byte order mark`, variant(`bom-${name}`, `﻿${key}`)],
        [`${name} with CRLF line ends`, variant(`crlf-${name}`, key.replaceAll("\n", "\r\n"))],
    ]);
});

/** Everything that must not be printed: the key files of the fixtures and of the variants, and the passphrases. */
const SECRETS = (() => {
    const names = readdirSync(new URL("fixtures/", import.meta.url)).filter((name) => name.endsWith(".key"));
    const keys = [...names.map((name) => text(name)), ...KEYS.map((name) => text(name))];
    const pieces = keys.flatMap((key) => [...piecesOf(key), ...startsOf(key)]);
    return [...new Set([...pieces, PASSPHRASE, WRONG, IN_FLAG])].filter((piece) => piece.length >= 8);
})();

/**
 * @typedef {object} Outcome
 * @property {string} what
 * @property {string[]} args The arguments after `check` and before the output mode.
 * @property {number} code
 * @property {Record<string, string | undefined>} [env]
 * @property {string | Uint8Array} [input]
 */

const CERT = typed("leaf-p256.pem");
const RSA = typed("leaf-rsa.pem");
/** The instant, and a requirement, so that a run that reaches the files has something to check. */
const base = ["--as-of", AT, "--reject-eku", "codeSigning"];

/** @type {Outcome[]} */
const OUTCOMES = [
    { what: "the key matches", args: [...base, "--key", typed("leaf-p256.key"), CERT], code: 0 },
    { what: "the key matches, encrypted, with its passphrase", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", "KEY_PASS", CERT], code: 0 },
    { what: "the traditional key matches, encrypted, with its passphrase", args: [...base, "--key", typed("leaf-rsa.pkcs1-encrypted.key"), "--key-passphrase-env", "KEY_PASS", RSA], code: 0 },
    { what: "the key does not match", args: [...base, "--key", typed("leaf-p256.mismatch.key"), CERT], code: 1 },
    { what: "the key is of another algorithm", args: [...base, "--key", typed("leaf-rsa.key"), CERT], code: 1 },
    { what: "the key is truncated", args: [...base, "--key", typed("leaf-rsa.truncated.key"), RSA], code: 1 },
    { what: "the key is encrypted and no passphrase was given", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), CERT], code: 1 },
    { what: "the traditional key is encrypted and no passphrase was given", args: [...base, "--key", typed("leaf-rsa.pkcs1-encrypted.key"), RSA], code: 1 },
    { what: "the key is encrypted and the passphrase is wrong", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", "KEY_WRONG", CERT], code: 1 },
    { what: "the traditional key is encrypted and the passphrase is wrong", args: [...base, "--key", typed("leaf-rsa.pkcs1-encrypted.key"), "--key-passphrase-env", "KEY_WRONG", RSA], code: 1 },
    { what: "the key is encrypted and the passphrase is empty", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", "KEY_EMPTY", CERT], code: 1, env: { KEY_EMPTY: "" } },
    { what: "the key is not encrypted and a passphrase is given", args: [...base, "--key", typed("leaf-p256.key"), "--key-passphrase-env", "KEY_WRONG", CERT], code: 0 },
    { what: "the file holds two keys", args: [...base, "--key", typed("two-keys.key"), CERT], code: 1 },
    { what: "the file holds a certificate", args: [...base, "--key", typed("leaf-rsa.certificate.key"), RSA], code: 1 },
    { what: "the file holds a public key", args: [...base, "--key", typed("leaf-rsa.public.key"), RSA], code: 1 },
    { what: "the file holds a block that is not a key", args: [...base, "--key", typed("not-a-key.key"), CERT], code: 1 },
    { what: "the key is softened to a warning", args: [...base, "--warn-only", "KEY_MISMATCH", "--key", typed("leaf-p256.mismatch.key"), CERT], code: 0 },
    { what: "the key file does not exist", args: [...base, "--key", join(directory, "missing.key"), CERT], code: 3 },
    { what: "the key file is a directory", args: [...base, "--key", directory, CERT], code: 3 },
    { what: "the policy asks for a key that was not given", args: [...base, "--policy", "schema/examples/policy/pinned.json", CERT], code: 2 },
    { what: "the policy asks for a key and only a passphrase variable was given", args: [...base, "--policy", "schema/examples/policy/every-rule.json", "--key-passphrase-env", "KEY_PASS", CERT], code: 2 },
    { what: "the variable of the passphrase is not defined", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", "KEY_NOT_DEFINED", CERT], code: 2 },
    { what: "the passphrase itself is given as the name of the variable", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", PASSPHRASE, CERT], code: 2 },
    { what: "the passphrase is given as the name of a variable and --key is not", args: [...base, "--key-passphrase-env", PASSPHRASE, CERT], code: 2 },
    { what: "the passphrase is given as an option the command does not have", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), `--key-passphrase=${IN_FLAG}`, CERT], code: 2 },
    { what: "the passphrase is given as a separate argument of an option the command does not have", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase", IN_FLAG, CERT], code: 2 },
    { what: "the passphrase is given as --passphrase", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--passphrase", IN_FLAG, CERT], code: 2 },
    { what: "the passphrase is given as a short option", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), `-p${IN_FLAG}`, CERT], code: 2 },
    { what: "the passphrase is given where the name of a variable starts with a dash", args: [...base, "--key", typed("leaf-p256.pkcs8-encrypted.key"), "--key-passphrase-env", `-${IN_FLAG}`, CERT], code: 2 },
    { what: "the key is given as the path of the certificate", args: [...base, typed("leaf-p256.key")], code: 3 },
    { what: "the encrypted key is given as the path of the certificate", args: [...base, typed("leaf-p256.pkcs8-encrypted.key")], code: 3 },
    { what: "the traditional encrypted key is given as the path of the certificate", args: [...base, typed("leaf-rsa.pkcs1-encrypted.key")], code: 3 },
    { what: "the key is given as the certificate and as the key", args: [...base, "--key", typed("leaf-p256.key"), typed("leaf-p256.key")], code: 3 },
    { what: "the key is given as the certificate on standard input", args: [...base, "-"], code: 3, input: fixture("leaf-p256.pkcs8-encrypted.key") },
    { what: "the key is given as --policy", args: [...base, "--policy", typed("leaf-p256.key"), CERT], code: 3 },
    { what: "the encrypted key is given as --policy", args: [...base, "--policy", typed("leaf-p256.pkcs8-encrypted.key"), CERT], code: 3 },
    { what: "the traditional encrypted key is given as --policy", args: [...base, "--policy", typed("leaf-rsa.pkcs1-encrypted.key"), RSA], code: 3 },
    { what: "the key is given as --policy on standard input", args: [...base, "--policy", "-", CERT], code: 3, input: fixture("leaf-p256.key") },
    { what: "the key is given as --policy and as --key", args: [...base, "--policy", typed("leaf-p256.key"), "--key", typed("leaf-p256.key"), CERT], code: 3 },
    { what: "the key is given as --select", args: [...base, "--select", "-----BEGIN PRIVATE KEY-----", CERT], code: 2 },
    { what: "the key is given as --as-of", args: ["--as-of", text("leaf-p256.key"), "--reject-eku", "codeSigning", CERT], code: 2 },
    ...VARIANTS.flatMap(([name, path]) => [
        { what: `${name}, given as the path of the certificate`, args: [...base, path], code: 3 },
        { what: `${name}, given as --policy`, args: [...base, "--policy", path, CERT], code: 3 },
    ]),
];

/** The three ways to print, which differ in what they write and never in the exit code. */
const MODES = /** @type {const} */ ([
    ["readable", []],
    ["--json", ["--json"]],
    ["--quiet", ["--quiet"]],
]);

/** @param {string} where */
function assertNoSecret(where, /** @type {string} */ output) {
    for (const secret of SECRETS) assert.ok(!output.includes(secret), `${where}: ${JSON.stringify(secret.slice(0, 12))}... is in the output`);
    assert.ok(!/-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----/.test(output), `${where}: a key boundary is in the output`);
}

test("the pieces searched for are in the key files, so that finding none means something", () => {
    assert.ok(SECRETS.length > 50, `${SECRETS.length} pieces`);
    for (const name of KEYS) {
        for (const piece of [...piecesOf(text(name)), ...startsOf(text(name))]) assert.ok(SECRETS.includes(piece), `${name}: ${piece}`);
    }
    // Ten characters of the start of the body, which V8 quotes, are among them.
    assert.ok(SECRETS.includes(text("leaf-p256.key").split("\n")[1].slice(0, 10)));
});

test("the key and the passphrase never appear on standard output, on standard error, in the JSON or in any message, in readable output, in --json and with --quiet, for each way the check can end", { timeout: 240_000 }, async () => {
    const outcomes = OUTCOMES;
    /** @type {[Outcome, ["readable" | "--json" | "--quiet", import("./helpers/command.js").Result][]][]} */
    const done = [];
    for (let start = 0; start < outcomes.length; start += 4) {
        done.push(...(await Promise.all(outcomes.slice(start, start + 4).map(async (outcome) => {
            const runs = await Promise.all(MODES.map(async ([mode, flags]) => /** @type {["readable" | "--json" | "--quiet", import("./helpers/command.js").Result]} */ ([
                mode,
                await run(["check", ...flags, ...outcome.args], { env: { ...ENV, ...outcome.env }, ...(outcome.input === undefined ? {} : { input: outcome.input }) }),
            ])));
            return /** @type {[Outcome, typeof runs]} */ ([outcome, runs]);
        }))));
    }
    assert.ok(done.length > 50, `${done.length} ways to end`);
    for (const [{ what, code }, runs] of done) {
        for (const [mode, result] of runs) {
            const where = `${what} (${mode})`;
            assert.equal(result.code, code, `${where}: ${result.stderr}`);
            assertNoSecret(where, result.stdout);
            assertNoSecret(where, result.stderr);
            if (mode === "--quiet") {
                assert.deepEqual([result.stdout, result.stderr], ["", ""], where);
                continue;
            }
            if (code <= 1) {
                // A check that ran printed what it found, and only that.
                if (mode === "--json") {
                    assert.equal(result.stderr, "", where);
                    assert.deepEqual(errorsOf(JSON.parse(result.stdout)), [], where);
                } else {
                    assert.ok(result.stdout.includes("matchesPrivateKey"), `${where}: the rule is in the output`);
                }
            } else {
                // Misuse and unreadable files say so on standard error, and print nothing else.
                assert.equal(result.stdout, "", where);
                assert.match(result.stderr, /^certdrift: /, where);
            }
        }
    }
});

test("a key given where a policy or a certificate goes is exit 3 with a fixed message that holds none of the file, whatever the file starts with", async () => {
    for (const [name, path] of VARIANTS) {
        const asPolicy = await run(["check", ...base, "--policy", path, CERT]);
        assert.equal(asPolicy.code, 3, name);
        assert.match(asPolicy.stderr, /^certdrift: .*: the policy is not valid JSON\n$/, name);
        const asCertificate = await run(["check", ...base, path]);
        assert.equal(asCertificate.code, 3, name);
        assert.match(asCertificate.stderr, /^certdrift: .*: the material holds no certificate/, name);
    }
    // The files for which V8 does quote the start of the text are among those tried: a text that starts with the body.
    const body = VARIANTS.find(([name]) => name === "leaf-p256.key as the body alone");
    assert.ok(body);
    assert.throws(() => JSON.parse(text("leaf-p256.key").split("\n").slice(1).join("\n")), (error) => error instanceof SyntaxError && error.message.includes(text("leaf-p256.key").split("\n")[1].slice(0, 10)));
});
