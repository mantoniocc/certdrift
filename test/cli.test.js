import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rootCertificates } from "node:tls";
import { inspect, serializeObservation, AmbiguousTargetError } from "../src/index.js";
import { INSPECT_OPTIONS, present } from "../bin/cli.js";
import { validatorFor } from "./helpers/schema.js";

// The command is run as a child process, the way a person runs it, so that the shebang, the
// permission bit, the real streams and the exit code are all part of what is tested. The command
// always observes at the real current time, so nothing here asserts on days remaining, the
// fraction used or whether a certificate is valid; the library gives the values that do not
// depend on the clock, with `at` pinned. Nothing depends on a fixture's exact bytes either:
// `npm run fixtures` replaces them.

const root = new URL("../", import.meta.url);
const fixturesUrl = new URL("test/fixtures/", root);
const BIN = new URL("bin/certdrift.js", root).pathname;
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");
const ESC = String.fromCharCode(27);
const COLOUR = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/** The path of a fixture as someone in the repository would type it. */
const typed = (/** @type {string} */ name) => `test/fixtures/${name}`;

/**
 * @typedef {object} Result
 * @property {number | null} code
 * @property {string} stdout
 * @property {string} stderr
 */

/**
 * @typedef {object} RunOptions
 * @property {Uint8Array | string} [input] Written to standard input, which is then closed.
 * @property {boolean} [openStdin] Leaves standard input open and never writes to it, like a pipe from a program that has not finished.
 * @property {Record<string, string | undefined>} [env] Added to a minimal environment; `undefined` removes a key.
 * @property {string} [cwd]
 * @property {string[]} [nodeArguments] Placed before the script, e.g. `--import`.
 * @property {boolean} [direct] Runs the file itself instead of through `node`.
 * @property {boolean} [closeStdout] Closes the reading end of standard output before the command writes.
 */

/**
 * Runs the command. The environment is minimal and has NO_COLOR set unless a test says otherwise,
 * so that nothing inherited from the machine changes the output.
 * @param {string[]} args
 * @param {RunOptions} [options]
 * @returns {Promise<Result>}
 */
function run(args, { input, openStdin, env = {}, cwd, nodeArguments = [], direct, closeStdout } = {}) {
    /** @type {Record<string, string | undefined>} */
    const merged = { PATH: process.env.PATH, NO_COLOR: "1", ...env };
    for (const key of Object.keys(merged)) if (merged[key] === undefined) delete merged[key];

    const command = direct ? BIN : process.execPath;
    const child = spawn(command, direct ? args : [...nodeArguments, BIN, ...args], {
        cwd,
        env: /** @type {Record<string, string>} */ (merged),
        stdio: [input === undefined && !openStdin ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const { stdout, stderr } = child;
    if (stdout === null || stderr === null) throw new Error("the child has no output streams");
    if (closeStdout) stdout.destroy();
    if (input !== undefined) child.stdin?.end(input);

    return new Promise((resolve, reject) => {
        /** @type {Buffer[]} */ const out = [];
        /** @type {Buffer[]} */ const err = [];
        stdout.on("data", (chunk) => out.push(chunk));
        stderr.on("data", (chunk) => err.push(chunk));
        child.stdin?.on("error", () => {});
        child.on("error", reject);
        child.on("close", (code) => {
            child.stdin?.destroy();
            resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
        });
    });
}

/**
 * The observation printed by `--json`, which must be the whole of standard output.
 * @param {Result} result
 * @returns {ReturnType<typeof inspect>}
 */
function observationOf(result) {
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
}

/** What the library says about a fixture at a pinned time. @param {string} name */
function expected(name) {
    return inspect(fixture(name), { at: AT });
}

/**
 * The text without the lines that depend on the clock, so two runs can be compared.
 * @param {string} text
 */
function withoutRemaining(text) {
    return text.split("\n").filter((line) => !/^\s+remaining\s/.test(line)).join("\n");
}

/** @param {string} name */
function sha256Of(name) {
    return expected(name).certificates[expected(name).target].sha256;
}

// ---------------------------------------------------------------------------------------------
// The executable

test("bin/certdrift.js starts with #!/usr/bin/env node, is executable and runs by its own path", async () => {
    const text = readFileSync(BIN, "utf8");
    assert.equal(text.split("\n")[0], "#!/usr/bin/env node");
    assert.equal(statSync(BIN).mode & 0o111, 0o111, "execute permission for user, group and others");

    const result = await run(["inspect", "--json", typed("leaf-p256.pem")], { direct: true, cwd: new URL(root).pathname });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(observationOf(result).certificates[0].sha256, sha256Of("leaf-p256.pem"));
});

// ---------------------------------------------------------------------------------------------
// Input

test("inspect reads a PEM file, a DER file and standard input (-) as the same certificate", async () => {
    const sha256 = sha256Of("leaf-p256.pem");
    const cwd = new URL(root).pathname;

    const pem = observationOf(await run(["inspect", "--json", typed("leaf-p256.pem")], { cwd }));
    const der = observationOf(await run(["inspect", "--json", typed("leaf-p256.der")], { cwd }));
    const fromPem = observationOf(await run(["inspect", "--json", "-"], { input: fixture("leaf-p256.pem") }));
    const fromDer = observationOf(await run(["inspect", "--json", "-"], { input: fixture("leaf-p256.der") }));

    for (const observation of [pem, der, fromPem, fromDer]) {
        assert.equal(observation.certificates[0].sha256, sha256);
    }
    assert.deepEqual(pem.observation.source, { kind: "file", ref: typed("leaf-p256.pem") });
    assert.deepEqual(der.observation.source, { kind: "file", ref: typed("leaf-p256.der") });
    assert.deepEqual(fromPem.observation.source, { kind: "stdin", ref: "-" });
    assert.deepEqual(fromDer.observation.source, { kind: "stdin", ref: "-" });
});

test("inspect with no argument and no stdin exits 2 with a short usage message", async () => {
    const result = await run(["inspect"]);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^certdrift: no path given/);
    assert.match(result.stderr, /Usage: certdrift inspect /);
    assert.ok(result.stderr.trimEnd().split("\n").length <= 4, `a short message, got:\n${result.stderr}`);
});

test("standard input is read only when it is named with -, whatever is attached to it", { timeout: 20_000 }, async () => {
    // A certificate waiting on standard input is not read without the "-".
    const piped = await run(["inspect"], { input: fixture("leaf-p256.pem") });
    assert.equal(piped.code, 2);
    assert.equal(piped.stdout, "");

    // A pipe that never closes would hang a command that waited for it.
    const open = await run(["inspect"], { openStdin: true });
    assert.equal(open.code, 2);
});

// ---------------------------------------------------------------------------------------------
// Readable output

test("the readable output shows the target's kind, common name, SAN, EKU, validity, key, issuer and fingerprint, one line per other certificate and every warning", async () => {
    const want = expected("bundle-duplicates.pem");
    const [target, ...others] = [want.certificates[want.target], ...want.certificates.filter((_, index) => index !== want.target)];
    const cwd = new URL(root).pathname;
    const { code, stdout, stderr } = await run(["inspect", typed("bundle-duplicates.pem")], { cwd });
    assert.equal(code, 0, stderr);
    assert.equal(stderr, "");
    assert.equal(stdout.includes(ESC), false, "NO_COLOR is set");

    const [head, chain, warnings] = stdout.trimEnd().split("\n\n");
    assert.match(head, /^Target\n/);
    const lines = head.split("\n");
    /** @param {string} label */
    const field = (label) => lines.find((line) => line.startsWith(`  ${label.padEnd(12)}`))?.slice(14);

    assert.equal(field("certificate"), `[${target.index}] ${target.kind}  ${target.subject.cn}`);
    assert.equal(field("san"), `dns: ${target.san.dns.join(", ")}`);
    assert.equal(field("eku"), target.eku?.join(", "));
    assert.equal(field("validity"), `${target.notBefore} to ${target.notAfter}`);
    assert.match(field("remaining") ?? "", /^-?\d+(\.\d)? days?, (-?\d+% of the lifetime used|no lifetime to measure)$/);
    assert.equal(field("key"), "ec P-256 (256 bits)");
    assert.match(field("issuer") ?? "", new RegExp(`^${target.issuer.cn}  \\(issued by \\[${target.issuedBy[0]}\\]\\)$`));
    assert.equal(field("sha256"), target.sha256);

    // The detail of --verbose is not here.
    for (const label of ["subject", "serial", "key sha256", "issuer dn"]) assert.equal(field(label), undefined, label);

    // One line per other certificate, in index order, and nothing else.
    const chainLines = chain.split("\n");
    assert.equal(chainLines[0], "Chain");
    assert.equal(chainLines.length - 1, others.length);
    others.forEach((other, position) => {
        const line = chainLines[position + 1];
        assert.ok(line.startsWith(`  [${other.index}] ${other.kind}  ${other.subject.cn}  `), line);
        assert.ok(line.endsWith(`  ${other.sha256}`), line);
    });
    assert.match(chainLines[chainLines.length - 1], /\(self-signed\)/);

    // Every warning, with its code, the certificate it is about and its message.
    const warningLines = warnings.split("\n");
    assert.equal(warningLines[0], "Warnings");
    assert.deepEqual(
        warningLines.slice(1),
        want.warnings.map((warning) => `  ${warning.code} [${warning.certificate}] ${warning.message}`),
    );
});

test("a material with a single certificate and no warnings has neither a chain nor a warnings section", async () => {
    const { stdout } = await run(["inspect", typed("leaf-p256.pem")], { cwd: new URL(root).pathname });
    assert.match(stdout, /^Target\n/);
    assert.equal(/Chain|Warnings/.test(stdout), false);
});

test("dates are shown in UTC, whatever the time zone", async () => {
    const want = expected("leaf-p256.pem").certificates[0];
    for (const TZ of ["UTC", "Pacific/Auckland", "America/Los_Angeles"]) {
        const { stdout } = await run(["inspect", typed("leaf-p256.pem")], { cwd: new URL(root).pathname, env: { TZ } });
        assert.ok(stdout.includes(`  validity    ${want.notBefore} to ${want.notAfter}\n`), `${TZ}:\n${stdout}`);
    }
});

test("--verbose adds the full names, serial, public key fingerprint, usage OIDs and every chain certificate in detail", async () => {
    const cwd = new URL(root).pathname;
    const want = expected("bundle-ordered.pem");
    const { code, stdout, stderr } = await run(["inspect", "--verbose", typed("bundle-ordered.pem")], { cwd });
    assert.equal(code, 0, stderr);

    // The target block and one full block per other certificate: nothing is left as a one-liner.
    assert.equal(stdout.split("\n").filter((line) => line.startsWith("  certificate ")).length, want.certificates.length);
    for (const certificate of want.certificates) {
        assert.ok(stdout.includes(`  serial      ${certificate.serial}\n`), `serial of ${certificate.index}`);
        assert.ok(stdout.includes(`  subject     ${certificate.subject.dn}\n`), `subject of ${certificate.index}`);
        assert.ok(stdout.includes(`  issuer dn   ${certificate.issuer.dn}\n`), `issuer of ${certificate.index}`);
        assert.ok(stdout.includes(`  sha256      ${certificate.sha256}\n`), `sha256 of ${certificate.index}`);
        assert.ok(stdout.includes(`  key sha256  ${certificate.spkiSha256}\n`), `public key sha256 of ${certificate.index}`);
    }
    // The OIDs stand beside the names.
    assert.ok(stdout.includes("  eku         clientAuth (1.3.6.1.5.5.7.3.2), serverAuth (1.3.6.1.5.5.7.3.1)\n"), stdout);

    // The default output keeps the usage names bare.
    const plain = await run(["inspect", typed("bundle-ordered.pem")], { cwd });
    assert.equal(plain.stdout.includes("1.3.6.1.5.5.7.3"), false);
});

test("--verbose keeps the escape of a comma in a full distinguished name, and an OID with no name as it is", async () => {
    const dn = expected("leaf-multi-dn.pem").certificates[0].subject.dn;
    assert.match(dn, /\\,/, "the fixture has a comma inside a value");
    const { stdout } = await run(["inspect", "-v", typed("leaf-multi-dn.pem")], { cwd: new URL(root).pathname });
    assert.ok(stdout.includes(`  subject     ${dn}\n`), stdout);
});

test("lifetimeFraction is shown as a percentage, and nothing says whether a certificate is valid or expired", () => {
    const base = expected("leaf-p256.pem");
    /** @param {number} daysRemaining @param {number | null} lifetimeFraction */
    const shown = (daysRemaining, lifetimeFraction) => {
        const observation = structuredClone(base);
        observation.certificates[0].derived = { daysRemaining, lifetimeFraction };
        return present(observation, { verbose: false, colour: false });
    };

    // 0.29 * 100 is 28.999999999999996 and 0.57 * 100 is 56.99999999999999.
    const cases = /** @type {[number | null, string][]} */ ([
        [0.45, "45%"], [0.29, "29%"], [0.57, "57%"], [0, "0%"], [1, "100%"], [1.2, "120%"], [-0.05, "-5%"],
    ]);
    for (const [fraction, text] of cases) {
        assert.ok(shown(10, fraction).includes(`  remaining   10 days, ${text} of the lifetime used\n`), `${fraction}`);
    }
    assert.ok(shown(10, null).includes("  remaining   10 days, no lifetime to measure\n"));

    // The numbers are the observation's own, with their sign, and one day is not "1 days".
    assert.ok(shown(44.4, 0.5).includes("  remaining   44.4 days, 50%"));
    assert.ok(shown(1, 0.5).includes("  remaining   1 day, 50%"));
    assert.ok(shown(-3.5, 1.1).includes("  remaining   -3.5 days, 110%"));
    assert.ok(shown(0, 1).includes("  remaining   0 days, 100%"));
    for (const [days, fraction] of [[-3.5, 1.1], [100, 0.1], [0, null]]) {
        assert.equal(/expired|\bvalid\b|\bok\b/i.test(shown(days ?? 0, fraction)), false);
    }
});

test("an extended key usage extension that is absent, and one that is present and empty, are told apart", () => {
    const base = expected("leaf-p256.pem");
    /** @param {string[] | null} eku */
    const shown = (eku) => {
        const observation = structuredClone(base);
        observation.certificates[0].eku = eku;
        return present(observation, { verbose: true, colour: false });
    };
    assert.ok(shown(null).includes("  eku         absent (no restriction)\n"));
    assert.ok(shown([]).includes("  eku         empty\n"));
    assert.ok(shown(["1.3.6.1.4.1.311.10.3.4", "serverAuth"]).includes("  eku         1.3.6.1.4.1.311.10.3.4, serverAuth (1.3.6.1.5.5.7.3.1)\n"));
    // A name that is also the name of something on every object is not an OID lookup.
    assert.ok(shown(["constructor", "toString"]).includes("  eku         constructor, toString\n"));
});

test("a certificate with no common name, an empty name or an unknown key is shown without inventing a value", () => {
    const observation = structuredClone(expected("leaf-p256.pem"));
    const [certificate] = observation.certificates;
    certificate.subject = { cn: null, dn: "O=Acme\\, Inc., OU=Platform" };
    certificate.issuer = { cn: null, dn: "" };
    certificate.key = { algorithm: null, size: null, curve: null };
    certificate.san = { dns: [], ip: [], email: [], uri: [] };
    certificate.issuedBy = [];
    const text = present(observation, { verbose: false, colour: false });
    assert.ok(text.includes("  certificate [0] end-entity  O=Acme\\, Inc., OU=Platform\n"), text);
    assert.ok(text.includes("  issuer      (empty name)  (issuer not in the material)\n"), text);
    assert.ok(text.includes("  key         unknown\n"), text);
    assert.ok(text.includes("  san         none\n"), text);
});

// ---------------------------------------------------------------------------------------------
// --json, --quiet

test("--json prints exactly what serializeObservation returns and nothing else, and errors go only to stderr", async () => {
    const cwd = new URL(root).pathname;
    const before = Date.now();
    const result = await run(["inspect", "--json", typed("bundle-ordered.pem")], { cwd, env: { NO_COLOR: undefined } });
    const after = Date.now();
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");

    // The whole of standard output is one document in the serializer's bytes: re-serializing what
    // was parsed gives the same text, so the command added nothing and reordered nothing.
    const observation = JSON.parse(result.stdout);
    assert.equal(result.stdout, serializeObservation(observation));
    assert.equal(result.stdout.endsWith("}\n"), true);
    assert.equal(result.stdout.includes(ESC), false, "no colour in JSON, with or without NO_COLOR");
    assert.deepEqual(errorsOf(observation), []);

    // The moment is the real one, in whole seconds: the command has no option to pin it.
    const at = Date.parse(observation.observation.at);
    assert.ok(at >= Math.floor(before / 1000) * 1000 && at <= after, `${observation.observation.at}`);

    // The other flags do not change the document.
    const verbose = JSON.parse((await run(["inspect", "--json", "--verbose", typed("bundle-ordered.pem")], { cwd })).stdout);
    verbose.observation.at = observation.observation.at;
    verbose.certificates.forEach((/** @type {{ derived: unknown }} */ certificate, /** @type {number} */ position) => {
        observation.certificates[position].derived = certificate.derived;
    });
    assert.deepEqual(verbose, observation);

    // A failure prints nothing on standard output, so a pipe never receives half a document.
    for (const args of [["inspect", "--json", "missing.pem"], ["inspect", "--json"], ["inspect", "--json", typed("bundle-two-leaves.pem")]]) {
        const failed = await run(args, { cwd });
        assert.notEqual(failed.code, 0);
        assert.equal(failed.stdout, "", args.join(" "));
        assert.notEqual(failed.stderr, "", args.join(" "));
    }
});

test("--quiet prints nothing and keeps the exit code", async () => {
    const cwd = new URL(root).pathname;
    const cases = /** @type {[string[], number][]} */ ([
        [["inspect", "-q", typed("leaf-p256.pem")], 0],
        [["inspect", "--quiet", typed("bundle-duplicates.pem")], 0],
        [["inspect", "--quiet", "--json", typed("leaf-p256.pem")], 0],
        [["inspect", "-qv", typed("leaf-p256.pem")], 0],
        [["inspect", "-q", typed("bundle-two-leaves.pem")], 2],
        [["inspect", "-q"], 2],
        [["inspect", "-q", "--bogus", "x"], 2],
        [["inspect", "-q", "a", "b"], 2],
        [["-q"], 2],
        [["-q", "other"], 2],
        [["inspect", "-q", "missing.pem"], 3],
        [["inspect", "-q", typed("leaf-p256.key")], 3],
        [["inspect", "-q", "--help"], 0],
    ]);
    for (const [args, code] of cases) {
        const result = await run(args, { cwd });
        assert.deepEqual([args.join(" "), result.code, result.stdout, result.stderr], [args.join(" "), code, "", ""]);
    }
    const stdin = await run(["inspect", "-q", "-"], { input: "not a certificate" });
    assert.deepEqual([stdin.code, stdin.stdout, stdin.stderr], [3, "", ""]);
});

// ---------------------------------------------------------------------------------------------
// Colour

/** Makes a standard stream believe it is a terminal that understands colour. */
const TERMINAL = `data:text/javascript,${encodeURIComponent(`
for (const stream of [process.stdin, process.stdout, process.stderr]) {
    Object.defineProperty(stream, "isTTY", { value: true });
    stream.hasColors = () => true;
    stream.getColorDepth = () => 8;
}`)}`;

test("NO_COLOR is respected, and it is the only condition that disables colour: the output does not change with a terminal", async () => {
    const cwd = new URL(root).pathname;
    const args = ["inspect", typed("bundle-ordered.pem")];

    // Through a pipe, with nothing set, the output is coloured: no terminal is needed for it.
    const coloured = await run(args, { cwd, env: { NO_COLOR: undefined } });
    assert.equal(coloured.code, 0, coloured.stderr);
    assert.match(coloured.stdout, COLOUR);
    const plain = coloured.stdout.replace(COLOUR, "");
    assert.equal(plain.includes(ESC), false);

    // A terminal, a dumb one, an explicit request for colour or against it: nothing changes.
    /** @type {[string, RunOptions][]} */
    const same = [
        ["a terminal", { nodeArguments: ["--import", TERMINAL] }],
        ["TERM=dumb", { env: { TERM: "dumb" } }],
        ["TERM=xterm-256color", { env: { TERM: "xterm-256color" } }],
        ["FORCE_COLOR=1", { env: { FORCE_COLOR: "1" } }],
        ["FORCE_COLOR=0", { env: { FORCE_COLOR: "0" } }],
        ["NODE_DISABLE_COLORS=1", { env: { NODE_DISABLE_COLORS: "1" } }],
        ["NO_COLOR empty", { env: { NO_COLOR: "" } }],
    ];
    for (const [name, options] of same) {
        const result = await run(args, { cwd, ...options, env: { NO_COLOR: undefined, ...options.env } });
        assert.equal(withoutRemaining(result.stdout), withoutRemaining(coloured.stdout), name);
    }

    // NO_COLOR with any value turns it off, with or without a terminal, and it is the same text.
    for (const NO_COLOR of ["1", "0", "false", "anything"]) {
        for (const nodeArguments of [[], ["--import", TERMINAL]]) {
            const result = await run(args, { cwd, nodeArguments, env: { NO_COLOR } });
            assert.equal(withoutRemaining(result.stdout), withoutRemaining(plain), `NO_COLOR=${NO_COLOR} ${nodeArguments.length ? "terminal" : "pipe"}`);
        }
    }

    // The headings are bold and the warning codes yellow, and nothing else is painted.
    const duplicates = await run(["inspect", typed("bundle-duplicates.pem")], { cwd, env: { NO_COLOR: undefined } });
    for (const heading of ["Target", "Chain", "Warnings"]) assert.ok(duplicates.stdout.includes(`${ESC}[1m${heading}${ESC}[22m`), heading);
    assert.ok(duplicates.stdout.includes(`${ESC}[33mDUPLICATE_CERTIFICATE${ESC}[39m`));
    assert.equal(duplicates.stdout.match(COLOUR)?.length, 8, "three headings and one code, each opened and closed");

    // Standard error is plain text always, with a terminal and without NO_COLOR.
    const failed = await run(["inspect", typed("bundle-two-leaves.pem")], { cwd, nodeArguments: ["--import", TERMINAL], env: { NO_COLOR: undefined } });
    assert.equal(failed.code, 2);
    assert.equal(failed.stderr.includes(ESC), false);
});

// ---------------------------------------------------------------------------------------------
// Ambiguity and --select

test("an ambiguous bundle exits 2 listing the candidates, and --select with a unique prefix resolves it", async () => {
    const cwd = new URL(root).pathname;
    const candidates = [
        { name: "leaf-rsa.pem", cn: "rsa.example" },
        { name: "leaf-p256.pem", cn: "p256.example" },
    ].map((candidate) => ({ ...candidate, sha256: sha256Of(candidate.name) }));

    const ambiguous = await run(["inspect", typed("bundle-two-leaves.pem")], { cwd });
    assert.equal(ambiguous.code, 2);
    assert.equal(ambiguous.stdout, "");
    for (const { sha256, cn } of candidates) {
        assert.ok(ambiguous.stderr.includes(sha256), `lists ${sha256}`);
        assert.ok(ambiguous.stderr.includes(cn), `lists ${cn}`);
    }
    assert.match(ambiguous.stderr, /--select/);
    assert.match(ambiguous.stderr, /input block 1: .*\ninput block 2: /, "one candidate per line");

    for (const { name, sha256 } of candidates) {
        for (const select of [sha256, sha256.slice(0, 16), sha256.slice(0, 16).toUpperCase()]) {
            for (const args of [["inspect", "--json", "--select", select, typed("bundle-two-leaves.pem")], ["inspect", `--select=${select}`, "--json", typed("bundle-two-leaves.pem")]]) {
                const observation = observationOf(await run(args, { cwd }));
                assert.equal(observation.certificates[observation.target].sha256, sha256, args.join(" "));
            }
        }
        // It works through standard input too, and in the readable output.
        const text = await run(["inspect", "--select", sha256.slice(0, 12), "-"], { input: fixture("bundle-two-leaves.pem") });
        assert.equal(text.code, 0, text.stderr);
        assert.ok(text.stdout.includes(`  sha256      ${sha256}\n`));
    }

    // A prefix that matches nothing is ambiguity too, and it lists the candidates again.
    for (const select of ["0".repeat(10), "zz"]) {
        const none = await run(["inspect", "--select", select, typed("bundle-two-leaves.pem")], { cwd });
        assert.equal(none.code, 2);
        assert.match(none.stderr, /matches no candidate/);
        assert.ok(candidates.every(({ sha256 }) => none.stderr.includes(sha256)));
    }
});

test("--select that matches several candidates exits 2, and a bundle where every certificate signs another one is resolved by it", async () => {
    const cwd = new URL(root).pathname;
    const leaves = readdirSync(fixturesUrl).filter((name) => /^leaf-.*\.pem$/.test(name) && !name.includes("mismatch"));
    const sharing = leaves.flatMap((one, i) => leaves.slice(i + 1).map((other) => [one, other])).find(([one, other]) => sha256Of(one)[0] === sha256Of(other)[0]);
    const [one, other] = sharing ?? assert.fail("no two leaves share a first digit");
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    try {
        const path = join(dir, "two.pem");
        writeFileSync(path, Buffer.concat([fixture(one), fixture(other)]));
        const several = await run(["inspect", "--select", sha256Of(one)[0], path]);
        assert.equal(several.code, 2);
        assert.match(several.stderr, /matches 2 candidates/);
        assert.equal((await run(["inspect", "--select", sha256Of(other).slice(0, 12), path])).code, 0);
    } finally {
        rmSync(dir, { recursive: true });
    }

    // Both certificates of the renewed root sign the other: the message says so, and a prefix chooses.
    const renewed = await run(["inspect", typed("bundle-renewed-root.pem")], { cwd });
    assert.equal(renewed.code, 2);
    assert.match(renewed.stderr, /every certificate in the material signs another one/);
    const sha256 = sha256Of("root-ca-renewed.pem");
    const chosen = observationOf(await run(["inspect", "--json", "--select", sha256.slice(0, 10), typed("bundle-renewed-root.pem")], { cwd }));
    assert.equal(chosen.certificates[chosen.target].sha256, sha256);
});

// ---------------------------------------------------------------------------------------------
// Exit codes

test("exit codes: 0 on success, 2 on misuse or ambiguity, 3 when the file is missing, unreadable or unparseable", async (t) => {
    const cwd = new URL(root).pathname;
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    writeFileSync(join(dir, "empty.pem"), "");
    writeFileSync(join(dir, "text.pem"), "this is not a certificate\n");
    const pem = fixture("leaf-p256.pem").toString("utf8");
    writeFileSync(join(dir, "truncated.pem"), pem.slice(0, pem.length / 2));
    mkdirSync(join(dir, "directory"));
    writeFileSync(join(dir, "locked.pem"), pem);
    chmodSync(join(dir, "locked.pem"), 0o000);
    const root_ = process.getuid?.() === 0;

    /** @type {[string, string[], RunOptions, number][]} */
    const table = [
        // 0
        ["a PEM file", ["inspect", typed("leaf-p256.pem")], {}, 0],
        ["a certificate that expired, which is not this command's concern", ["inspect", typed("leaf-expired.pem")], {}, 0],
        ["a bundle with a warning", ["inspect", typed("bundle-duplicates.pem")], {}, 0],
        ["--help", ["--help"], {}, 0],
        ["inspect --help", ["inspect", "-h"], {}, 0],
        // 2
        ["no command", [], {}, 2],
        ["an unknown command", ["frobnicate", "x"], {}, 2],
        ["an option in place of the command", ["--json", typed("leaf-p256.pem")], {}, 2],
        ["no path", ["inspect"], {}, 2],
        ["no path, with flags", ["inspect", "--json", "-v"], {}, 2],
        ["two paths", ["inspect", typed("leaf-p256.pem"), typed("leaf-rsa.pem")], {}, 2],
        ["an unknown flag", ["inspect", "--nope", typed("leaf-p256.pem")], {}, 2],
        ["an unknown short flag", ["inspect", "-x", typed("leaf-p256.pem")], {}, 2],
        ["a flag given a value it does not take", ["inspect", "--verbose=yes", typed("leaf-p256.pem")], {}, 2],
        ["--select without a value", ["inspect", typed("leaf-p256.pem"), "--select"], {}, 2],
        ["--select followed by a flag", ["inspect", "--select", "--json", typed("leaf-p256.pem")], {}, 2],
        // Each prefix alone would resolve the bundle, so only the repetition can make it misuse.
        ["--select given twice", ["inspect", "--select", sha256Of("leaf-rsa.pem").slice(0, 12), "--select", sha256Of("leaf-p256.pem").slice(0, 12), typed("bundle-two-leaves.pem")], {}, 2],
        ["--select given twice with the same prefix", ["inspect", "--select", sha256Of("leaf-rsa.pem").slice(0, 12), "--select", sha256Of("leaf-rsa.pem").slice(0, 12), typed("bundle-two-leaves.pem")], {}, 2],
        ["--select with nothing after the equals sign", ["inspect", "--select=", typed("leaf-p256.pem")], {}, 2],
        ["--select that does not match the target of a single certificate", ["inspect", "--select", "0000000000", typed("leaf-p256.pem")], {}, 2],
        ["an ambiguous bundle", ["inspect", typed("bundle-two-leaves.pem")], {}, 2],
        // 3
        ["a missing file", ["inspect", join(dir, "missing.pem")], {}, 3],
        ["an empty path", ["inspect", ""], {}, 3],
        ["a directory", ["inspect", join(dir, "directory")], {}, 3],
        ["an empty file", ["inspect", join(dir, "empty.pem")], {}, 3],
        ["a file that is not a certificate", ["inspect", join(dir, "text.pem")], {}, 3],
        ["a PEM block that stops half way", ["inspect", join(dir, "truncated.pem")], {}, 3],
        ["a private key", ["inspect", typed("leaf-p256.key")], {}, 3],
        ["empty standard input", ["inspect", "-"], { input: "" }, 3],
        ["standard input that is closed", ["inspect", "-"], {}, 3],
        ["text on standard input", ["inspect", "-"], { input: "hello" }, 3],
        ["bytes on standard input that start like DER and are not", ["inspect", "-"], { input: Buffer.from([0x30, 0x82, 0x00, 0x01, 0x00]) }, 3],
    ];
    if (!root_) table.push(["a file that can not be read", ["inspect", join(dir, "locked.pem")], {}, 3]);

    for (const [name, args, options, code] of table) {
        await t.test(`${name} exits ${code}`, async () => {
            const result = await run(args, { cwd, ...options });
            assert.equal(result.code, code, result.stderr);
            if (code === 0) assert.equal(result.stderr, "");
            else assert.equal(result.stdout, "", "a failure prints nothing on standard output");
            if (code !== 0) assert.match(result.stderr, /^certdrift: /);
        });
    }
});

test("a message about a file names it, and the usage message names the flags that exist", async () => {
    const missing = await run(["inspect", "no-such-file.pem"]);
    assert.match(missing.stderr, /^certdrift: cannot read no-such-file\.pem: ENOENT/);
    const text = await run(["inspect", "-"], { input: "hello" });
    assert.match(text.stderr, /^certdrift: standard input: the material holds no certificate/);

    const help = await run(["--help"]);
    // Each flag has its own line in the options list, with its short form where it has one.
    for (const [name, option] of Object.entries(INSPECT_OPTIONS)) {
        const short = "short" in option ? `-${option.short}, ` : "";
        assert.match(help.stdout, new RegExp(`^  ${short}--${name}[ \\n]`, "m"), `--help lists ${short}--${name}`);
    }
    for (const code of [0, 2, 3]) assert.match(help.stdout, new RegExp(`^  ${code}  `, "m"));
    assert.match(help.stdout, /NO_COLOR/);
});

// ---------------------------------------------------------------------------------------------
// The source of the observation

const FLAG_ARGUMENTS = {
    json: ["--json"],
    verbose: ["--json", "--verbose"],
    quiet: ["--json", "--quiet"],
    select: ["--json", "--select", sha256Of("leaf-p256.pem").slice(0, 12)],
    help: ["--json", "--help"],
};

test("no flag writes into the observation's source", async () => {
    // A flag added to the command must be added here, shown not to touch the source.
    assert.deepEqual(Object.keys(INSPECT_OPTIONS).sort(), Object.keys(FLAG_ARGUMENTS).sort());

    const cwd = new URL(root).pathname;
    for (const [flag, flags] of Object.entries(FLAG_ARGUMENTS)) {
        const result = await run(["inspect", ...flags, typed("bundle-ordered.pem")], { cwd });
        if (flag === "quiet") {
            assert.equal(result.stdout, "", flag);
        } else if (flag === "help") {
            assert.match(result.stdout, /^certdrift inspects/);
            assert.equal(result.stdout.includes('"source"'), false);
        } else {
            const { source } = observationOf(result).observation;
            assert.deepEqual(source, { kind: "file", ref: typed("bundle-ordered.pem") }, flag);
            assert.deepEqual(Object.keys(source), ["kind", "ref"], flag);
        }
    }

    // Standard input has its own source, and a flag does not change that either.
    const piped = observationOf(await run(["inspect", "--json", "--verbose", "--select", sha256Of("leaf-p256.pem").slice(0, 12), "-"], { input: fixture("bundle-ordered.pem") }));
    assert.deepEqual(piped.observation.source, { kind: "stdin", ref: "-" });
});

/** @type {Promise<{ name: string, byPath: Result, byStdin: Result, select: string[] }[]> | undefined} */
let everyFixture;

/**
 * The command run with --json over every certificate fixture, by path and through standard input.
 * A bundle that is ambiguous is resolved with a prefix of its first candidate.
 */
function overEveryFixture() {
    everyFixture ??= (async () => {
        const names = readdirSync(fixturesUrl).filter((name) => /\.(pem|der)$/.test(name)).sort();
        assert.ok(names.length > 30, `found ${names.length} certificate fixtures`);
        const runs = [];
        for (let start = 0; start < names.length; start += 12) {
            runs.push(...await Promise.all(names.slice(start, start + 12).map(async (name) => {
                let select = /** @type {string[]} */ ([]);
                try {
                    inspect(fixture(name), { at: AT });
                } catch (error) {
                    if (!(error instanceof AmbiguousTargetError)) throw error;
                    select = ["--select", error.candidates[0].sha256.slice(0, 16)];
                }
                const [byPath, byStdin] = await Promise.all([
                    run(["inspect", "--json", ...select, typed(name)], { cwd: new URL(root).pathname }),
                    run(["inspect", "--json", ...select, "-"], { input: fixture(name) }),
                ]);
                return { name, byPath, byStdin, select };
            })));
        }
        return runs;
    })();
    return everyFixture;
}

test("over every fixture the command produces only a file, stdin or host source", async () => {
    for (const { name, byPath, byStdin } of await overEveryFixture()) {
        const path = observationOf(byPath).observation.source;
        const stdin = observationOf(byStdin).observation.source;
        assert.deepEqual(path, { kind: "file", ref: typed(name) }, name);
        assert.deepEqual(stdin, { kind: "stdin", ref: "-" }, name);
        for (const { kind } of [path, stdin]) assert.ok(["file", "stdin", "host"].includes(kind), `${name}: ${kind}`);
    }
});

test("--json over every fixture validates against the observation schema, by path and through standard input", async () => {
    for (const { name, byPath, byStdin } of await overEveryFixture()) {
        for (const [how, result] of /** @type {[string, Result][]} */ ([["path", byPath], ["stdin", byStdin]])) {
            assert.equal(result.stderr, "", `${name} by ${how}`);
            const observation = observationOf(result);
            assert.deepEqual(errorsOf(observation), [], `${name} by ${how}`);
            assert.equal(result.stdout, serializeObservation(observation), `${name} by ${how}`);
        }
    }
});

// ---------------------------------------------------------------------------------------------
// Cases the criteria do not name and the purpose of the command covers

test("a file named - is read as a file when it is written ./-, and a path that starts with a dash after --", async () => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    try {
        writeFileSync(join(dir, "-"), fixture("leaf-p256.pem"));
        writeFileSync(join(dir, "-x.pem"), fixture("leaf-p256.pem"));
        const named = observationOf(await run(["inspect", "--json", "./-"], { cwd: dir }));
        assert.deepEqual(named.observation.source, { kind: "file", ref: "./-" });

        const dashed = observationOf(await run(["inspect", "--json", "--", "-x.pem"], { cwd: dir }));
        assert.deepEqual(dashed.observation.source, { kind: "file", ref: "-x.pem" });

        // Without the "--" it is a flag, which the parser says how to fix.
        const flag = await run(["inspect", "-x.pem"], { cwd: dir });
        assert.equal(flag.code, 2);
        assert.match(flag.stderr, /Unknown option '-x'/);
    } finally {
        rmSync(dir, { recursive: true });
    }
});

test("a bundle with a private key next to its certificates is read, and the key alone is not a certificate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    try {
        writeFileSync(join(dir, "both.pem"), Buffer.concat([fixture("leaf-p256.key"), fixture("bundle-ordered.pem")]));
        const observation = observationOf(await run(["inspect", "--json", join(dir, "both.pem")]));
        assert.equal(observation.certificates.length, 3);
    } finally {
        rmSync(dir, { recursive: true });
    }
});

// A self-signed certificate made with `openssl req` whose subject common name holds an escape
// sequence, a bell and a right-to-left override, and whose DNS name holds an escape sequence.
const HOSTILE = `-----BEGIN CERTIFICATE-----
MIIBsDCCAVegAwIBAgIUKei+pEzSzy9QwqkwPxSUnErCphYwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUZXZpbBtdMDtwd25lZAcgYeKArmIwIBcNMjYxMDExMDIyMjU5
WhgPMjEyNjA5MTcwMjIyNTlaMB8xHTAbBgNVBAMMFGV2aWwbXTA7cHduZWQHIGHi
gK5iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbz+M9YHFy5+q7fmjnLI83uXA
5z/Y1RzVb28ru4qLwVIWzN8PBe5pLVVNEkvdINMZxwMOiJNlFfpHQp4iBFIZ7aNv
MG0wHQYDVR0OBBYEFAXn/88pSdhdnnidhrEDzbb1aXK1MB8GA1UdIwQYMBaAFAXn
/88pSdhdnnidhrEDzbb1aXK1MA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIP
YRtbMzFtYi5leGFtcGxlMAoGCCqGSM49BAMCA0cAMEQCIG8nNQnbCCwF81UxoIS5
3l5Exvb9uuv9s9Uy2j99n9jaAiBVk4wDZqeiVTITNdpq82nJ4zQ74N1VDQjTM134
ijCNBA==
-----END CERTIFICATE-----
`;

test("text a certificate controls can not move the cursor, retitle the window or reverse the line: it is shown escaped", async () => {
    // The library keeps what the certificate holds, which is what --json prints.
    const held = inspect(HOSTILE, { at: AT }).certificates[0];
    assert.equal(held.subject.cn, `evil${ESC}]0;pwned\u0007 a‮b`);
    assert.deepEqual(held.san.dns, [`a${ESC}[31mb.example`]);
    const json = observationOf(await run(["inspect", "--json", "-"], { input: HOSTILE }));
    assert.equal(json.certificates[0].subject.cn, held.subject.cn);

    for (const flags of [[], ["--verbose"]]) {
        const { code, stdout, stderr } = await run(["inspect", ...flags, "-"], { input: HOSTILE });
        assert.equal(code, 0, stderr);
        assert.equal(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/.test(stdout), false, `${flags} has a control character`);
        assert.ok(stdout.includes("evil\\u{1B}]0;pwned\\u{7} a\\u{202E}b"), stdout);
        assert.ok(stdout.includes("dns: a\\u{1B}[31mb.example"), stdout);
    }

    // With colour on, the only escape sequences are the command's own.
    const coloured = await run(["inspect", "-"], { input: HOSTILE, env: { NO_COLOR: undefined } });
    assert.equal(coloured.stdout.replace(COLOUR, "").includes(ESC), false);

    // The same goes for what is written to standard error: a path, an error message.
    const path = `${ESC}]0;pwned\u0007missing.pem`;
    const failed = await run(["inspect", path]);
    assert.equal(failed.code, 3);
    assert.equal(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(failed.stderr), false);
    assert.ok(failed.stderr.includes("\\u{1B}]0;pwned\\u{7}missing.pem"), failed.stderr);
});

test("output larger than a pipe holds arrives whole, and a reader that stops early does not change the exit code", { timeout: 30_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    try {
        // Every root signs no other one, so they are all candidates and one is chosen.
        const path = join(dir, "roots.pem");
        writeFileSync(path, rootCertificates.join("\n"));
        const error = (() => {
            try {
                inspect(readFileSync(path), { at: AT });
            } catch (caught) {
                return caught;
            }
        })();
        assert.ok(error instanceof AmbiguousTargetError, "the system roots are ambiguous");
        const select = error.candidates[0].sha256.slice(0, 20);

        const whole = await run(["inspect", "--json", "--select", select, path]);
        assert.equal(whole.code, 0, whole.stderr);
        assert.ok(whole.stdout.length > 65_536, `${whole.stdout.length} characters is not more than a pipe's buffer`);
        const observation = JSON.parse(whole.stdout);
        assert.equal(observation.certificates.length, rootCertificates.length);
        assert.equal(whole.stdout, serializeObservation(observation));

        const text = await run(["inspect", "--verbose", "--select", select, path]);
        assert.equal(text.code, 0, text.stderr);
        assert.equal(text.stdout.split("\n").filter((line) => line.startsWith("  certificate ")).length, rootCertificates.length);

        // The reading end is closed before the command writes: it must not die on the write.
        const early = await run(["inspect", "--json", "--select", select, path], { closeStdout: true });
        assert.equal(early.code, 0);
        assert.equal(early.stderr, "");
        const failing = await run(["inspect", "--json", path], { closeStdout: true });
        assert.equal(failing.code, 2, "the exit code of the command, not of the broken pipe");
    } finally {
        rmSync(dir, { recursive: true });
    }
});

test("every flag may come before or after the path", async () => {
    const cwd = new URL(root).pathname;
    const before = await run(["inspect", "--json", "-v", typed("leaf-p256.pem")], { cwd });
    const after = await run(["inspect", typed("leaf-p256.pem"), "-v", "--json"], { cwd });
    const [one, two] = [before, after].map((result) => observationOf(result).certificates);
    assert.deepEqual(one, two);
});

test("a file the way editors and other tools write it is read: a byte order mark, Windows line ends, text around the blocks", async () => {
    const pem = fixture("leaf-p256.pem");
    const sha256 = sha256Of("leaf-p256.pem");
    const forms = {
        "a UTF-8 byte order mark": Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), pem]),
        "CRLF line ends": Buffer.from(pem.toString("utf8").replaceAll("\n", "\r\n")),
        "the output of openssl s_client": Buffer.from(`CONNECTED(00000003)\n---\nCertificate chain\n${pem.toString("utf8")}---\nServer certificate\n`),
    };
    for (const [name, input] of Object.entries(forms)) {
        const observation = observationOf(await run(["inspect", "--json", "-"], { input }));
        assert.equal(observation.certificates[0].sha256, sha256, name);
    }
});

test("a certificate saved as UTF-16, as PowerShell redirection does, exits 3 instead of being read as something else", async () => {
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(fixture("leaf-p256.pem").toString("utf8"), "utf16le")]);
    const result = await run(["inspect", "-"], { input: utf16 });
    assert.equal(result.code, 3);
    assert.match(result.stderr, /holds no certificate/);
});

test("a fingerprint copied with colons, as openssl prints it, is not a prefix of a sha256 and matches nothing", async () => {
    const sha256 = sha256Of("leaf-p256.pem");
    const withColons = sha256.slice(0, 6).replace(/(..)(?=.)/g, "$1:").toUpperCase();
    assert.match(withColons, /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/);
    const result = await run(["inspect", "--select", withColons, typed("bundle-two-leaves.pem")], { cwd: new URL(root).pathname });
    assert.equal(result.code, 2);
    assert.match(result.stderr, /matches no candidate/);
});

test("standard input is read to its end however many chunks it arrives in", { timeout: 30_000 }, async () => {
    // More than a pipe holds, so the command reads it in several pieces.
    const roots = rootCertificates.join("\n");
    const error = (() => {
        try {
            inspect(roots, { at: AT });
        } catch (caught) {
            return caught;
        }
    })();
    assert.ok(error instanceof AmbiguousTargetError);
    assert.ok(roots.length > 65_536);
    const observation = observationOf(await run(["inspect", "--json", "--select", error.candidates[0].sha256.slice(0, 20), "-"], { input: roots }));
    assert.equal(observation.certificates.length, rootCertificates.length);
    assert.deepEqual(observation.observation.source, { kind: "stdin", ref: "-" });
});
