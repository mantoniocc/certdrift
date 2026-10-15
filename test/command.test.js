import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "../src/index.js";
import { QUIET_ONLY, colourOn, misuseOf, observe, painter, parseFlags, readInput, warningLines, wantsQuiet } from "../bin/command.js";
import { fixture } from "./helpers/command.js";

// What `inspect` and `check` share: reading a path or standard input, saying what the library's two
// errors mean, reading --quiet before the arguments are known to be valid, colour, misuse and the
// observation's warnings. The commands are tested through the real executable; these are the cases
// that only the functions can be asked.

const ESC = String.fromCharCode(27);
const OPTIONS = /** @type {const} */ ({ quiet: { type: "boolean", short: "q" }, select: { type: "string", multiple: true }, json: { type: "boolean" } });

/** @param {(string | Uint8Array)[]} pieces */
async function* chunks(...pieces) {
    for (const piece of pieces) yield piece;
}

test("--quiet is found among arguments that are invalid in other ways, and a flag that takes a value takes the next argument whatever it is", () => {
    for (const argv of [["-q"], ["--quiet"], ["x", "-q", "y"], ["-qj"], ["--bogus", "-q"], ["--select", "a", "-q"], ["-q", "--select"]]) {
        assert.equal(wantsQuiet(argv, OPTIONS), true, argv.join(" "));
    }
    for (const argv of [[], ["x"], ["--json"], ["--select", "-q"], ["--select=-q"], ["--", "-q"]]) {
        assert.equal(wantsQuiet(argv, OPTIONS), false, argv.join(" "));
    }
    // With the options of no command, only --quiet is known, so a value of another flag is not taken.
    assert.equal(wantsQuiet(["--select", "-q"], QUIET_ONLY), true);
    assert.equal(wantsQuiet(["frobnicate"], QUIET_ONLY), false);
});

test("colour is on unless NO_COLOR has a value, and nothing else is looked at", () => {
    assert.equal(colourOn({}), true);
    assert.equal(colourOn({ NO_COLOR: undefined }), true);
    assert.equal(colourOn({ NO_COLOR: "" }), true);
    for (const value of ["1", "0", "false", " ", "anything"]) assert.equal(colourOn({ NO_COLOR: value }), false, JSON.stringify(value));
    assert.equal(colourOn({ NO_COLOR: "", TERM: "dumb", FORCE_COLOR: "0", NODE_DISABLE_COLORS: "1" }), true);
});

test("the painter writes an escape sequence when colour is on and the text unchanged when it is off, whatever the terminal", () => {
    assert.equal(painter(true)("bold", "x"), `${ESC}[1mx${ESC}[22m`);
    assert.equal(painter(true)("red", "x"), `${ESC}[31mx${ESC}[39m`);
    assert.equal(painter(false)("bold", "x"), "x");
});

test("parseFlags gives the values and the positionals, and the parser's own complaint as misuse in its first line", () => {
    const parsed = parseFlags(["a", "--select", "ab", "--json", "b"], OPTIONS);
    assert.ok("values" in parsed);
    assert.deepEqual({ ...parsed.values }, { select: ["ab"], json: true });
    assert.deepEqual(parsed.positionals, ["a", "b"]);
    const unknown = parseFlags(["--bogus"], OPTIONS);
    assert.ok("misuse" in unknown && unknown.misuse.startsWith("Unknown option '--bogus'"), JSON.stringify(unknown));
    assert.ok(!("misuse" in unknown && unknown.misuse.includes("\n")));
    const missing = parseFlags(["--select"], OPTIONS);
    assert.ok("misuse" in missing && /^Option '--select(?: <value>)?' argument missing/.test(missing.misuse), JSON.stringify(missing));
    const given = parseFlags(["--json=x"], OPTIONS);
    assert.ok("misuse" in given);
    // The parser's message goes on for lines, with advice that names its own flags: only the first is ours to print.
    assert.deepEqual(parseFlags(["--select", "--json"], OPTIONS), { misuse: "Option '--select' argument is ambiguous." });
});

test("an error of the parser that is not one of its complaints about the arguments is a bug and is not turned into misuse", () => {
    // A definition the parser cannot read is a mistake of the command, not of the person.
    assert.throws(() => parseFlags(["x"], /** @type {any} */ ({ bad: { type: "no-such-type" } })), (error) => error instanceof TypeError && !String(/** @type {any} */ (error).code).startsWith("ERR_PARSE_ARGS_"));
});

test("misuse says what is wrong, lists the details, then the usage and where to read more, and escapes each line on its own", () => {
    /** @type {string[]} */
    const printed = [];
    const misuse = misuseOf((text) => printed.push(text), "Usage: certdrift x", "Run certdrift x --help for the options.");
    assert.equal(misuse("it is wrong"), 2);
    assert.equal(misuse(`bad${ESC}[31m`, ["one", `two\nthree`, "four‮"]), 2);
    assert.deepEqual(printed, [
        "certdrift: it is wrong\nUsage: certdrift x\nRun certdrift x --help for the options.\n",
        "certdrift: bad\\u{1B}[31m\n  one\n  two\\u{A}three\n  four\\u{202E}\nUsage: certdrift x\nRun certdrift x --help for the options.\n",
    ]);
});

test("a path is read, and - is standard input in whatever pieces it arrives in, strings included", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "x.bin");
    writeFileSync(path, "from a file");
    const file = await readInput(path, chunks());
    assert.deepEqual([Buffer.from(/** @type {any} */ (file).bytes).toString(), /** @type {any} */ (file).described], ["from a file", path]);

    const stdin = await readInput("-", chunks("one ", Buffer.from("two "), new Uint8Array([0x74, 0x68, 0x72, 0x65, 0x65])));
    assert.deepEqual([Buffer.from(/** @type {any} */ (stdin).bytes).toString(), /** @type {any} */ (stdin).described], ["one two three", "standard input"]);
    const empty = await readInput("-", chunks());
    assert.equal(/** @type {any} */ (empty).bytes.length, 0);
});

test("a file that cannot be read is exit 3 with its name escaped, and an error that carries no code is a bug and is not caught", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const missing = await readInput(join(dir, `${ESC}missing`), chunks());
    assert.ok("code" in missing && missing.code === 3 && missing.message.startsWith(`certdrift: cannot read ${join(dir, "\\u{1B}missing")}: ENOENT`) && missing.message.endsWith("\n"), JSON.stringify(missing));
    const directory = await readInput(dir, chunks());
    assert.ok("code" in directory && directory.message.includes("EISDIR"));

    const coded = await readInput("-", (async function* () { throw Object.assign(new Error("reset"), { code: "ECONNRESET" }); })());
    assert.ok("code" in coded && coded.code === 3);
    await assert.rejects(readInput("-", (async function* () { throw new Error("a bug"); })()), /a bug/);
    await assert.rejects(readInput("-", (async function* () { throw "a string"; })()), (thrown) => thrown === "a string");
});

test("material that is not a certificate is exit 3, an ambiguous bundle is exit 2 with the candidates and the way to choose, and anything else is not caught", () => {
    const ok = observe(fixture("leaf-p256.pem"), { source: { kind: "file", ref: "x" } }, "x");
    assert.ok("observation" in ok);
    assert.deepEqual(ok.observation.observation.source, { kind: "file", ref: "x" });

    const bad = observe(Buffer.from("hello"), {}, `we${ESC}ird`);
    assert.ok("code" in bad && bad.code === 3 && bad.message.startsWith("certdrift: we\\u{1B}ird: the material holds no certificate") && bad.message.endsWith("\n"), JSON.stringify(bad));

    const two = observe(fixture("bundle-two-leaves.pem"), {}, "bundle");
    assert.ok("code" in two && two.code === 2);
    assert.match(two.message, /^certdrift: bundle: .*input block 1: .*\ninput block 2: .*\nUse --select with the start of one sha256 to choose\.\n$/s);
    const sha256 = inspect(fixture("leaf-rsa.pem")).certificates[0].sha256;
    assert.ok("observation" in observe(fixture("bundle-two-leaves.pem"), { select: sha256.slice(0, 8) }, "bundle"));

    // The line that ends the candidates is the command's to word, for a material that --select does not reach.
    const choose = observe(fixture("bundle-two-leaves.pem"), {}, "bundle", "A line of the command.");
    assert.ok("code" in choose && choose.code === 2);
    assert.match(choose.message, /candidates:\n.*\nA line of the command\.\n$/s);
    assert.doesNotMatch(choose.message, /--select/);

    // What the material holds is shown escaped, in both messages.
    const label = observe(Buffer.from("-----BEGIN CERTIFICATE\u202e-----\nQUJD\n-----END CERTIFICATE\u202e-----\n"), {}, `in${ESC}put`);
    assert.ok("code" in label && label.code === 3);
    assert.equal(/[\u202e\u001b]/.test(label.message), false, label.message);
    assert.ok(label.message.includes("in\\u{1B}put: input block 1 has a malformed boundary line") && label.message.includes("CERTIFICATE\\u{202E}-----"), label.message);
    const named = observe(fixture("bundle-two-leaves.pem"), {}, `bun${ESC}dle`);
    assert.ok("code" in named && named.message.startsWith("certdrift: bun\\u{1B}dle: "), JSON.stringify(named));

    // A wrong call is a bug of the command, which must show as one.
    assert.throws(() => observe(/** @type {any} */ (42), {}, "x"), TypeError);
});

test("the warnings of an observation are a heading and a line each, with the certificate they are about, painted and escaped, and nothing when there are none", () => {
    assert.deepEqual(warningLines([], painter(true)), []);
    const warnings = [{ code: "A_CODE", certificate: null, message: "about the material" }, { code: `B${ESC}`, certificate: 2, message: "about one‮" }];
    assert.deepEqual(warningLines(warnings, painter(false)), ["Warnings", "  A_CODE about the material", "  B\\u{1B} [2] about one\\u{202E}"]);
    assert.deepEqual(warningLines(warnings.slice(0, 1), painter(true)), [`${ESC}[1mWarnings${ESC}[22m`, `  ${ESC}[33mA_CODE${ESC}[39m about the material`]);
});
