import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KEY_OPTIONS, keyRequestOf, readKey } from "../bin/private-key.js";
import { PASSPHRASE, bytes } from "./helpers/keys.js";

// The two options that name a private key and the reading of its file, without a process: what
// each rule says, in the order they are applied. The command around them is in check-key.test.js.

test("the key options are lists, so that a repeated one can be refused where parseArgs would keep the last", () => {
    assert.deepEqual(KEY_OPTIONS, { key: { type: "string", multiple: true }, "key-passphrase-env": { type: "string", multiple: true } });
});

test("no key option asks for no key", () => {
    assert.deepEqual(keyRequestOf({}, {}), { request: undefined });
    assert.deepEqual(keyRequestOf({ other: ["x"] }, { x: "y" }), { request: undefined });
});

test("a key with no variable has no passphrase, which is not an empty one", () => {
    assert.deepEqual(keyRequestOf({ key: ["k.pem"] }, {}), { request: { path: "k.pem", passphrase: undefined } });
});

test("the passphrase is what the variable holds, with nothing trimmed, and an empty variable is an empty passphrase", () => {
    for (const held of [PASSPHRASE, "", " ", ` ${PASSPHRASE}`, `${PASSPHRASE}\n`, `${PASSPHRASE} `, "a\0b", "ñ", "�"]) {
        assert.deepEqual(keyRequestOf({ key: ["k.pem"], "key-passphrase-env": ["PASS"] }, { PASS: held }), { request: { path: "k.pem", passphrase: held } }, JSON.stringify(held));
    }
});

test("a variable the environment does not have as its own is not defined, whatever the environment answers for the name", () => {
    const env = { PATH: "/bin", UNSET: undefined };
    for (const name of ["", "NOPE", "path", "UNSET", "constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
        const asked = keyRequestOf({ key: ["k.pem"], "key-passphrase-env": [name] }, env);
        assert.deepEqual(asked, { misuse: "--key-passphrase-env names an environment variable that is not defined" }, JSON.stringify(name));
    }
    // process.env answers for these names with a function, which a lookup would take for a passphrase.
    for (const name of ["constructor", "toString", "__proto__"]) {
        assert.notEqual(typeof process.env[name], "string", name);
        assert.ok("misuse" in keyRequestOf({ key: ["k.pem"], "key-passphrase-env": [name] }, process.env), name);
    }
    assert.deepEqual(keyRequestOf({ key: ["k.pem"], "key-passphrase-env": ["PATH"] }, { PATH: "x" }), { request: { path: "k.pem", passphrase: "x" } });
});

test("a message never repeats the name of the variable, which may be the passphrase typed by mistake", () => {
    const asked = keyRequestOf({ key: ["k.pem"], "key-passphrase-env": [PASSPHRASE] }, {});
    assert.ok("misuse" in asked);
    assert.ok(!asked.misuse.includes(PASSPHRASE));
});

test("--key - is misuse, and is refused before the variable is looked at", () => {
    const refused = { misuse: "--key - would read the key from standard input, which is not supported: give a file" };
    assert.deepEqual(keyRequestOf({ key: ["-"] }, {}), refused);
    assert.deepEqual(keyRequestOf({ key: ["-"], "key-passphrase-env": ["NOPE"] }, {}), refused);
    assert.deepEqual(keyRequestOf({ key: ["-"], "key-passphrase-env": ["PASS"] }, { PASS: "x" }), refused);
    // Only the one name is standard input: it is a file anywhere else.
    for (const path of ["--", "-k", "./-", "- ", ""]) assert.ok("request" in keyRequestOf({ key: [path] }, {}), JSON.stringify(path));
});

test("--key-passphrase-env without --key is misuse, whatever the variable holds, and is refused before the variable is looked at", () => {
    const refused = { misuse: "--key-passphrase-env needs --key" };
    assert.deepEqual(keyRequestOf({ "key-passphrase-env": ["PASS"] }, { PASS: "x" }), refused);
    assert.deepEqual(keyRequestOf({ "key-passphrase-env": ["NOPE"] }, {}), refused);
    assert.deepEqual(keyRequestOf({ "key-passphrase-env": [""] }, {}), refused);
});

test("a key file is read as a file: its bytes, an error that names the path, and - is a file called -", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "certdrift-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const key = join(dir, "k.key");
    writeFileSync(key, bytes("leaf-p256.key"));
    const read = await readKey(key);
    assert.ok("material" in read);
    assert.deepEqual(Buffer.from(read.material), bytes("leaf-p256.key"));

    mkdirSync(join(dir, "folder"));
    for (const path of [join(dir, "missing.key"), join(dir, "folder"), "", join(dir, "k.key", "x")]) {
        const failed = await readKey(path);
        assert.ok("code" in failed, path);
        assert.equal(failed.code, 3);
        assert.match(failed.message, /^certdrift: cannot read .*: E[A-Z]+/, path);
    }
    // `-` here is a file, so a command that does not want standard input for a key reads it with this.
    const dash = await readKey("-");
    assert.ok("code" in dash);
    assert.match(dash.message, /^certdrift: cannot read -: ENOENT/);
});
