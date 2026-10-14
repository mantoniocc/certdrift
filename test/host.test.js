import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import tls from "node:tls";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import { INSPECT_OPTIONS } from "../bin/cli.js";
import { HOST_OPTIONS, fetchHost, hostRequestOf, refusalOf } from "../bin/host.js";
import { safe } from "../bin/safe.js";
import { closedPort, serveChain, serveSilent } from "./helpers/tls.js";

// What every command that takes a host shares: the flags that name it, the rules about them, the
// check of the arguments before connecting, and what a failure says. The command's own output is
// tested through the real executable in cli.test.js; this file tests the pieces on their own and
// shows that nothing of them is written anywhere else.

const root = new URL("../", import.meta.url);

/** @param {string} path Repository-relative. */
const read = (path) => readFileSync(new URL(path, root), "utf8");

/** Every file of bin/, by repository-relative path. */
const binFiles = readdirSync(new URL("bin/", root)).filter((name) => name.endsWith(".js")).map((name) => `bin/${name}`);

/**
 * What `main()` is made of: the text from its declaration to the closing brace at the start of a line.
 * @param {string} text
 */
function bodyOfMain(text) {
    const start = text.indexOf("export async function main(");
    assert.notEqual(start, -1, "main() is in bin/cli.js");
    const end = text.indexOf("\n}\n", start);
    assert.notEqual(end, -1);
    return text.slice(start, end);
}

/**
 * The module specifiers of the import statements of a file, which are the lines that start with `import`.
 * @param {string} text
 */
const importedBy = (text) => [...text.matchAll(/^import [^\n]* from "([^"]+)";$/gm)].map((match) => match[1]);

/**
 * The host flags as `parseArgs` reads them from a command line.
 * @param {string[]} args
 * @param {Record<string, unknown>} [options]
 */
function valuesOf(args, options = HOST_OPTIONS) {
    return parseArgs({ args, options: /** @type {any} */ ({ ...options, json: { type: "boolean" } }), allowPositionals: true }).values;
}

/** @param {ReturnType<typeof hostRequestOf>} result */
const misuseOf = (result) => ("misuse" in result ? result.misuse : undefined);

test("reading the host flags, the rules about them, the fetch and the message and exit code of a host failure are in bin/host.js, and main() writes none of them", async () => {
    const cli = read("bin/cli.js");
    const main = bodyOfMain(cli);
    const hostLogic = [
        "fetchChain", "AbortSignal", "hostFailure", "ConnectionError", "HandshakeError", "TimeoutError",
        "values.host", "values.servername", "values.timeout", "[1-9]", "timeoutMs", "Number(",
    ];
    for (const text of hostLogic) assert.equal(main.includes(text), false, `main() writes ${text}`);
    assert.equal(importedBy(cli).includes("../src/tls/index.js"), false, "the command no longer reaches the TLS module itself");
    assert.ok(importedBy(cli).includes("./host.js"));

    const host = read("bin/host.js");
    for (const text of ["fetchChain(", "AbortSignal.abort(", "hostFailure(", "HOST_OPTIONS", "[1-9][0-9]*", "timeoutMs: Number("]) {
        assert.ok(host.includes(text), `bin/host.js has ${text}`);
    }

    // The failure is the whole line and the exit code, from the module, for a host that refuses.
    const closed = `127.0.0.1:${await closedPort()}`;
    const outcome = await fetchHost({ target: closed, options: {} });
    assert.ok("code" in outcome);
    assert.equal(outcome.code, 3);
    assert.match(outcome.message, new RegExp(`^certdrift: ${closed.replace(".", "\\.")}: connection refused: .*\\n$`));
});

test("each rule about --host, --servername and --timeout is written once, in bin/host.js", () => {
    /** @type {[string, string][]} */
    const rules = [
        ["a server name needs a host", "is sent to a host, so it needs"],
        ["a timeout needs a host", "is the wait for a host, so it needs"],
        ["a host takes no path and no -", "it reads what a server sends"],
        ["a timeout is digits with no leading zero", "needs a positive whole number of milliseconds"],
        ["the digits pattern", "^[1-9][0-9]*$"],
    ];
    for (const [rule, text] of rules) {
        const places = binFiles.flatMap((path) => read(path).split("\n").flatMap((line, index) => (line.includes(text) ? [`${path}:${index + 1}`] : [])));
        assert.equal(places.length, 1, `${rule}: ${places.join(", ")}`);
        assert.ok(places[0].startsWith("bin/host.js:"), `${rule}: ${places[0]}`);
    }

    // The rule that a flag is given once: one line for the three host flags, and none of them in the
    // command, which keeps the same rule for --select and --query.
    const repeated = binFiles.flatMap((path) => read(path).split("\n").flatMap((line, index) => (line.includes("was given more than once") ? [{ path, line, index }] : [])));
    assert.deepEqual(repeated.filter(({ path }) => path === "bin/host.js").length, 1);
    for (const { path, line } of repeated.filter(({ path }) => path !== "bin/host.js")) {
        assert.equal(/host|servername|timeout/.test(line), false, `${path}: ${line}`);
    }
});

test("each rule gives its own message, and the first rule broken is the one reported", () => {
    /** @type {[string, string[], boolean, string | undefined][]} */
    const table = [
        ["a repeated --host", ["--host", "a", "--host", "b"], false, "--host was given more than once"],
        ["a repeated --servername", ["--host", "a", "--servername", "x", "--servername", "x"], false, "--servername was given more than once"],
        ["a repeated --timeout", ["--host", "a", "--timeout", "1", "--timeout", "1"], false, "--timeout was given more than once"],
        ["a repeat before a path", ["--host", "a", "--host", "b"], true, "--host was given more than once"],
        ["a repeated --timeout without a host", ["--timeout", "1", "--timeout", "1"], false, "--timeout was given more than once"],
        ["a path with the host", ["--host", "a"], true, '--host takes no path and no "-": it reads what a server sends, not a file or standard input'],
        ["a path before a bad timeout", ["--host", "a", "--timeout", "0"], true, '--host takes no path and no "-": it reads what a server sends, not a file or standard input'],
        ["a timeout that is not digits", ["--host", "a", "--timeout", "1e3"], false, '--timeout needs a positive whole number of milliseconds, and got "1e3"'],
        ["a server name without a host", ["--servername", "a"], false, "--servername is sent to a host, so it needs --host"],
        ["a timeout without a host", ["--timeout", "1"], false, "--timeout is the wait for a host, so it needs --host"],
        ["a server name and a timeout without a host", ["--timeout", "1", "--servername", "a"], false, "--servername is sent to a host, so it needs --host"],
        ["nothing about a host", [], false, undefined],
        ["nothing about a host, and a path", [], true, undefined],
        ["a host only", ["--host", "a"], false, undefined],
    ];
    for (const [name, args, pathGiven, message] of table) {
        assert.equal(misuseOf(hostRequestOf(valuesOf(args), { pathGiven })), message, name);
    }
});

test("--timeout accepts only digits with no leading zero, and the module keeps the upper bound", () => {
    for (const value of ["1", "10000", "2147483647", "2147483648", "9".repeat(400)]) {
        const result = hostRequestOf(valuesOf(["--host", "a", "--timeout", value]), { pathGiven: false });
        assert.equal(misuseOf(result), undefined, value);
    }
    for (const value of ["0", "01", "-1", "+1", "1.5", "1e3", "0x10", " 5", "5 ", "", "٣", "1_000"]) {
        const result = hostRequestOf(valuesOf(["--host", "a", `--timeout=${value}`]), { pathGiven: false });
        assert.equal(misuseOf(result), `--timeout needs a positive whole number of milliseconds, and got ${JSON.stringify(value)}`, JSON.stringify(value));
    }
});

test("a request holds the host as typed and only the options that were given", () => {
    /** @type {[string[], unknown][]} */
    const table = [
        [["--host", "Api.Example.com:8443"], { target: "Api.Example.com:8443", options: {} }],
        [["--host", "a", "--servername", "n.example"], { target: "a", options: { servername: "n.example" } }],
        [["--host", "a", "--timeout", "250"], { target: "a", options: { timeoutMs: 250 } }],
        [["--host", "a", "--timeout", "250", "--servername", "n.example"], { target: "a", options: { servername: "n.example", timeoutMs: 250 } }],
        // An empty server name is a value, and it is the module that refuses it.
        [["--host", "a", "--servername="], { target: "a", options: { servername: "" } }],
    ];
    for (const [args, request] of table) {
        const result = hostRequestOf(valuesOf(args), { pathGiven: false });
        assert.deepEqual(result, { request }, args.join(" "));
        assert.deepEqual(Object.keys(/** @type {{ request: { options: object } }} */ (result).request.options), Object.keys(/** @type {{ options: object }} */ (request).options), args.join(" "));
    }
    assert.deepEqual(hostRequestOf(valuesOf([]), { pathGiven: true }), { request: undefined });
});

test("the module's refusal of an argument is given in its own words without opening a socket, and a good request is not refused", async (t) => {
    const server = await serveSilent(t);
    const target = `127.0.0.1:${server.port}`;
    /** @type {[string, Parameters<typeof refusalOf>[0], RegExp][]} */
    const refused = [
        ["a target that cannot be read", { target: "a b", options: {} }, /^target "a b" cannot be read: /],
        ["a server name that is an address", { target, options: { servername: "192.0.2.1" } }, /^options\.servername must be a host name in ASCII, not an IP address$/],
        ["a timeout above the bound", { target, options: { timeoutMs: 2 ** 31 } }, /^options\.timeoutMs must be a whole number of milliseconds from 1 to 2147483647$/],
        ["a timeout of Infinity, which 400 digits become", { target, options: { timeoutMs: Number("9".repeat(400)) } }, /^options\.timeoutMs must be /],
        ["the target first when several are refused", { target: "a b", options: { servername: "192.0.2.1", timeoutMs: 0 } }, /^target "a b" cannot be read/],
    ];
    for (const [name, request, message] of refused) {
        assert.match(String(await refusalOf(request)), message, name);
    }
    for (const request of [{ target, options: {} }, { target, options: { servername: "n.example", timeoutMs: 5000 } }]) {
        assert.equal(await refusalOf(request), undefined);
    }
    await sleep(50);
    assert.equal(server.accepted(), 0, "none of these connected");
});

test("an argument the module refuses is asked first with a signal that is already aborted, and a bug in the connection code is neither refused nor caught", async (t) => {
    for (const Class of [TypeError, RangeError, Error]) {
        const thrown = new Class("a bug inside the connection code");
        const connect = t.mock.method(tls, "connect", () => { throw thrown; });

        // Asking tells the arguments were fine, and never reaches the connection code.
        assert.equal(await refusalOf({ target: "127.0.0.1:1", options: {} }), undefined, Class.name);
        assert.equal(connect.mock.callCount(), 0, `${Class.name}: asking does not connect`);

        // The real call does reach it, and the error comes out as it is, not as misuse or a host failure.
        await assert.rejects(fetchHost({ target: "127.0.0.1:1", options: {} }), (error) => error === thrown, Class.name);
        assert.equal(connect.mock.callCount(), 1, Class.name);
        connect.mock.restore();
    }
});

test("an error of the refusal check that is neither the module's TypeError nor the one the aborted signal gives is rethrown as it is, not reported as a refusal", async () => {
    // A bug in the module's checks must end the command with the error, not read as misuse.
    const boom = new RangeError("a bug inside the module's checks");
    const request = {
        target: "127.0.0.1:1",
        options: {
            /** @returns {number} */
            get timeoutMs() { throw boom; },
        },
    };
    await assert.rejects(refusalOf(request), (error) => error === boom);
});

test("fetching gives what the server sent, and for a host that fails the line and the exit code", async (t) => {
    const server = await serveChain(t);
    const target = `127.0.0.1:${server.port}`;
    const fetched = await fetchHost({ target, options: { servername: "named.example", timeoutMs: 5000 } });
    assert.ok("chain" in fetched);
    assert.deepEqual(fetched.chain.source, { kind: "host", ref: target, servername: "named.example" });
    assert.ok(fetched.chain.bytes instanceof Uint8Array);
    assert.deepEqual(server.names, ["named.example"]);

    // Two requests at once keep their own outcomes: one succeeds, one fails, and neither borrows the other's.
    const closed = `127.0.0.1:${await closedPort()}`;
    const [good, bad] = await Promise.all([fetchHost({ target, options: {} }), fetchHost({ target: closed, options: {} })]);
    assert.ok("chain" in good && good.chain.source.ref === target);
    assert.ok("code" in bad && bad.code === 3 && bad.message.startsWith(`certdrift: ${closed}: `));

    const silent = await serveSilent(t);
    const slow = await fetchHost({ target: `127.0.0.1:${silent.port}`, options: { timeoutMs: 200 } });
    assert.ok("code" in slow);
    assert.match(slow.message, /^certdrift: 127\.0\.0\.1:\d+: did not answer in time: no answer from .* within 200 ms/);
});

test("the three option definitions are written once and the options of inspect are composed from them", () => {
    assert.deepEqual(Object.keys(HOST_OPTIONS), ["host", "servername", "timeout"]);
    for (const name of /** @type {const} */ (["host", "servername", "timeout"])) {
        assert.equal(INSPECT_OPTIONS[name], HOST_OPTIONS[name], `inspect takes ${name} from HOST_OPTIONS`);
        assert.deepEqual(HOST_OPTIONS[name], { type: "string", multiple: true }, name);
    }
    // No other file defines them: a definition is an object with the type and `multiple`.
    for (const path of binFiles.filter((path) => path !== "bin/host.js")) {
        assert.equal(/\b(?:host|servername|timeout)\s*:\s*\{\s*type:/.test(read(path)), false, path);
    }
});

test("a command that takes the host flags under other names gets the same rules in its own words, and reads only those flags", () => {
    const names = { host: "peer", servername: "peer-name", timeout: "peer-wait" };
    const options = { peer: HOST_OPTIONS.host, "peer-name": HOST_OPTIONS.servername, "peer-wait": HOST_OPTIONS.timeout };
    /** @type {[string[], boolean, string | undefined][]} */
    const table = [
        [["--peer", "a", "--peer", "b"], false, "--peer was given more than once"],
        [["--peer", "a", "--peer-name", "x", "--peer-name", "x"], false, "--peer-name was given more than once"],
        [["--peer", "a", "--peer-wait", "1", "--peer-wait", "1"], false, "--peer-wait was given more than once"],
        [["--peer", "a"], true, '--peer takes no path and no "-": it reads what a server sends, not a file or standard input'],
        [["--peer", "a", "--peer-wait", "0"], false, '--peer-wait needs a positive whole number of milliseconds, and got "0"'],
        [["--peer-name", "x"], false, "--peer-name is sent to a host, so it needs --peer"],
        [["--peer-wait", "1"], false, "--peer-wait is the wait for a host, so it needs --peer"],
    ];
    for (const [args, pathGiven, message] of table) {
        assert.equal(misuseOf(hostRequestOf(valuesOf(args, options), { pathGiven, names })), message, args.join(" "));
    }

    // The plain names are not read when the command calls them something else.
    const plain = valuesOf(["--peer", "a"], { ...options, ...HOST_OPTIONS, peer: options.peer });
    assert.deepEqual(hostRequestOf(plain, { pathGiven: false, names }), { request: { target: "a", options: {} } });
    const ignored = hostRequestOf(valuesOf(["--host", "b"], { ...options, ...HOST_OPTIONS }), { pathGiven: false, names });
    assert.deepEqual(ignored, { request: undefined }, "--host is not --peer");

    // A request from one command line is the one the same flags give under the plain names.
    const sided = hostRequestOf(valuesOf(["--peer", "h:1", "--peer-name", "n.example", "--peer-wait", "7"], options), { pathGiven: false, names });
    assert.deepEqual(sided, hostRequestOf(valuesOf(["--host", "h:1", "--servername", "n.example", "--timeout", "7"]), { pathGiven: false }));
});

test("bin/host.js imports only the TLS entry point that package.json exports, and neither node:crypto nor node:tls", () => {
    const host = read("bin/host.js");
    const { exports } = JSON.parse(read("package.json"));
    assert.equal(exports["./tls"].default, "./src/tls/index.js");
    assert.deepEqual(importedBy(host), ["../src/tls/index.js", "./safe.js"]);
    assert.equal(/node:(?:crypto|tls)\b/.test(host), false);
    // A type may come from the TLS entry point too, and from nowhere else.
    const types = [...host.matchAll(/^\/\*\* @import [^\n]* from "([^"]+)" \*\/$/gm)].map((match) => match[1]);
    assert.deepEqual(types, ["../src/tls/index.js"]);
});

test("the modules a command shares print nothing, read no environment and end nothing: the command decides", () => {
    for (const path of ["bin/host.js", "bin/safe.js"]) {
        const text = read(path);
        assert.equal(/\bprocess\b|\bconsole\b|\bstdout\b|\bstderr\b|\bstdin\b/.test(text), false, path);
        assert.equal(importedBy(text).includes("./cli.js"), false, `${path} does not depend on the command that uses it`);
    }
});

test("safe is defined once in bin/, in bin/safe.js, and bin/cli.js and bin/host.js both import it from there", () => {
    const definitions = binFiles.filter((path) => /\bfunction safe\b|\b(?:const|let|var) safe\b/.test(read(path)));
    assert.deepEqual(definitions, ["bin/safe.js"]);
    for (const path of ["bin/cli.js", "bin/host.js"]) {
        assert.match(read(path), /^import \{[^}]*\bsafe\b[^}]*\} from "\.\/safe\.js";$/m, path);
    }
    // No other file of bin/ writes the escaping of its own: the pattern that does it is in one place.
    const patterns = binFiles.filter((path) => read(path).includes("\\p{Cc}"));
    assert.deepEqual(patterns, ["bin/safe.js"]);
});

test("safe shows control, format and separator characters as text, and leaves everything else as it is", () => {
    assert.equal(safe("plain text, ünïcödé and 日本語"), "plain text, ünïcödé and 日本語");
    assert.equal(safe("a\u001b]0;x\u0007b"), "a\\u{1B}]0;x\\u{7}b");
    assert.equal(safe("‮abc\u0085  \ud800"), "\\u{202E}abc\\u{85}\\u{2028}\\u{2029}\\u{D800}");
    assert.equal(safe("tab\there"), "tab\\u{9}here");
});
