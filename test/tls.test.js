import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { getEventListeners } from "node:events";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { TLSSocket } from "node:tls";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import * as core from "../src/index.js";
import { inspect } from "../src/index.js";
import { ConnectionError, HandshakeError, TimeoutError, fetchChain } from "../src/tls/index.js";
import { validatorFor } from "./helpers/schema.js";
import { MODULE_URL, closedPort, fixture, runChild, serveChain, serveSilent, serveWith } from "./helpers/tls.js";

// Every test connects to a server it starts on the loopback interface. None depends on how long a
// fixture certificate is valid: the chains are compared by what they are made of, and the one
// that expires within days is only served, never judged.

const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string | Uint8Array} certificate */
const fingerprint = (certificate) => new X509Certificate(certificate).fingerprint256;

/** The fingerprints of the fixture files, in the order given. @param {string[]} names */
const fingerprintsOfFixtures = (names) => names.map((name) => fingerprint(fixture(name)));

/**
 * The fingerprints of the certificates in some PEM bytes, in order.
 * @param {Uint8Array} bytes
 */
function fingerprintsOf(bytes) {
    const blocks = Buffer.from(bytes).toString("utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
    return blocks.map(fingerprint);
}

/**
 * What a promise rejects with. A promise that resolves fails the test.
 * @param {Promise<unknown>} promise
 */
async function rejection(promise) {
    try {
        await promise;
    } catch (error) {
        return error;
    }
    return assert.fail("expected the promise to reject");
}

// ---------------------------------------------------------------------------------------------
// The entry point

test("certdrift/tls resolves to src/tls/index.js, which exports fetchChain, and src/tls/.gitkeep is gone", async () => {
    const entry = new URL("../src/tls/index.js", import.meta.url);
    assert.equal(import.meta.resolve("certdrift/tls"), entry.href);
    assert.equal(typeof fetchChain, "function");
    assert.equal(existsSync(new URL("../src/tls/.gitkeep", import.meta.url)), false);
    assert.ok(readdirSync(new URL("../src/tls/", import.meta.url)).includes("index.js"));
});

// ---------------------------------------------------------------------------------------------
// The target

test("a target that cannot be read rejects with TypeError and opens no connection", async (t) => {
    const server = await serveSilent(t);
    for (const target of ["", "2001:db8::1", `127.1:${server.port}`, `localhost:${server.port}:1`, "localhost:0", "[::1]x", 443, undefined, null]) {
        // @ts-expect-error: the point is that a wrong argument is refused at run time too
        await assert.rejects(fetchChain(target), TypeError, JSON.stringify(target));
    }
    // A target that would have connected, with an option that cannot be used.
    await assert.rejects(fetchChain(`127.0.0.1:${server.port}`, { timeoutMs: 0 }), TypeError);
    await sleep(50);
    assert.equal(server.accepted(), 0);
});

// ---------------------------------------------------------------------------------------------
// The result

test("it resolves to a Uint8Array with one PEM block per certificate in the order sent, and a host source that inspect() takes as it is", async (t) => {
    const sent = ["leaf-p256.pem", "intermediate.pem", "root-ca.pem"];
    const server = await serveChain(t, { certs: sent });
    const result = await fetchChain(`127.0.0.1:${server.port}`);

    assert.deepEqual(Object.keys(result).sort(), ["bytes", "source"]);
    assert.ok(result.bytes instanceof Uint8Array);
    assert.equal(Buffer.isBuffer(result.bytes), false, "a plain Uint8Array, not a Buffer");
    assert.deepEqual(fingerprintsOf(result.bytes), fingerprintsOfFixtures(sent));
    // Nothing but the blocks: no text between them, so the bytes are what `inspect()` reads as PEM.
    const leftover = Buffer.from(result.bytes).toString("utf8").replaceAll(/-----BEGIN CERTIFICATE-----\n[\s\S]+?\n-----END CERTIFICATE-----\n/g, "");
    assert.equal(leftover, "");
    assert.deepEqual(result.source, { kind: "host", ref: `127.0.0.1:${server.port}`, servername: null });

    const observation = inspect(result.bytes, { source: result.source, at: AT });
    assert.deepEqual(errorsOf(observation), []);
    assert.deepEqual(observation.observation.source, result.source);
    assert.equal(observation.target, 0);
    assert.deepEqual(observation.certificates.map((certificate) => certificate.sha256), fingerprintsOfFixtures(sent).map((value) => value.replaceAll(":", "").toLowerCase()));
});

test("ref gives two spellings of the same server the same label, and the host name is what the server sees", async (t) => {
    const server = await serveChain(t);
    const lower = await fetchChain(`localhost:${server.port}`);
    const mixed = await fetchChain(`LocalHost:${server.port}`);
    assert.equal(lower.source.ref, `localhost:${server.port}`);
    assert.deepEqual(mixed.source, lower.source);
    assert.deepEqual(server.names, ["localhost", "localhost"]);
});

// ---------------------------------------------------------------------------------------------
// The server name

test("the server name sent defaults to the host name, and a host name given in capitals is sent in lowercase", async (t) => {
    const server = await serveChain(t);
    const result = await fetchChain(`LOCALHOST:${server.port}`);
    assert.equal(result.source.servername, "localhost");
    assert.deepEqual(server.names, ["localhost"]);
});

test("an IP address target sends no server name, records null, and Node.js prints no warning", async (t) => {
    const server = await serveChain(t);
    // A new process, because Node.js warns about an IP address as a server name once per process.
    const child = await runChild(`
        import { fetchChain } from ${JSON.stringify(MODULE_URL)};
        const sources = [];
        sources.push((await fetchChain("127.0.0.1:${server.port}")).source);
        sources.push((await fetchChain("127.0.0.1:${server.port}", { servername: "api.example.test" })).source);
        console.log(JSON.stringify(sources));
    `);
    assert.deepEqual([child.code, child.stderr], [0, ""], child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), [
        { kind: "host", ref: `127.0.0.1:${server.port}`, servername: null },
        { kind: "host", ref: `127.0.0.1:${server.port}`, servername: "api.example.test" },
    ]);
    // The first connection sent no name at all, and the second sent the one it was given.
    assert.deepEqual(server.names, ["api.example.test"]);
});

test("a servername given by the caller is sent and recorded as typed, for a host name and for an IP address target", async (t) => {
    const server = await serveChain(t);
    const byName = await fetchChain(`localhost:${server.port}`, { servername: "Api.Example.COM" });
    const byAddress = await fetchChain(`127.0.0.1:${server.port}`, { servername: "api.example.test" });
    assert.equal(byName.source.servername, "Api.Example.COM");
    assert.equal(byAddress.source.servername, "api.example.test");
    assert.deepEqual(server.names, ["Api.Example.COM", "api.example.test"]);
});

test("a servername that is empty, an IP address, not ASCII or not a string rejects with TypeError", async () => {
    const port = await closedPort();
    for (const servername of ["", " ", "192.0.2.1", "127.1", "::1", "[::1]", "bücher.example", "a b", 443, null, false]) {
        // @ts-expect-error: values of the wrong type are refused at run time
        const error = await rejection(fetchChain(`127.0.0.1:${port}`, { servername }));
        assert.ok(error instanceof TypeError, `${JSON.stringify(servername)}: ${error}`);
    }
});

// ---------------------------------------------------------------------------------------------
// What is accepted

test("expired, self-signed, wrongly named and untrusted chains are returned, and the result holds only bytes and source", async (t) => {
    /** @type {{ label: string, certs: string[], key: string, servername?: string }[]} */
    const cases = [
        { label: "an expired leaf", certs: ["leaf-expired.pem", "intermediate.pem"], key: "leaf-expired.key" },
        { label: "a leaf that expires within days", certs: ["leaf-6-days.pem", "intermediate.pem"], key: "leaf-6-days.key" },
        { label: "a self-signed leaf", certs: ["selfsigned-leaf.pem"], key: "selfsigned-leaf.key" },
        { label: "a leaf for another name", certs: ["leaf-p256.pem", "intermediate.pem"], key: "leaf-p256.key", servername: "wrong.example" },
        { label: "a leaf whose issuer was not sent", certs: ["leaf-p256.pem"], key: "leaf-p256.key" },
        { label: "a root nobody trusts", certs: ["leaf-p256.pem", "intermediate.pem", "root-ca.pem"], key: "leaf-p256.key" },
    ];
    for (const { label, certs, key, servername } of cases) {
        const server = await serveChain(t, { certs, key });
        const result = await fetchChain(`127.0.0.1:${server.port}`, { servername });
        assert.deepEqual(fingerprintsOf(result.bytes), fingerprintsOfFixtures(certs), label);
        assert.deepEqual(Object.keys(result).sort(), ["bytes", "source"], label);
        assert.deepEqual(Object.keys(result.source).sort(), ["kind", "ref", "servername"], label);
    }
});

test("every leaf fixture a server can send comes back as sent, and inspect() finds the leaf as the target", async (t) => {
    // leaf-sm2 is not here: tls.createServer itself refuses an SM2 certificate.
    const names = [
        "rsa", "rsa-pss", "p256", "p384", "p521", "ed25519", "ml-dsa-44", "brainpool", "no-cn", "multi-dn", "san-kinds",
        "san-comma", "san-quotes", "serial-zero", "serial-negative", "expired", "6-days", "zero-validity",
    ];
    for (const name of names) {
        const certs = [`leaf-${name}.pem`, "intermediate.pem"];
        const server = await serveChain(t, { certs, key: `leaf-${name}.key` });
        const result = await fetchChain(`127.0.0.1:${server.port}`);
        assert.deepEqual(fingerprintsOf(result.bytes), fingerprintsOfFixtures(certs), name);
        const observation = inspect(result.bytes, { source: result.source, at: AT });
        assert.equal(observation.certificates[observation.target].sha256, fingerprint(fixture(certs[0])).replaceAll(":", "").toLowerCase(), name);
    }
});

test("a certificate the server sends twice is returned twice, and nothing after it is dropped", async (t) => {
    const twice = ["leaf-p256.pem", "intermediate.pem", "intermediate.pem", "root-ca.pem"];
    const server = await serveChain(t, { certs: twice });
    assert.deepEqual(fingerprintsOf((await fetchChain(`127.0.0.1:${server.port}`)).bytes), fingerprintsOfFixtures(twice));

    const leafTwice = ["leaf-p256.pem", "leaf-p256.pem", "intermediate.pem"];
    const other = await serveChain(t, { certs: leafTwice });
    assert.deepEqual(fingerprintsOf((await fetchChain(`127.0.0.1:${other.port}`)).bytes), fingerprintsOfFixtures(leafTwice));
});

test("an IPv6 loopback target connects, sends no server name and keeps its brackets in ref", async (t) => {
    /** @type {Awaited<ReturnType<typeof serveChain>>} */
    let server;
    try {
        server = await serveChain(t, { host: "::1" });
    } catch (error) {
        return t.skip(`::1 cannot be bound here: ${/** @type {NodeJS.ErrnoException} */ (error).code}`);
    }
    const result = await fetchChain(`[::1]:${server.port}`);
    assert.deepEqual(result.source, { kind: "host", ref: `[::1]:${server.port}`, servername: null });
    assert.deepEqual(fingerprintsOf(result.bytes), fingerprintsOfFixtures(["leaf-p256.pem", "intermediate.pem"]));
    assert.deepEqual(server.names, []);
});

test("a brainpool chain whose root the trust store holds is fetched without killing the process", async (t) => {
    // Node.js crashes with a segmentation fault when a chain with a brainpool key verifies
    // against the store, so the store has to hold the root before the process starts.
    const server = await serveChain(t, { certs: ["leaf-brainpool.pem", "intermediate.pem"], key: "leaf-brainpool.key" });
    const child = await runChild(`
        import { fetchChain } from ${JSON.stringify(MODULE_URL)};
        import { X509Certificate } from "node:crypto";
import { getEventListeners } from "node:events";
        const { bytes } = await fetchChain("127.0.0.1:${server.port}");
        console.log(new X509Certificate(bytes).fingerprint256);
    `, { env: { NODE_EXTRA_CA_CERTS: fileURLToPath(new URL("fixtures/root-ca.pem", import.meta.url)) } });
    // Which other certificates come back is not asserted: what the store adds is not this module's claim.
    assert.deepEqual([child.code, child.signal], [0, null], child.stderr);
    assert.equal(child.stdout.trim(), fingerprint(fixture("leaf-brainpool.pem")));
});

test("a chain that cannot be read, or that holds no certificate, rejects with HandshakeError and closes the socket", async (t) => {
    const server = await serveChain(t);
    const peer = t.mock.method(TLSSocket.prototype, "getPeerX509Certificate", () => {
        throw new Error("no such certificate");
    });
    const unreadable = await rejection(fetchChain(`127.0.0.1:${server.port}`));
    assert.ok(unreadable instanceof HandshakeError);
    assert.match(unreadable.message, /could not be read: no such certificate/);
    assert.ok(unreadable.cause instanceof Error);
    await server.closed();

    // The same mock, not a second one over it: mocks restore in the order they were made, and the
    // second would leave the first in place for the tests that follow.
    peer.mock.mockImplementation(() => undefined);
    const empty = await rejection(fetchChain(`127.0.0.1:${server.port}`));
    assert.ok(empty instanceof HandshakeError);
    assert.match(empty.message, /without a certificate/);
    await server.closed(2);
});

// ---------------------------------------------------------------------------------------------
// Closing the socket

test("the server sees the connection closed after a success, a handshake error, a timeout and an abort", async (t) => {
    const ok = await serveChain(t);
    await fetchChain(`127.0.0.1:${ok.port}`);
    await ok.closed();

    // A server that answers in plain text and then keeps the connection open: only the client can close it.
    const plain = await serveWith(t, (socket) => socket.write("HTTP/1.1 400 Bad Request\r\n\r\n"));
    await assert.rejects(fetchChain(`127.0.0.1:${plain.port}`), HandshakeError);
    await plain.closed();

    const silent = await serveSilent(t);
    await assert.rejects(fetchChain(`127.0.0.1:${silent.port}`, { timeoutMs: 100 }), TimeoutError);
    await silent.closed();

    const controller = new AbortController();
    const aborted = rejection(fetchChain(`127.0.0.1:${silent.port}`, { signal: controller.signal }));
    await silent.connected(2);
    controller.abort();
    await aborted;
    await silent.closed(2);
});

test("after every outcome, a closed port included, the process exits by itself long before the default timeout", async (t) => {
    const ok = await serveChain(t);
    const plain = await serveWith(t, (socket) => socket.write("220 not tls\r\n"));
    const silent = await serveSilent(t);
    const refused = await closedPort();
    const child = await runChild(`
        import { fetchChain } from ${JSON.stringify(MODULE_URL)};
        const outcomes = [];
        async function attempt(label, target, options) {
            try {
                await fetchChain(target, options);
                outcomes.push(label + ":resolved");
            } catch (error) {
                outcomes.push(label + ":" + error.name);
            }
        }
        // No timeoutMs: a timer left running would keep the process alive for ten seconds.
        await attempt("success", "127.0.0.1:${ok.port}");
        await attempt("handshake", "127.0.0.1:${plain.port}");
        await attempt("refused", "127.0.0.1:${refused}");
        await attempt("timeout", "127.0.0.1:${silent.port}", { timeoutMs: 100 });
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 100);
        await attempt("abort", "127.0.0.1:${silent.port}", { signal: controller.signal });
        console.log(JSON.stringify(outcomes));
    `, { timeoutMs: 6000 });
    assert.equal(child.timedOut, false, "the process was still running after six seconds");
    assert.deepEqual([child.code, child.stderr], [0, ""]);
    assert.deepEqual(JSON.parse(child.stdout), ["success:resolved", "handshake:HandshakeError", "refused:ConnectionError", "timeout:TimeoutError", "abort:AbortError"]);
});

// ---------------------------------------------------------------------------------------------
// The timeout and the signal

test("timeoutMs ends the attempt with a TimeoutError: a server that stays silent past it, which is not the DOMException AbortSignal.timeout() gives", async (t) => {
    const server = await serveSilent(t);
    const error = await rejection(fetchChain(`127.0.0.1:${server.port}`, { timeoutMs: 100 }));
    assert.ok(error instanceof TimeoutError);
    assert.equal(error.name, "TimeoutError");
    assert.ok(error instanceof Error);
    assert.ok(!(error instanceof DOMException));
    assert.equal(error.cause, undefined, "nothing failed underneath it");
    assert.match(error.message, new RegExp(`127\\.0\\.0\\.1:${server.port} within 100 ms while handshaking`));

    // The name alone does not tell them apart, so a test or a caller has to use instanceof.
    const own = AbortSignal.timeout(1);
    await sleep(30);
    assert.equal(own.reason.name, "TimeoutError");
    assert.ok(!(own.reason instanceof TimeoutError));

    // Handed to fetchChain as the signal, that timeout is the caller's reason, and comes back as it is.
    const viaSignal = await rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: AbortSignal.timeout(100) }));
    assert.ok(viaSignal instanceof DOMException);
    assert.equal(/** @type {Error} */ (viaSignal).name, "TimeoutError");
    assert.ok(!(viaSignal instanceof TimeoutError));
});

test("without timeoutMs a silent server is given 10000 ms", async (t) => {
    const server = await serveSilent(t);
    // The global timer, which is what the attempt uses, stands still until the test moves it.
    t.mock.timers.enable({ apis: ["setTimeout"] });
    /** @type {unknown} */
    let outcome;
    const attempt = fetchChain(`127.0.0.1:${server.port}`).then(() => "resolved", (error) => error);
    attempt.then((value) => (outcome = value));
    await server.connected();

    t.mock.timers.tick(9_999);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(outcome, undefined, "it gave up before 10000 ms");
    t.mock.timers.tick(1);
    const error = await attempt;
    assert.ok(error instanceof TimeoutError);
    assert.match(error.message, /within 10000 ms/);
});

test("an AbortSignal cancels the attempt: the promise rejects with the signal's reason and the server sees the connection closed", async (t) => {
    const server = await serveSilent(t);

    const reason = new Error("stop");
    const first = new AbortController();
    const withReason = rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: first.signal }));
    await server.connected();
    first.abort(reason);
    assert.equal(await withReason, reason);
    await server.closed();

    // With no reason given, the signal's own is an AbortError, and that is what comes back.
    const second = new AbortController();
    const withDefault = rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: second.signal }));
    await server.connected(2);
    second.abort();
    const error = await withDefault;
    assert.equal(error, second.signal.reason);
    assert.equal(/** @type {Error} */ (error).name, "AbortError");
    await server.closed(2);

    // Before the connection is made, as soon as the call returns.
    const third = new AbortController();
    const early = rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: third.signal }));
    third.abort(reason);
    assert.equal(await early, reason);
});

test("an already aborted signal rejects with its reason before connecting", async (t) => {
    const server = await serveSilent(t);
    const reason = new Error("never started");
    assert.equal(await rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: AbortSignal.abort(reason) })), reason);
    const error = await rejection(fetchChain(`127.0.0.1:${server.port}`, { signal: AbortSignal.abort() }));
    assert.equal(/** @type {Error} */ (error).name, "AbortError");
    await sleep(100);
    assert.equal(server.accepted(), 0);
});

test("a signal used for many calls keeps no listener once each has ended, and aborting it afterwards changes nothing", async (t) => {
    const ok = await serveChain(t);
    const refused = await closedPort();
    const controller = new AbortController();
    const unhandled = /** @type {unknown[]} */ ([]);
    const note = (/** @type {unknown} */ reason) => unhandled.push(reason);
    process.on("unhandledRejection", note);
    t.after(() => process.off("unhandledRejection", note));

    // More than the ten listeners Node.js warns about, on one signal.
    for (let call = 0; call < 12; call += 1) {
        await fetchChain(`127.0.0.1:${ok.port}`, { signal: controller.signal });
        await assert.rejects(fetchChain(`127.0.0.1:${refused}`, { signal: controller.signal }), ConnectionError);
    }
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);

    controller.abort();
    await sleep(50);
    assert.deepEqual(unhandled, []);
});

test("calls made at the same time each open their own connection and get their own result", async (t) => {
    const sent = [["leaf-p256.pem", "intermediate.pem"], ["leaf-rsa.pem"], ["selfsigned-leaf.pem"]];
    const keys = ["leaf-p256.key", "leaf-rsa.key", "selfsigned-leaf.key"];
    const servers = await Promise.all(sent.map((certs, index) => serveChain(t, { certs, key: keys[index] })));
    const results = await Promise.all(servers.flatMap((server) => [1, 2].map(() => fetchChain(`127.0.0.1:${server.port}`))));
    assert.deepEqual(
        results.map((result) => [result.source.ref, fingerprintsOf(result.bytes)]),
        servers.flatMap((server, index) => [1, 2].map(() => [`127.0.0.1:${server.port}`, fingerprintsOfFixtures(sent[index])])),
    );
});

test("a timeoutMs that is not a whole number from 1 to 2147483647, or a signal that is not an AbortSignal, rejects with TypeError", async () => {
    const port = await closedPort();
    for (const timeoutMs of [0, -1, 1.5, NaN, Infinity, 2 ** 31, "100", null, 10n]) {
        // @ts-expect-error: values of the wrong type are refused at run time
        const error = await rejection(fetchChain(`127.0.0.1:${port}`, { timeoutMs }));
        assert.ok(error instanceof TypeError, `${String(timeoutMs)}: ${error}`);
    }
    for (const signal of [null, {}, "abort", { aborted: false, addEventListener() {} }, 1]) {
        // @ts-expect-error: values of the wrong type are refused at run time
        const error = await rejection(fetchChain(`127.0.0.1:${port}`, { signal }));
        assert.ok(error instanceof TypeError, `${JSON.stringify(signal)}: ${error}`);
    }
    for (const options of [null, 5, "options", true]) {
        // @ts-expect-error: values of the wrong type are refused at run time
        const error = await rejection(fetchChain(`127.0.0.1:${port}`, options));
        assert.ok(error instanceof TypeError, `${JSON.stringify(options)}: ${error}`);
    }
    // The largest delay a timer takes is accepted.
    const error = await rejection(fetchChain(`127.0.0.1:${port}`, { timeoutMs: 2 ** 31 - 1 }));
    assert.ok(error instanceof ConnectionError, String(error));
});

// ---------------------------------------------------------------------------------------------
// The errors

test("a closed port rejects with ConnectionError", async () => {
    const port = await closedPort();
    const error = await rejection(fetchChain(`127.0.0.1:${port}`));
    assert.ok(error instanceof ConnectionError);
    assert.equal(error.name, "ConnectionError");
    assert.equal(/** @type {NodeJS.ErrnoException} */ (error.cause).code, "ECONNREFUSED");
    assert.match(error.message, new RegExp(`could not connect to 127\\.0\\.0\\.1:${port}`));
    assert.ok(!(error instanceof HandshakeError) && !(error instanceof TimeoutError));
});

test("a server that accepts the connection and answers with plain text rejects with HandshakeError", async (t) => {
    const server = await serveWith(t, (socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
    const error = await rejection(fetchChain(`127.0.0.1:${server.port}`));
    assert.ok(error instanceof HandshakeError);
    assert.equal(error.name, "HandshakeError");
    assert.ok(error.cause instanceof Error);
    assert.match(error.message, new RegExp(`handshake with 127\\.0\\.0\\.1:${server.port} failed`));
    assert.doesNotMatch(error.message, /\n/, "OpenSSL's several lines are cut to one");
    assert.ok(!(error instanceof ConnectionError) && !(error instanceof TimeoutError));
});

test("a server that stays silent past timeoutMs rejects with TimeoutError", async (t) => {
    const server = await serveSilent(t);
    const error = await rejection(fetchChain(`127.0.0.1:${server.port}`, { timeoutMs: 100 }));
    assert.ok(error instanceof TimeoutError);
    assert.equal(error.name, "TimeoutError");
    assert.ok(!(error instanceof ConnectionError) && !(error instanceof HandshakeError));
});

test("a server that accepts the connection and closes it, or resets it, rejects with HandshakeError although Node.js reports ECONNRESET", async (t) => {
    for (const [label, behaviour] of /** @type {const} */ ([
        ["closes it", (/** @type {import("node:net").Socket} */ socket) => socket.end()],
        ["resets it", (/** @type {import("node:net").Socket} */ socket) => socket.resetAndDestroy()],
    ])) {
        const server = await serveWith(t, behaviour);
        const error = await rejection(fetchChain(`127.0.0.1:${server.port}`));
        assert.ok(error instanceof HandshakeError, `${label}: ${error}`);
        assert.equal(/** @type {NodeJS.ErrnoException} */ (error.cause).code, "ECONNRESET", label);
    }
});

test("today: a server that requires a client certificate gives its chain over TLS 1.3, and over TLS 1.2 rejects with HandshakeError", async (t) => {
    // Not a rule of the module: it is what Node.js and the protocol do. Over TLS 1.3 the client
    // finishes the handshake before the server refuses it, so the chain has been read by then.
    const demand = { requestCert: true, rejectUnauthorized: true, ca: fixture("root-ca.pem") };
    const modern = await serveChain(t, { options: { ...demand, minVersion: "TLSv1.3" } });
    const sent = fingerprintsOfFixtures(["leaf-p256.pem", "intermediate.pem"]);
    assert.deepEqual(fingerprintsOf((await fetchChain(`127.0.0.1:${modern.port}`)).bytes), sent);
    await sleep(100);

    const older = await serveChain(t, { options: { ...demand, maxVersion: "TLSv1.2" } });
    const error = await rejection(fetchChain(`127.0.0.1:${older.port}`));
    assert.ok(error instanceof HandshakeError, String(error));
    assert.ok(error.cause instanceof Error);
});

test("ConnectionError, HandshakeError and TimeoutError set their name and keep the original error as cause", () => {
    const original = new Error("underneath");
    for (const [Class, name] of /** @type {const} */ ([[ConnectionError, "ConnectionError"], [HandshakeError, "HandshakeError"], [TimeoutError, "TimeoutError"]])) {
        const error = new Class("message", { cause: original });
        assert.equal(error.name, name);
        assert.equal(error.message, "message");
        assert.equal(error.cause, original);
        assert.ok(error instanceof Error);
        assert.equal(Object.prototype.toString.call(error), "[object Error]");
        assert.equal(new Class("message").cause, undefined);
    }
});

test("the core neither exports nor names the TLS errors", () => {
    for (const name of ["ConnectionError", "HandshakeError", "TimeoutError", "fetchChain"]) {
        assert.equal(name in core, false, name);
    }
    const files = readdirSync(new URL("../src/", import.meta.url), { recursive: true, encoding: "utf8" })
        .map((path) => path.replaceAll("\\", "/"))
        .filter((path) => path.endsWith(".js") && !path.startsWith("tls/"));
    assert.ok(files.includes("inspect.js"), files.join(", "));
    for (const path of files) {
        assert.doesNotMatch(readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8"), /ConnectionError|HandshakeError|TimeoutError/, path);
    }
});
