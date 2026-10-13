import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer as createTcpServer } from "node:net";
import { createServer as createTlsServer } from "node:tls";

// Local servers for the tests of the TLS module. Every one listens on an ephemeral port of the
// loopback interface, so no test reaches anything it did not start.

const fixturesUrl = new URL("../fixtures/", import.meta.url);

/** @param {string} name File name in test/fixtures/. */
export function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/**
 * @typedef {object} LocalServer
 * @property {number} port
 * @property {string[]} names The server names clients sent, in order. Empty when none was sent.
 * @property {() => number} accepted How many connections the server has accepted.
 * @property {(count?: number) => Promise<void>} connected Resolves once that many connections
 *   have been accepted.
 * @property {(count?: number) => Promise<void>} closed Resolves once that many connections have
 *   been accepted and every one of them is closed. Rejects when that takes too long, which is
 *   how a socket left open shows.
 * @property {() => Promise<void>} close Destroys what is open and stops listening.
 */

/**
 * Counts the connections of a server, whatever it speaks, at the level of the TCP socket.
 * @param {import("node:net").Server} server
 * @param {number} port
 * @param {string[]} names
 * @param {boolean} drain Whether to read and discard what clients send. A socket nobody reads
 *   never notices that the client left, so a server that is only silent must still read. A TLS
 *   server's sockets are read by the TLS layer, and must be left alone.
 * @returns {LocalServer}
 */
function track(server, port, names, drain) {
    let accepted = 0;
    let open = 0;
    /** @type {Set<import("node:net").Socket>} */
    const sockets = new Set();
    /** @type {Set<() => void>} */
    const listeners = new Set();
    const changed = () => listeners.forEach((listener) => listener());

    server.on("connection", (socket) => {
        accepted += 1;
        open += 1;
        sockets.add(socket);
        if (drain) socket.resume();
        socket.on("error", () => {});
        socket.on("close", () => {
            open -= 1;
            sockets.delete(socket);
            changed();
        });
        changed();
    });

    /**
     * @param {() => boolean} condition
     * @param {string} what
     * @param {number} ms
     */
    const until = (condition, what, ms) => new Promise((resolve, reject) => {
        if (condition()) return resolve(undefined);
        const timer = setTimeout(() => {
            listeners.delete(check);
            reject(new Error(`${what}: ${accepted} accepted, ${open} still open`));
        }, ms);
        function check() {
            if (!condition()) return;
            clearTimeout(timer);
            listeners.delete(check);
            resolve(undefined);
        }
        listeners.add(check);
    });

    return {
        port,
        names,
        accepted: () => accepted,
        connected: async (count = 1) => void (await until(() => accepted >= count, `expected ${count} connections`, 3000)),
        closed: async (count = 1) => void (await until(() => accepted >= count && open === 0, `expected ${count} connections, all closed`, 3000)),
        close: () => new Promise((resolve) => {
            for (const socket of sockets) socket.destroy();
            server.close(() => resolve());
        }),
    };
}

/**
 * @param {import("node:net").Server} server
 * @param {string} [host]
 * @returns {Promise<number>}
 */
function listen(server, host = "127.0.0.1") {
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, host, () => resolve(/** @type {import("node:net").AddressInfo} */ (server.address()).port));
    });
}

/**
 * Registers a server to be closed when the test ends.
 * @param {import("node:test").TestContext} t
 * @param {LocalServer} server
 */
function closeAfter(t, server) {
    t.after(() => server.close());
    return server;
}

/**
 * A TLS server that sends the given certificates, the first of which must match the key.
 * @param {import("node:test").TestContext} t
 * @param {{ certs?: string[], key?: string, host?: string, options?: import("node:tls").TlsOptions }} [what]
 *   `certs` are fixture file names, in the order the server sends them.
 */
export async function serveChain(t, { certs = ["leaf-p256.pem", "intermediate.pem"], key = "leaf-p256.key", host, options = {} } = {}) {
    /** @type {string[]} */
    const names = [];
    const server = createTlsServer({
        key: fixture(key),
        cert: Buffer.concat(certs.map(fixture)),
        // An empty store keeps the server to what it is given. With the default one, OpenSSL
        // completes a chain from the certificates this process trusts (`NODE_EXTRA_CA_CERTS`
        // included) and sends the issuer that the test said it would not send.
        ca: [],
        // The callback only records the name. Without it the server never learns whether one was sent.
        SNICallback: (name, done) => {
            names.push(name);
            done(null, undefined);
        },
        ...options,
    }, (socket) => socket.on("error", () => {}));
    // A client that leaves mid-handshake is expected here; it is not a failure of the test.
    server.on("tlsClientError", () => {});
    const port = await listen(server, host);
    return closeAfter(t, track(server, port, names, false));
}

/**
 * A server that accepts connections and says nothing.
 * @param {import("node:test").TestContext} t
 */
export async function serveSilent(t) {
    const server = createTcpServer();
    const port = await listen(server);
    return closeAfter(t, track(server, port, [], true));
}

/**
 * A server that answers with what the callback does to each socket.
 * @param {import("node:test").TestContext} t
 * @param {(socket: import("node:net").Socket) => void} behaviour
 */
export async function serveWith(t, behaviour) {
    const server = createTcpServer((socket) => behaviour(socket));
    const port = await listen(server);
    return closeAfter(t, track(server, port, [], true));
}

/** A port nothing listens on: one that was just released. */
export async function closedPort() {
    const server = createTcpServer();
    const port = await listen(server);
    await new Promise((resolve) => server.close(() => resolve(undefined)));
    return port;
}

/**
 * @typedef {object} ChildResult
 * @property {number | null} code
 * @property {NodeJS.Signals | null} signal
 * @property {string} stdout
 * @property {string} stderr
 * @property {boolean} timedOut The child was still running when the time given ran out.
 */

/**
 * Runs a script as an ES module in a new Node.js process; `MODULE_URL` is how it imports the
 * module under test. A new process is the only way to show what a process does on its own:
 * whether it exits, what it prints, what the environment it starts with changes.
 * @param {string} source
 * @param {{ env?: Record<string, string>, timeoutMs?: number }} [options]
 * @returns {Promise<ChildResult>}
 */
export function runChild(source, { env = {}, timeoutMs = 20_000 } = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
            env: { ...process.env, NODE_OPTIONS: "", ...env },
            stdio: ["ignore", "pipe", "pipe"],
        });
        /** @type {Buffer[]} */ const out = [];
        /** @type {Buffer[]} */ const err = [];
        child.stdout.on("data", (chunk) => out.push(chunk));
        child.stderr.on("data", (chunk) => err.push(chunk));
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill("SIGKILL");
        }, timeoutMs);
        child.on("error", reject);
        child.on("close", (code, signal) => {
            clearTimeout(timer);
            resolve({ code, signal, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), timedOut });
        });
    });
}

/** The URL of the module under test, for the scripts a child process runs. */
export const MODULE_URL = new URL("../../src/tls/index.js", import.meta.url).href;
