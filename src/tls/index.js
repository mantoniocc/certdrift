import tls from "node:tls";
import { servernameOf, targetOf } from "./target.js";

/** @import { Source } from "../index.js" */

// The only place that opens a socket. It returns what the server sends and nothing about how
// Node.js judged it: whether the local trust store would accept the chain describes this
// machine, not the certificates, and the observation has no field for it on purpose.

const DEFAULT_TIMEOUT_MS = 10_000;
// The longest delay a timer takes. A larger one is cut to 1 ms with a warning.
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/**
 * @typedef {object} FetchChainOptions
 * @property {string} [servername] The server name to send, which decides the certificate a
 *   server picks. It defaults to the host name. An IP address target sends none unless this is
 *   given, and it cannot itself be an IP address.
 * @property {number} [timeoutMs] The longest the whole attempt may take, from the lookup to the
 *   end of the handshake, as a whole number of milliseconds. It defaults to 10000.
 * @property {AbortSignal} [signal] Cancels the attempt. The promise rejects with the signal's
 *   reason and the socket is closed.
 */

/**
 * What a server sent for a connection.
 * @typedef {object} FetchedChain
 * @property {Uint8Array} bytes One PEM block per certificate, in the order Node.js lists them
 *   for the connection, which `inspect()` accepts as it is.
 * @property {Source} source `{ kind: "host", ref, servername }`, ready to pass to `inspect()`.
 *   `ref` is `host:port` with the port always written, and `servername` is the name that was
 *   sent, or `null` when none was.
 */

/** The network failed: the name did not resolve, or the host refused or could not be reached. */
export class ConnectionError extends Error {
    /**
     * @param {string} message
     * @param {{ cause?: unknown }} [options] `cause` is the error Node.js raised.
     */
    constructor(message, options) {
        super(message, options);
        this.name = "ConnectionError";
    }
}

/** The host accepted the connection and then did not speak TLS, or answered with an alert. */
export class HandshakeError extends Error {
    /**
     * @param {string} message
     * @param {{ cause?: unknown }} [options] `cause` is the error Node.js raised, if any.
     */
    constructor(message, options) {
        super(message, options);
        this.name = "HandshakeError";
    }
}

/**
 * The attempt took longer than `timeoutMs`. There is no error underneath it, so it has no
 * `cause`. A signal made with `AbortSignal.timeout()` rejects with a `DOMException` that is
 * also named `TimeoutError`: tell this one apart with `instanceof`, not with the name.
 */
export class TimeoutError extends Error {
    /**
     * @param {string} message
     * @param {{ cause?: unknown }} [options]
     */
    constructor(message, options) {
        super(message, options);
        this.name = "TimeoutError";
    }
}

/**
 * Connects to a host over TLS and returns the certificates it presents, as bytes ready for
 * `inspect()` and the source to record with them. Expired, self-signed and otherwise untrusted
 * certificates are returned like any other: nothing is verified, and nothing is said about
 * whether this machine would trust the chain.
 *
 * The chain is what Node.js exposes for the connection: the certificate the server presented,
 * then each issuer Node.js links to it, until there is none or it is one already seen. Node.js
 * links a certificate to its issuer with the local trust store as well as with what the server
 * sent, so the chain may hold a certificate the server did not send.
 *
 * Rejects with `TypeError` for an argument that cannot be used, before any socket is opened,
 * with `ConnectionError` when the network fails, `HandshakeError` when the host does not speak
 * TLS or answers with an alert, `TimeoutError` when `timeoutMs` passes, and with the reason of
 * the signal when it aborts. The socket is closed in every outcome.
 * @param {string} target `host`, `host:port`, an IPv4 address with or without a port, or an
 *   IPv6 address in brackets with or without a port, as in `[2001:db8::1]:443`. The port
 *   defaults to 443.
 * @param {FetchChainOptions} [options]
 * @returns {Promise<FetchedChain>}
 */
export async function fetchChain(target, options) {
    const { host, port, ref, servername: byDefault } = targetOf(target);
    if (options !== undefined && (typeof options !== "object" || options === null)) {
        throw new TypeError("options must be an object");
    }
    const servername = servernameOf(options?.servername) ?? byDefault;
    const timeoutMs = timeoutOf(options?.timeoutMs);
    const signal = signalOf(options?.signal);
    if (signal?.aborted) throw signal.reason;

    return new Promise((resolve, reject) => {
        let stage = "connecting";
        let settled = false;

        // `rejectUnauthorized: false` is what lets an untrusted chain be read at all.
        //
        // `ca: []` gives the connection an empty trust store, so verification always fails. When
        // it succeeds, Node.js converts the peer certificate with `getPeerCertificate(true)` for
        // its own server identity check, and that conversion kills the process for a chain with
        // a brainpool key (a segmentation fault, no error to catch) as soon as the machine's
        // store trusts the chain. Trust is never reported, so nothing is lost. An empty string
        // would not do: Node.js reads it as the default store.
        const socket = tls.connect({
            host,
            port,
            ...(servername === null ? {} : { servername }),
            rejectUnauthorized: false,
            ca: [],
        });

        const timer = setTimeout(() => {
            settle(() => reject(new TimeoutError(`no answer from ${ref} within ${timeoutMs} ms while ${stage}`)));
        }, timeoutMs);
        const onAbort = () => settle(() => reject(signal?.reason));
        signal?.addEventListener("abort", onAbort, { once: true });

        /**
         * Ends the attempt once, whatever happens first, and always releases what it holds.
         * @param {() => void} outcome
         */
        function settle(outcome) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            signal?.removeEventListener("abort", onAbort);
            socket.destroy();
            outcome();
        }

        // An error that arrives after the attempt ended must not become an uncaught exception, so
        // this listener is never removed: `settle` ignores it by then.
        socket.on("error", (error) => {
            settle(() => reject(stage === "connecting"
                ? new ConnectionError(`could not connect to ${ref}: ${reasonOf(error)}`, { cause: error })
                : new HandshakeError(`the TLS handshake with ${ref} failed: ${reasonOf(error)}`, { cause: error })));
        });
        socket.once("connect", () => {
            stage = "handshaking";
        });
        socket.once("secureConnect", () => {
            try {
                const pem = chainOf(socket);
                if (pem === "") {
                    settle(() => reject(new HandshakeError(`${ref} completed the handshake without a certificate`)));
                } else {
                    settle(() => resolve({
                        bytes: new TextEncoder().encode(pem),
                        source: { kind: "host", ref, servername },
                    }));
                }
            } catch (error) {
                settle(() => reject(new HandshakeError(`the certificates of ${ref} could not be read: ${reasonOf(error)}`, { cause: error })));
            }
        });
    });
}

/**
 * The certificates Node.js exposes for a connection, as PEM, walked from the peer certificate
 * through its issuer. `getPeerCertificate()` and `toLegacyObject()` are never used: the first
 * also reports a root from the local trust store that the server did not send, and the second
 * does not survive a brainpool key.
 *
 * The walk ends when there is no next certificate or it is one already seen, and it compares
 * objects, not bytes: a server may send the same certificate twice, and each copy is a
 * different object that must not cut the chain short.
 * @param {import("node:tls").TLSSocket} socket
 * @returns {string} Empty when there is no peer certificate.
 */
function chainOf(socket) {
    const seen = new Set();
    let pem = "";
    for (let certificate = socket.getPeerX509Certificate(); certificate !== undefined && !seen.has(certificate); certificate = certificate.issuerCertificate) {
        seen.add(certificate);
        pem += certificate.toString();
    }
    return pem;
}

/**
 * What an error says, in one line. OpenSSL's reports run to several lines and begin with a
 * thread address, and its `reason` is the part a reader needs. The other errors Node.js raises
 * here come from the operating system and are one line already.
 * @param {unknown} error
 */
function reasonOf(error) {
    if (!(error instanceof Error)) return String(error);
    const reason = /** @type {{ reason?: unknown }} */ (error).reason;
    return typeof reason === "string" ? reason : error.message;
}

/**
 * @param {unknown} given
 * @returns {number}
 */
function timeoutOf(given) {
    if (given === undefined) return DEFAULT_TIMEOUT_MS;
    if (typeof given !== "number" || !Number.isInteger(given) || given < 1 || given > MAX_TIMEOUT_MS) {
        throw new TypeError(`options.timeoutMs must be a whole number of milliseconds from 1 to ${MAX_TIMEOUT_MS}`);
    }
    return given;
}

/**
 * @param {unknown} given
 * @returns {AbortSignal | undefined}
 */
function signalOf(given) {
    if (given === undefined) return undefined;
    if (!(given instanceof AbortSignal)) throw new TypeError("options.signal must be an AbortSignal");
    return given;
}
