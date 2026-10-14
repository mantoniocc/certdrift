import { isIPv4, isIPv6 } from "node:net";
import { ConnectionError, HandshakeError, TimeoutError, fetchChain } from "../src/tls/index.js";
import { safe } from "./safe.js";

/** @import { FetchChainOptions, FetchedChain } from "../src/tls/index.js" */

// Getting the certificates of a host, for every command that takes one: the flags that name it,
// the rules about them, the call to the TLS module, and what a failure says and exits with. Each
// command composes these instead of writing its own, so the same mistake and the same unreachable
// host read the same whichever command was asked.
//
// Nothing here prints or ends anything. Each function gives back the text, and the command decides
// whether to print it, because only the command knows whether it was asked to be quiet.

/** The flags that choose a host and how to reach it, as `parseArgs` reads them. */
export const HOST_OPTIONS = /** @type {const} */ ({
    // Lists so that a repeated flag can be refused: parseArgs would silently keep the last one.
    host: { type: "string", multiple: true },
    servername: { type: "string", multiple: true },
    timeout: { type: "string", multiple: true },
});

/**
 * The names a command gives the three flags, without the dashes. Every message is worded from
 * them, so a command that takes the flags under other names gets the same rules in its own words.
 * @typedef {object} HostFlagNames
 * @property {string} host
 * @property {string} servername
 * @property {string} timeout
 */

/** @type {HostFlagNames} */
const NAMES = { host: "host", servername: "servername", timeout: "timeout" };

/**
 * A host asked for on the command line, checked against the rules of the flags and not yet
 * against those of the TLS module.
 * @typedef {object} HostRequest
 * @property {string} target The host as typed.
 * @property {Pick<FetchChainOptions, "servername" | "timeoutMs">} options Only what was given, so
 *   the module's defaults apply to the rest.
 */

/**
 * Reads the host flags of a command line and applies their rules. The first rule broken is the one
 * reported, in this order: a flag given twice, then, with a host, a path given too and a timeout
 * that is not digits; without one, a server name or a timeout given anyway.
 * @param {Readonly<Record<string, unknown>>} values What `parseArgs` read, with the three flags
 *   defined by `HOST_OPTIONS`.
 * @param {{ pathGiven: boolean, names?: HostFlagNames }} context `pathGiven` says whether the
 *   command line also names a path or `-` for what the host would replace.
 * @returns {{ misuse: string } | { request: HostRequest | undefined }} `request` is `undefined`
 *   when no host was asked for.
 */
export function hostRequestOf(values, { pathGiven, names = NAMES }) {
    const flag = (/** @type {keyof HostFlagNames} */ key) => `--${names[key]}`;
    for (const key of /** @type {const} */ (["host", "servername", "timeout"])) {
        if (listOf(values, names[key]).length > 1) return { misuse: `${flag(key)} was given more than once` };
    }
    const [host] = listOf(values, names.host);
    const [servername] = listOf(values, names.servername);
    const [timeout] = listOf(values, names.timeout);
    if (host === undefined) {
        if (servername !== undefined) return { misuse: `${flag("servername")} is sent to a host, so it needs ${flag("host")}` };
        if (timeout !== undefined) return { misuse: `${flag("timeout")} is the wait for a host, so it needs ${flag("host")}` };
        return { request: undefined };
    }
    // A path is always a file and the host is always given with its flag, so a command line that
    // holds both has no single meaning, and neither is guessed from a colon or from whether a file
    // of that name exists.
    if (pathGiven) return { misuse: `${flag("host")} takes no path and no "-": it reads what a server sends, not a file or standard input` };
    // Only the form is checked here. The upper bound is the module's, which refuses it in its own
    // words: `Number()` alone would accept `1e3`, `0x10` and ` 5`.
    if (timeout !== undefined && !/^[1-9][0-9]*$/.test(timeout)) return { misuse: `${flag("timeout")} needs a positive whole number of milliseconds, and got ${JSON.stringify(timeout)}` };
    return {
        request: {
            target: host,
            options: {
                ...(servername === undefined ? {} : { servername }),
                ...(timeout === undefined ? {} : { timeoutMs: Number(timeout) }),
            },
        },
    };
}

/**
 * The values of one flag. `HOST_OPTIONS` makes each of them a list, absent when not given.
 * @param {Readonly<Record<string, unknown>>} values
 * @param {string} name
 * @returns {string[]}
 */
function listOf(values, name) {
    return /** @type {string[] | undefined} */ (values[name]) ?? [];
}

/**
 * Why the TLS module refuses the arguments of a request, in its own words, or `undefined` when it
 * accepts them. No socket is opened.
 *
 * `fetchChain` refuses an argument it cannot use with a `TypeError` before it opens a socket, and
 * it does so before it looks at the signal. Asking with a signal that is already aborted therefore
 * tells a refused argument (misuse) from everything else without connecting, and without taking
 * every `TypeError` for misuse: the one raised while connecting is a bug. Anything else the call
 * rejects with is not caught.
 * @param {HostRequest} request
 * @returns {Promise<string | undefined>}
 */
export async function refusalOf({ target, options }) {
    const accepted = new Error("the arguments were accepted");
    try {
        await fetchChain(target, { ...options, signal: AbortSignal.abort(accepted) });
    } catch (error) {
        if (error instanceof TypeError) return error.message;
        if (error !== accepted) throw error;
    }
    return undefined;
}

/**
 * Connects and gives what the host sent, or the line that says why it could not and the exit code
 * that goes with it. Ask `refusalOf` first: an argument the module refuses is a `TypeError` here,
 * and it is not caught, like every error that is not a failure of the host.
 * @param {HostRequest} request
 * @param {{ names?: HostFlagNames }} [context] The names the command gives the flags, which the
 *   failure's hint is worded from.
 * @returns {Promise<{ chain: FetchedChain } | { code: 3, message: string }>}
 */
export async function fetchHost(request, { names = NAMES } = {}) {
    const { target, options } = request;
    try {
        return { chain: await fetchChain(target, options) };
    } catch (error) {
        const failure = hostFailure(error, { request, names });
        if (failure === undefined) throw error;
        return { code: 3, message: `certdrift: ${safe(target)}: ${failure}\n` };
    }
}

/**
 * What a failure to get the certificates of a host says, or `undefined` when the error is none of
 * the three the module raises for that: any other error is not this command's to explain.
 *
 * The module's `ConnectionError` covers a host that cannot be reached and one that refuses the
 * connection, which a person fixes differently, so the original error's code tells them apart.
 * Every part of the text comes from the error, and the host's own text can be in it, so it is shown
 * escaped.
 *
 * A failed handshake with a target that sent no server name says so on a second line, because a
 * server that picks its certificate by name often answers that with an alert, and "the host may not
 * speak TLS" then points away from the fix. Whether to say it is decided from the request alone:
 * OpenSSL's code and wording for that alert change between versions, and a server may refuse the
 * handshake for this reason in other words. Without the request nothing is known about what was
 * typed, so nothing is added.
 * @param {unknown} error
 * @param {{ request?: HostRequest, names?: HostFlagNames }} [context]
 * @returns {string | undefined}
 */
export function hostFailure(error, { request, names = NAMES } = {}) {
    if (error instanceof TimeoutError) return `did not answer in time: ${safe(error.message)}`;
    if (error instanceof HandshakeError) {
        const headline = `the TLS handshake failed (the host may not speak TLS): ${safe(reasonOf(error))}`;
        return sendsNoServerName(request) ? `${headline}\n${serverNameHint(names)}` : headline;
    }
    if (error instanceof ConnectionError) {
        const code = error.cause instanceof Error && "code" in error.cause ? error.cause.code : undefined;
        const refused = code === "ECONNREFUSED" || code === "ECONNRESET";
        return `${refused ? "connection refused" : "cannot be reached"}: ${safe(reasonOf(error))}`;
    }
    return undefined;
}

/**
 * Whether the request sent no server name: the target is an address, which has none of its own,
 * and none was given.
 * @param {HostRequest | undefined} request
 */
function sendsNoServerName(request) {
    return request !== undefined && request.options.servername === undefined && isAddress(request.target);
}

/**
 * Whether a target as typed is an IPv4 address, or an IPv6 address in brackets, each with or
 * without a port. This is the rule `targetOf` applies in `src/tls/target.js` to give no server name
 * to an address. It is written again here because `bin/` may import only the files `package.json`
 * exports and that parser is not one of them, and exporting it would add to the public API. A test
 * runs both on the same targets so that they stay in agreement. A target the module refuses never
 * gets here, because `refusalOf` is asked first, but this must not throw on one.
 * @param {string} target
 */
function isAddress(target) {
    const bracketed = /^\[([^\]]*)\]/s.exec(target);
    return bracketed === null ? isIPv4(target.split(":")[0]) : isIPv6(bracketed[1]);
}

/**
 * What to say when a handshake failed for a target that sent no server name. It is the same text
 * for every host and every error, and only the name of the flag comes from the command.
 * @param {HostFlagNames} names
 */
function serverNameHint({ servername }) {
    return `An IP address sends no server name, and a server that needs one may refuse the handshake: try --${servername} <name>.`;
}

/**
 * The reason inside a module error: what Node.js or OpenSSL said, which is more to the point than
 * the module's sentence around it, and that sentence when there is nothing underneath. OpenSSL's
 * `reason` is the part of its report a reader needs.
 * @param {Error} error
 */
function reasonOf(error) {
    const { cause } = error;
    if (!(cause instanceof Error)) return error.message;
    const reason = /** @type {{ reason?: unknown }} */ (cause).reason;
    return typeof reason === "string" ? reason : cause.message.split("\n")[0];
}
