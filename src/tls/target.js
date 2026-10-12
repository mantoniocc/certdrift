import { isIPv4, isIPv6 } from "node:net";

// What a target may be written as, and what `ref` and the server name are made of. This file
// opens no socket, so the rules can be tested one by one.

const DEFAULT_PORT = 443;
const LABEL = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/;
// Resolvers read a last label that is a number as part of an IPv4 address (`127.1` is
// 127.0.0.1, `0x7f.0.0.1` is too), so such a name would be sent to the server as one thing and
// connected to as another.
const NUMBER = /^(?:\d+|0[xX][0-9A-Fa-f]*)$/;
const PORT = /^[1-9]\d{0,4}$/;

/**
 * Whether a text is a host name that can be connected to and sent as a server name: dot
 * separated labels of ASCII letters, digits, hyphens and underscores, the last one not a number.
 * An IP address is not a host name.
 * @param {string} text
 */
export function isHostName(text) {
    if (text.length > 253) return false;
    const labels = text.split(".");
    return labels.every((label) => LABEL.test(label)) && !NUMBER.test(labels[labels.length - 1]);
}

/**
 * @param {string} text
 * @param {string} reason
 * @returns {never}
 */
function refuse(text, reason) {
    throw new TypeError(`target ${JSON.stringify(text)} cannot be read: ${reason}`);
}

/**
 * Reads a target: `host`, `host:port`, `a.b.c.d`, `a.b.c.d:port`, `[ipv6]` or `[ipv6]:port`.
 * The port defaults to 443.
 *
 * `host` is what to connect to, without brackets. A host name is lowercased, and an IPv6
 * address is written the way the subject alternative names write it (RFC 5952), so the same
 * server is always labelled the same way in `ref`. `servername` is the server name to send by
 * default: the host name, and `null` for an IP address, which has none.
 * @param {unknown} text
 * @returns {{ host: string, port: number, ref: string, servername: string | null }}
 * @throws {TypeError} The text is not a target.
 */
export function targetOf(text) {
    if (typeof text !== "string") throw new TypeError("target must be a string");

    /** @type {string} */ let host;
    /** @type {string | undefined} */ let portText;
    let inBrackets = false;

    const bracketed = /^\[([^\]]*)\](.*)$/s.exec(text);
    if (bracketed !== null) {
        const [, address, rest] = bracketed;
        if (!isIPv6(address)) refuse(text, "the brackets must hold an IPv6 address");
        if (address.includes("%")) refuse(text, "an IPv6 address with a zone is not accepted");
        if (rest !== "" && !rest.startsWith(":")) refuse(text, "only :port may follow the brackets");
        // The host name of a URL is where a canonical form of the address is already written.
        host = new URL(`https://[${address}]/`).hostname.slice(1, -1);
        portText = rest === "" ? undefined : rest.slice(1);
        inBrackets = true;
    } else {
        const parts = text.split(":");
        if (parts.length > 2) refuse(text, "an IPv6 address must be written in brackets, as [2001:db8::1]:443");
        host = parts[0];
        portText = parts[1];
    }

    let port = DEFAULT_PORT;
    if (portText !== undefined) {
        port = Number(portText);
        if (!PORT.test(portText) || port > 65535) refuse(text, "the port must be a whole number from 1 to 65535");
    }

    if (inBrackets) return { host, port, ref: `[${host}]:${port}`, servername: null };
    if (isIPv4(host)) return { host, port, ref: `${host}:${port}`, servername: null };
    if (!isHostName(host)) refuse(text, "write a host name, an IPv4 address or a bracketed IPv6 address");
    const name = host.toLowerCase();
    return { host: name, port, ref: `${name}:${port}`, servername: name };
}

/**
 * Checks the server name a caller asks to send. Node.js sends nothing for an empty one and warns
 * for an IP address, and a record that claimed a name nobody sent would be wrong either way.
 * @param {unknown} given
 * @returns {string | undefined} The name as given, or `undefined` when none was given.
 * @throws {TypeError} The value is not a host name.
 */
export function servernameOf(given) {
    if (given === undefined) return undefined;
    if (typeof given !== "string" || !isHostName(given)) {
        throw new TypeError("options.servername must be a host name in ASCII, not an IP address");
    }
    return given;
}
