import { ParseError } from "./errors.js";

// Node.js gives the Subject Alternative Name extension as one string: `TYPE:value` entries
// joined by `, `. A value that holds a comma or a quote is written as a JSON string (the comma
// as `,`), so a `, ` outside quotes only ever separates entries. The text is read with a
// scanner that follows the quotes instead of by splitting on `, `, so it does not depend on
// Node.js escaping every comma.

/**
 * @typedef {object} SubjectAltNames
 * @property {string[]} dns Lowercase, sorted.
 * @property {string[]} ip Canonical form, sorted.
 * @property {string[]} email Sorted.
 * @property {string[]} uri Sorted.
 */

/**
 * Entries of a type the observation has no list for, as Node.js names the type.
 * @typedef {object} Unrepresented
 * @property {string} type
 * @property {number} count
 */

/** The type labels Node.js writes for the four lists, and the list each one fills. */
const LISTS = /** @type {const} */ ({ DNS: "dns", "IP Address": "ip", email: "email", URI: "uri" });

/**
 * The names in a certificate's SAN text, by type.
 *
 * Every entry of a type that has no list (DirName, othername, Registered ID, and any type
 * Node.js adds later) is counted under its own label instead of being dropped, so the caller
 * can say that the certificate holds something this observation does not show.
 * @param {string | undefined} text What Node.js gives for the extension. `undefined` is what it
 *   gives when there is none.
 * @param {number} block The input block of the certificate, for the error message.
 * @returns {{ names: SubjectAltNames, unrepresented: Unrepresented[] }}
 * @throws {ParseError} The text is not a list of entries, or an IP Address entry is not an address.
 */
export function subjectAltNames(text, block) {
    /** @type {SubjectAltNames} */
    const names = { dns: [], ip: [], email: [], uri: [] };
    /** @type {Map<string, number>} */
    const unrepresented = new Map();

    for (const { type, value } of entriesOf(text ?? "", block)) {
        if (!Object.hasOwn(LISTS, type)) {
            unrepresented.set(type, (unrepresented.get(type) ?? 0) + 1);
            continue;
        }
        const list = LISTS[/** @type {keyof typeof LISTS} */ (type)];
        if (list === "ip") {
            const address = canonicalAddress(value);
            if (address === null) {
                throw new ParseError(`input block ${block} has a subject alternative name IP address that is not an address: ${JSON.stringify(value)}`, block);
            }
            names.ip.push(address);
        } else if (list === "dns") {
            // Only A to Z: DNS names compare ignoring ASCII case alone, and Node.js writes the
            // bytes of a non-ASCII name one by one, so folding other letters would change them.
            names.dns.push(value.replace(/[A-Z]/g, (letter) => letter.toLowerCase()));
        } else {
            names[list].push(value);
        }
    }

    for (const list of Object.values(names)) list.sort();
    return { names, unrepresented: [...unrepresented].map(([type, count]) => ({ type, count })) };
}

/**
 * The entries of the text, in order, each as its type and its decoded value.
 * @param {string} text
 * @param {number} block
 * @returns {{ type: string, value: string }[]}
 */
function entriesOf(text, block) {
    /** @param {string} reason */
    const unreadable = (reason) => new ParseError(`input block ${block} has subject alternative names that cannot be read: ${reason}`, block);

    /** @type {{ type: string, value: string }[]} */
    const entries = [];
    let position = 0;
    while (text !== "") {
        const colon = text.indexOf(":", position);
        const type = colon === -1 ? "" : text.slice(position, colon);
        // A comma or a quote before the first colon means the text is not `TYPE:value` entries.
        if (type === "" || /[,"]/.test(type)) {
            throw unreadable(`expected TYPE:value at ${JSON.stringify(text.slice(position, position + 40))}`);
        }

        let end;
        let value;
        if (text[colon + 1] === '"') {
            end = closingQuote(text, colon + 1);
            if (end === -1) throw unreadable(`the quoted value of ${type} is not closed`);
            end += 1;
            try {
                value = /** @type {string} */ (JSON.parse(text.slice(colon + 1, end)));
            } catch {
                throw unreadable(`the quoted value of ${type} is not a JSON string`);
            }
        } else {
            const separator = text.indexOf(", ", colon + 1);
            end = separator === -1 ? text.length : separator;
            value = text.slice(colon + 1, end);
        }
        entries.push({ type, value });

        if (end === text.length) break;
        if (!text.startsWith(", ", end)) {
            throw unreadable(`${type} is followed by ${JSON.stringify(text.slice(end, end + 20))} instead of a separator`);
        }
        position = end + 2;
    }
    return entries;
}

/**
 * Position of the quote that closes the JSON string opening at `open`, or -1.
 * @param {string} text
 * @param {number} open
 */
function closingQuote(text, open) {
    for (let i = open + 1; i < text.length; i += 1) {
        if (text[i] === "\\") i += 1;
        else if (text[i] === '"') return i;
    }
    return -1;
}

/**
 * An IP address in canonical text: IPv4 as four decimal numbers, IPv6 as RFC 5952 prescribes —
 * lowercase, no leading zeros, and the first longest run of two or more zero groups as `::`.
 * An address with an IPv4 tail (`::ffff:192.0.2.1`) is written in hexadecimal like any other,
 * because only some prefixes get the mixed form and implementations disagree on which.
 *
 * Accepts every spelling RFC 4291 allows, so the same address always gives the same text.
 * Written by hand because `node:net` is off limits to the core. A dotted number with a leading
 * zero (`010.0.0.1`) is rejected: it reads as octal in some places and decimal in others.
 * @param {string} text
 * @returns {string | null} `null` when the text is not an IP address.
 */
export function canonicalAddress(text) {
    const v4 = ipv4Octets(text);
    if (v4 !== null) return v4.join(".");

    const halves = text.split("::");
    if (halves.length > 2) return null;
    const pieces = halves.map((half) => (half === "" ? [] : half.split(":")));

    // The IPv4 tail, if any, is the last thing in the text: it stands for the last two groups.
    const last = pieces[pieces.length - 1];
    if (last.length > 0 && last[last.length - 1].includes(".")) {
        const octets = ipv4Octets(/** @type {string} */ (last.pop()));
        if (octets === null) return null;
        last.push(((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16));
    }

    const written = pieces.flat();
    if (!written.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) return null;
    const groups = written.map((group) => Number.parseInt(group, 16));

    if (halves.length === 1) {
        if (groups.length !== 8) return null;
    } else {
        // `::` stands for at least one group.
        if (groups.length > 7) return null;
        const head = pieces[0].length;
        groups.splice(head, 0, ...new Array(8 - groups.length).fill(0));
    }
    return compress(groups);
}

/**
 * @param {string} text
 * @returns {number[] | null} The four octets of a dotted IPv4 address.
 */
function ipv4Octets(text) {
    const match = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(text);
    if (match === null) return null;
    const octets = match.slice(1).map(Number);
    return octets.every((octet) => octet <= 255) ? octets : null;
}

/**
 * @param {number[]} groups Eight 16-bit groups.
 */
function compress(groups) {
    let start = -1;
    let length = 0;
    for (let i = 0; i < groups.length; i += 1) {
        if (groups[i] !== 0) continue;
        let run = 1;
        while (i + run < groups.length && groups[i + run] === 0) run += 1;
        // Strictly longer, so the first of several equal runs wins.
        if (run > length) {
            start = i;
            length = run;
        }
        i += run - 1;
    }

    const hex = groups.map((group) => group.toString(16));
    if (length < 2) return hex.join(":");
    return `${hex.slice(0, start).join(":")}::${hex.slice(start + length).join(":")}`;
}
