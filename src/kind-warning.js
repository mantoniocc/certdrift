// Whether `kind` and `eku` can be trusted for a certificate.
//
// `kind` is Node.js's `ca`, which comes from OpenSSL: it is true only when OpenSSL can read every
// extension it knows. A CA that carries one of them twice, or one that does not decode, reads as
// not a CA, and nothing else in the observation shows it. So basicConstraints and Key Usage are
// read here, from the certificate's DER, and the rule `kind` states is applied to them: a CA when
// basicConstraints marks it as one and, if Key Usage is present, it includes keyCertSign. When
// either extension is repeated or does not decode, or the rule and Node.js disagree, the
// certificate gets a KIND_UNRELIABLE warning. `kind` keeps the value Node.js gives. Why Node.js
// failed is not decided here and the other extensions are not examined: the comparison is what
// finds the problem, so if Node.js comes to read such a certificate correctly, the warning stops.
//
// `eku` is Node.js's `keyUsage`, which is `undefined` both when the Extended Key Usage extension
// is absent and when it is present and OpenSSL cannot read it: then `eku` is `null`, which says the
// certificate restricts no usage, about a certificate that does restrict them. So the Extended Key
// Usage extensions are counted here too, and when the certificate carries one and Node.js reports
// none, it gets an EKU_UNRELIABLE warning; `eku` keeps the value Node.js gives. The count tells the
// two ways OpenSSL fails apart: an extension that appears more than once is not read, and one that
// appears once and is not read is one whose value does not decode. The value itself is not
// decoded: OpenSSL reads values a strict decoder would refuse, such as bytes after the sequence of
// usages or a length in the long form, so decoding it would warn about certificates whose `eku` is
// right. Counting needs the same walk to the extensions as `kind` does, which is why it is here: a
// module of its own could import nothing and would hold a copy of the walk, and the two copies
// would have to agree on which certificates cannot be walked. Those get KIND_UNRELIABLE, which
// says so, and no second warning from the count.
//
// This is not a DER parser, and it must not grow into one. A reader of our own can misread a
// certificate without anyone noticing, which is worse than not reading it, so this one is held to
// what the warnings need:
//   - it walks only as far as the extensions and decodes only the values of basicConstraints and
//     Key Usage; the Extended Key Usage extensions are counted by their identifier, and every other
//     field and extension is skipped by its length, unread;
//   - nothing it reads leaves this module except the warnings: no field of the observation comes
//     from it, and every one is read through X509Certificate;
//   - it never throws and never guesses: whatever it cannot walk or decode is reported as such,
//     and the warning follows;
//   - it trusts no length beyond the bytes of the element that contains it, and refuses the
//     indefinite length. A long-form length that a short one could have written is read: it has
//     one reading, and Node.js reads it and keeps the bytes as they are;
//   - it imports nothing.
// Reading another extension, or another field, is a new decision with its reason written here, as
// the one for the Extended Key Usage is, not an addition made in passing.

// The content of the OBJECT IDENTIFIER of each extension: 2.5.29.19, 2.5.29.15 and 2.5.29.37.
const BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13];
const KEY_USAGE = [0x55, 0x1d, 0x0f];
const EXTENDED_KEY_USAGE = [0x55, 0x1d, 0x25];

// The tags this reader meets.
const BOOLEAN = 0x01;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const OBJECT_IDENTIFIER = 0x06;
const SEQUENCE = 0x30;
const EXTENSIONS_FIELD = 0xa3;

/**
 * The KIND_UNRELIABLE warning for a certificate, or `null` when its `kind` can be trusted.
 * @param {Uint8Array} der The certificate, as Node.js keeps it (`raw`).
 * @param {boolean} ca What Node.js reports (`ca`), which `kind` is made from.
 * @param {number} index The certificate's index in the observation.
 * @returns {{ code: string, certificate: number, message: string } | null}
 */
export function kindWarning(der, ca, index) {
    const marks = caMarks(der);
    /** @type {string} */
    let why;
    if ("failure" in marks) {
        why = marks.failure === "unreadable"
            ? "the certificate's extensions could not be read to check it"
            : `${marks.names.join(" and ")} ${marks.failure === "repeated" ? `${marks.names.length === 1 ? "appears" : "appear"} more than once` : `${marks.names.length === 1 ? "does" : "do"} not decode`}`;
    } else if (marks.ca !== ca) {
        why = `Node.js reads the certificate as ${ca ? "ca" : "end-entity"}, and its basicConstraints and Key Usage make it ${marks.ca ? "a CA" : "not a CA"}`;
    } else {
        return null;
    }
    return { code: "KIND_UNRELIABLE", certificate: index, message: `kind cannot be trusted: ${why}` };
}

/**
 * The EKU_UNRELIABLE warning for a certificate, or `null` when its `eku` can be trusted.
 * @param {Uint8Array} der The certificate, as Node.js keeps it (`raw`).
 * @param {readonly string[] | undefined} usages What Node.js reports (`keyUsage`), which `eku` is
 *   made from.
 * @param {number} index The certificate's index in the observation.
 * @returns {{ code: string, certificate: number, message: string } | null}
 */
export function ekuWarning(der, usages, index) {
    // Node.js read the extension, so `eku` is what it holds.
    if (usages !== undefined) return null;
    const extensions = extensionsOf(der);
    // The certificate gets KIND_UNRELIABLE, which says its extensions could not be read.
    if (extensions === null) return null;
    const count = extensions.filter(({ id }) => sameBytes(der, id, EXTENDED_KEY_USAGE)).length;
    // Absent, which is what `null` says.
    if (count === 0) return null;
    // A repeated extension is not read whatever its copies hold, so that is the reason when both apply.
    const why = count > 1 ? "appears more than once" : "does not decode";
    return { code: "EKU_UNRELIABLE", certificate: index, message: `eku cannot be trusted: Extended Key Usage ${why}` };
}

/**
 * @typedef {{ failure: "unreadable" }
 *   | { failure: "repeated" | "undecodable", names: string[] }
 *   | { ca: boolean }} Marks
 * What basicConstraints and Key Usage say about whether the certificate is a CA, or why they say
 * nothing. When several failures apply, the one listed first wins: a value that is repeated is not
 * decoded, since there is no telling which copy a verifier reads.
 */

/**
 * @param {Uint8Array} der
 * @returns {Marks}
 */
function caMarks(der) {
    const extensions = extensionsOf(der);
    if (extensions === null) return { failure: "unreadable" };
    const basicConstraints = extensions.filter(({ id }) => sameBytes(der, id, BASIC_CONSTRAINTS));
    const keyUsage = extensions.filter(({ id }) => sameBytes(der, id, KEY_USAGE));

    const repeated = named(basicConstraints.length > 1, keyUsage.length > 1);
    if (repeated.length > 0) return { failure: "repeated", names: repeated };

    const ca = basicConstraints.length === 0 ? false : caFlag(der, basicConstraints[0].value);
    const certSign = keyUsage.length === 0 ? true : keyCertSign(der, keyUsage[0].value);
    const undecodable = named(ca === null, certSign === null);
    if (undecodable.length > 0) return { failure: "undecodable", names: undecodable };
    return { ca: ca === true && certSign === true };
}

/**
 * @param {boolean} basicConstraints
 * @param {boolean} keyUsage
 */
function named(basicConstraints, keyUsage) {
    return [...(basicConstraints ? ["basicConstraints"] : []), ...(keyUsage ? ["Key Usage"] : [])];
}

/**
 * The identifier and the value of every extension, as positions in `der`, or `null` when the way
 * to them cannot be walked. A certificate with no extensions field has none.
 *
 * The fields of the body before the extensions are skipped by their lengths and not looked at:
 * Node.js has already read them, and the extensions field is the only one tagged [3].
 * @param {Uint8Array} der
 * @returns {{ id: Element, value: Element }[] | null}
 */
function extensionsOf(der) {
    const certificate = elementAt(der, 0, der.length);
    if (certificate === null || certificate.tag !== SEQUENCE || certificate.end !== der.length) return null;
    const body = elementAt(der, certificate.start, certificate.end);
    if (body === null || body.tag !== SEQUENCE) return null;

    let field = null;
    for (let offset = body.start; offset < body.end && field === null; ) {
        const element = elementAt(der, offset, body.end);
        if (element === null) return null;
        if (element.tag === EXTENSIONS_FIELD) field = element;
        offset = element.end;
    }
    if (field === null) return [];

    const list = elementsIn(der, field);
    if (list === null || list.length !== 1 || list[0].tag !== SEQUENCE) return null;
    const extensions = elementsIn(der, list[0]);
    if (extensions === null) return null;

    const found = [];
    for (const extension of extensions) {
        if (extension.tag !== SEQUENCE) return null;
        // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        const parts = elementsIn(der, extension);
        if (parts === null || parts.length < 2 || parts.length > 3) return null;
        const id = parts[0];
        const value = parts[parts.length - 1];
        if (id.tag !== OBJECT_IDENTIFIER || value.tag !== OCTET_STRING) return null;
        if (parts.length === 3 && parts[1].tag !== BOOLEAN) return null;
        found.push({ id, value });
    }
    return found;
}

/**
 * Whether basicConstraints marks a CA, or `null` when its value does not decode.
 *
 * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.
 * The value must be that sequence and nothing else, both fields in that order. The path length is
 * not read: when it is wrong, Node.js reads no CA while cA says one, and the comparison finds it.
 * @param {Uint8Array} der
 * @param {Element} value The extension's OCTET STRING.
 * @returns {boolean | null}
 */
function caFlag(der, value) {
    const sequence = elementAt(der, value.start, value.end);
    if (sequence === null || sequence.tag !== SEQUENCE || sequence.end !== value.end) return null;
    const fields = elementsIn(der, sequence);
    if (fields === null) return null;

    let ca = false;
    let next = 0;
    if (fields[next]?.tag === BOOLEAN) {
        if (fields[next].end - fields[next].start !== 1) return null;
        ca = der[fields[next].start] !== 0;
        next += 1;
    }
    if (fields[next]?.tag === INTEGER) {
        if (fields[next].end === fields[next].start) return null;
        next += 1;
    }
    return next === fields.length ? ca : null;
}

/**
 * Whether Key Usage includes keyCertSign, or `null` when its value is not a bit string with at
 * least one bit.
 *
 * KeyUsage ::= BIT STRING, whose first octet counts the unused bits at the end, from 0 to 7.
 * keyCertSign is bit 5, `0x04` of the first octet of bits. Unused bits are not part of the value,
 * so they are cleared before it is read, as OpenSSL clears them.
 * @param {Uint8Array} der
 * @param {Element} value The extension's OCTET STRING.
 * @returns {boolean | null}
 */
function keyCertSign(der, value) {
    const bits = elementAt(der, value.start, value.end);
    if (bits === null || bits.tag !== BIT_STRING || bits.end !== value.end) return null;
    if (bits.end - bits.start < 2) return null;
    const unused = der[bits.start];
    if (unused > 7) return null;
    const first = der[bits.start + 1] & (bits.end - bits.start === 2 ? 0xff << unused : 0xff);
    return (first & 0x04) !== 0;
}

/**
 * @typedef {object} Element
 * @property {number} tag
 * @property {number} start Where its content starts.
 * @property {number} end Where its content ends, which is where the next element starts.
 */

/**
 * The tag and the bounds of the content of the element at `offset`, which must end by `end`, or
 * `null` when it cannot be read there. It reads a tag and a length and nothing of the content.
 * @param {Uint8Array} der
 * @param {number} offset
 * @param {number} end
 * @returns {Element | null}
 */
function elementAt(der, offset, end) {
    if (end - offset < 2) return null;
    const tag = der[offset];
    // A tag number above 30 takes more octets, which none of the elements walked here has.
    if ((tag & 0x1f) === 0x1f) return null;
    let length = der[offset + 1];
    let start = offset + 2;
    if (length >= 0x80) {
        // 0x80 alone is the indefinite length, which DER forbids. More than four octets of length
        // describe more bytes than any certificate has.
        const octets = length - 0x80;
        if (octets === 0 || octets > 4 || octets > end - start) return null;
        length = 0;
        for (let i = 0; i < octets; i += 1) length = length * 256 + der[start + i];
        start += octets;
    }
    if (length > end - start) return null;
    return { tag, start, end: start + length };
}

/**
 * The elements that fill the content of `parent` exactly, or `null` when they do not.
 * @param {Uint8Array} der
 * @param {Element} parent
 * @returns {Element[] | null}
 */
function elementsIn(der, parent) {
    const elements = [];
    for (let offset = parent.start; offset < parent.end; ) {
        const element = elementAt(der, offset, parent.end);
        if (element === null) return null;
        elements.push(element);
        offset = element.end;
    }
    return elements;
}

/**
 * @param {Uint8Array} der
 * @param {Element} element
 * @param {number[]} expected
 */
function sameBytes(der, element, expected) {
    return element.end - element.start === expected.length && expected.every((byte, i) => der[element.start + i] === byte);
}
