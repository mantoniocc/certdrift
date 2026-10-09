import { ParseError } from "./errors.js";

const BEGIN = /-----BEGIN ([A-Z0-9 ]+)-----/g;

/**
 * Splits material into one piece per certificate, before anything is parsed: handing a text
 * with several PEM blocks to `X509Certificate` parses only the first and raises no error.
 *
 * - Text outside PEM blocks is ignored, as is any block that is not a certificate (a private key
 *   next to its chain, for example).
 * - Material with no PEM marker at all is one DER certificate.
 * - Blocks are numbered from 1, in the order the certificates appear.
 *
 * @param {string | Uint8Array} material
 * @returns {{ block: number, data: string | Buffer }[]}
 */
export function splitMaterial(material) {
    if (typeof material === "string") return splitPem(material);

    const bytes = Buffer.from(material.buffer, material.byteOffset, material.byteLength);
    if (bytes.length === 0) throw new ParseError("the material is empty");
    // The marker is plain ASCII, so a byte-per-character decoding finds it without
    // assuming anything about the rest of the bytes.
    if (bytes.toString("latin1").includes("-----BEGIN ")) return splitPem(bytes.toString("latin1"));
    return [{ block: 1, data: bytes }];
}

/**
 * @param {string} text
 * @returns {{ block: number, data: string }[]}
 */
function splitPem(text) {
    if (text.trim() === "") throw new ParseError("the material is empty");

    /** @type {{ block: number, data: string }[]} */
    const blocks = [];
    let from = 0;
    for (const begin of text.matchAll(BEGIN)) {
        if (begin.index < from) continue;
        const label = begin[1];
        const end = `-----END ${label}-----`;
        const endAt = text.indexOf(end, begin.index);
        if (label === "CERTIFICATE" && endAt === -1) {
            throw new ParseError(`input block ${blocks.length + 1} has no "${end}" line`, {
                block: blocks.length + 1,
            });
        }
        if (endAt === -1) continue;
        from = endAt + end.length;
        if (label === "CERTIFICATE") {
            blocks.push({ block: blocks.length + 1, data: text.slice(begin.index, from) });
        }
    }

    if (blocks.length === 0) throw new ParseError("the material holds no certificate");
    return blocks;
}
