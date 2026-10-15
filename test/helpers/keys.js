import { readFileSync } from "node:fs";
import { inspect, matchesPrivateKey as matchesPrivateKeyOf } from "../../src/index.js";

// The key files among the fixtures and the observations they are checked against. Nothing here
// depends on a key's bytes, because `npm run fixtures` makes new keys.

export const AT = new Date("2026-09-15T14:02:11Z");

/**
 * `matchesPrivateKey` with the arguments of a test: they are often wrong on purpose. The declared
 * types are checked by the consumer in `npm run package:check`.
 * @type {(observation: any, privateKey: any, options?: any) => any}
 */
export const matchesPrivateKey = matchesPrivateKeyOf;

/** @param {string} name File name in test/fixtures/. */
export const text = (name) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");

/** @param {string} name File name in test/fixtures/. */
export const bytes = (name) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url));

/** The passphrase of the encrypted keys, as the generator wrote it, without the line end. */
export const PASSPHRASE = text("test-only-passphrase.txt").replace(/\n$/, "");

/**
 * The observation of a certificate among the fixtures.
 * @param {string} name File name of a single certificate, e.g. `leaf-p256.pem`.
 * @returns {any}
 */
export function observationOf(name) {
    return inspect(bytes(name), { at: AT, source: { kind: "file", ref: name } });
}

/** The message every result of an unreadable key starts with. */
export const UNREADABLE = "the private key could not be read: ";

/** What each reason says, as the README documents it. */
export const REASON = {
    certificate: `${UNREADABLE}the file holds a certificate`,
    publicKey: `${UNREADABLE}the file holds a public key`,
    noKey: `${UNREADABLE}the file holds no private key`,
    encrypted: `${UNREADABLE}it is encrypted and no passphrase was given`,
    decrypt: `${UNREADABLE}it could not be decrypted with the passphrase given`,
    several: `${UNREADABLE}the file holds more than one private key`,
    unsupported: `${UNREADABLE}its format or algorithm is not supported, or the key is damaged`,
};

/** The body of a PEM block, as lines of base64. @param {string} pem */
export function bodyLines(pem) {
    return pem.split("\n").filter((line) => line !== "" && !line.startsWith("-----") && !line.includes(":"));
}

/**
 * Pieces of a key's body that nothing public repeats: every line of base64, and a slice of the
 * middle of each, which is what a message that quotes part of a line would hold.
 * @param {string} key
 */
export function piecesOf(key) {
    return bodyLines(key).flatMap((line) => (line.length >= 16 ? [line, line.slice(4, 20)] : []));
}

/**
 * A PEM block around some body.
 * @param {string} label
 * @param {string} [body]
 */
export function block(label, body = "AAAA") {
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}
