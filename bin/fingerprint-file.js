import { observe, readInput } from "./command.js";

// The file of `--expect-fingerprint-of`: a certificate read as `check` reads one, whose target's
// SHA-256 becomes the fingerprint the checked certificate must have. The command only reads the
// file and asks the library for the target; it decides nothing about the digest.

/** The option that names the file, as `parseArgs` reads it. */
export const FINGERPRINT_FILE_OPTIONS = /** @type {const} */ ({
    // A list so that a repeated option can be refused: parseArgs would silently keep the last one.
    "expect-fingerprint-of": { type: "string", multiple: true },
});

/**
 * What ends the list of candidates when the file has several. `--select` chooses among what the
 * checked certificate's material holds, and never in this file, because a prefix that matches
 * nothing in a material is misuse and one prefix could not serve both.
 */
const FILE_CHOOSE = "--expect-fingerprint-of needs a file where the certificate it is about is one: --select does not choose in it.";

/**
 * Reads the file and gives the SHA-256 of its target, or the message and exit code of why there is
 * none: a file that cannot be read, or that holds no certificate, is exit 3, and one with several
 * candidates for the target is exit 2, with the candidates listed. The file may be standard input,
 * and then it is read to its end.
 * @param {string} path
 * @param {AsyncIterable<string | Uint8Array>} stdin
 * @returns {Promise<{ sha256: string } | { code: 2 | 3, message: string }>}
 */
export async function readFingerprintFile(path, stdin) {
    const read = await readInput(path, stdin);
    if ("code" in read) return read;
    // Only the target's digest is kept, so the observation's source is of no use and is not given.
    const observed = observe(read.bytes, {}, read.described, FILE_CHOOSE);
    if (!("observation" in observed)) return observed;
    const { certificates, target } = observed.observation;
    return { sha256: certificates[target].sha256 };
}
