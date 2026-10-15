import { readPath } from "./command.js";

// The private key of a command that takes one: the two options that name it, the rules about them,
// and reading the file. The command only reads the file and hands the bytes to the library, which
// decides whether it is the key of the certificate, so nothing here parses, hashes or prints any of
// it, and this file never imports `node:crypto`.
//
// The key and the passphrase are secrets, and nothing here repeats either in a message: a message
// names an option, never its value, and a value an option takes is a path or the name of a
// variable, which a person can mistype as the passphrase itself. A path is printed, as it is for a
// certificate, and nothing that is in the file.
//
// The passphrase comes from the environment on purpose. There is no option that takes it: a command
// line is shown to every user of the machine by the list of processes, and an environment is not.

/** The options that name a key, as `parseArgs` reads them. */
export const KEY_OPTIONS = /** @type {const} */ ({
    // Lists so that a repeated option can be refused: parseArgs would silently keep the last one.
    key: { type: "string", multiple: true },
    "key-passphrase-env": { type: "string", multiple: true },
});

/**
 * A private key asked for on the command line, checked against the rules of its options.
 * @typedef {object} KeyRequest
 * @property {string} path The file, as typed.
 * @property {string | undefined} passphrase Exactly what the variable holds, and `undefined` when
 *   no variable was named: an empty variable is an empty passphrase, which is not the same.
 */

/**
 * Reads the key options of a command line and applies their rules. The first rule broken is the
 * one reported: `--key -`, then `--key-passphrase-env` without `--key`, then a variable that is not
 * defined. A variable is defined when the environment has it as its own property, because the
 * environment of a process also answers for names such as `constructor`, with a function.
 * @param {Readonly<Record<string, unknown>>} values What `parseArgs` read, with the two options
 *   defined by `KEY_OPTIONS`. A repeated option was refused before.
 * @param {Readonly<Record<string, string | undefined>>} env The environment the command was given.
 * @returns {{ misuse: string } | { request: KeyRequest | undefined }} `request` is `undefined` when
 *   no key was asked for.
 */
export function keyRequestOf(values, env) {
    const [path] = /** @type {string[] | undefined} */ (values.key) ?? [];
    const [variable] = /** @type {string[] | undefined} */ (values["key-passphrase-env"]) ?? [];
    // A key read from standard input is not supported, and `-` is a file name nowhere else.
    if (path === "-") return { misuse: "--key - would read the key from standard input, which is not supported: give a file" };
    if (variable !== undefined && path === undefined) return { misuse: "--key-passphrase-env needs --key" };
    if (path === undefined) return { request: undefined };
    if (variable === undefined) return { request: { path, passphrase: undefined } };
    const passphrase = Object.hasOwn(env, variable) ? env[variable] : undefined;
    if (typeof passphrase !== "string") return { misuse: "--key-passphrase-env names an environment variable that is not defined" };
    return { request: { path, passphrase } };
}

/**
 * The bytes of a key file, read as a file and never from standard input. A file that cannot be
 * opened is exit 3, as a certificate file is; one that opens and holds no key is the library's
 * result, not an error here.
 * @param {string} path
 * @returns {Promise<{ material: Uint8Array } | { code: 3, message: string }>}
 */
export async function readKey(path) {
    const read = await readPath(path);
    return "code" in read ? read : { material: read.bytes };
}
