import { readFile } from "node:fs/promises";
import { parseArgs, styleText } from "node:util";
import { AmbiguousTargetError, ParseError, inspect } from "../src/index.js";
import { perLine, safe } from "./safe.js";

/** @import { Observation, Warning } from "../src/index.js" */

// What every command that reads a certificate does the same way: read a path or standard input,
// say what the library's two errors mean, read `--quiet` before the arguments are known to be valid,
// decide whether to colour, and word misuse and warnings. A command composes these instead of
// writing its own, so the same mistake reads the same whichever command was asked.
//
// Nothing here prints or ends anything. Each function gives back the text and the exit code, and
// the command decides whether to print them, because only the command knows whether it was asked
// to be quiet.

/**
 * @typedef {object} Io
 * @property {Record<string, string | undefined>} env
 * @property {AsyncIterable<string | Uint8Array>} stdin
 * @property {{ write(text: string): unknown, on(event: "error", listener: (error: Error & { code?: string }) => void): unknown }} stdout
 * @property {{ write(text: string): unknown, on(event: "error", listener: (error: Error & { code?: string }) => void): unknown }} stderr
 */

/**
 * What a command is given to run: the environment, standard input and the two writers, which print
 * nothing under `--quiet`.
 * @typedef {object} Context
 * @property {Record<string, string | undefined>} env
 * @property {AsyncIterable<string | Uint8Array>} stdin
 * @property {(text: string) => void} out
 * @property {(text: string) => void} err
 */

/** The one flag every command reads even before it knows the command. */
export const QUIET_ONLY = /** @type {const} */ ({ quiet: { type: "boolean", short: "q" } });

/**
 * Whether `--quiet` is among the arguments. They are read leniently here because they may be invalid
 * in other ways, and misuse is silent too: `--quiet` means nothing is printed, and the exit code is
 * the answer. A flag that takes a value takes the next argument whatever it is, so `--select -q` is
 * not quiet.
 * @param {string[]} argv
 * @param {import("node:util").ParseArgsConfig["options"]} options The options of the command.
 */
export function wantsQuiet(argv, options) {
    try {
        return Boolean(parseArgs({ args: argv, options, allowPositionals: true, strict: false }).values.quiet);
    } catch {
        return false;
    }
}

/**
 * Whether to colour: unless `NO_COLOR` has a value. no-color.org says an empty one is as good as
 * unset. Nothing else counts, such as a terminal being attached, so the output never depends on
 * where it goes.
 * @param {Record<string, string | undefined>} env
 */
export function colourOn(env) {
    const value = env.NO_COLOR;
    return value === undefined || value === "";
}

/** What both helps say about colour. */
export const COLOUR_NOTE = `The output is coloured unless the NO_COLOR environment variable is set to a non-empty value.
Nothing else, such as whether a terminal is attached, changes it.`;

/**
 * Paints text, or leaves it plain. Standard error is never painted: a command passes `colour` false
 * for it.
 * @param {boolean} colour
 */
export function painter(colour) {
    return (/** @type {Parameters<typeof styleText>[0]} */ format, /** @type {string} */ text) =>
        colour ? styleText(format, text, { validateStream: false }) : text;
}

/**
 * Reads the command line. Only the parser's own complaints are misuse; anything else is a bug and
 * must show.
 * @template {import("node:util").ParseArgsConfig["options"]} Options
 * @param {string[]} args
 * @param {Options} options
 * @returns {{ values: ReturnType<typeof parseArgs<{ options: Options, allowPositionals: true }>>["values"], positionals: string[] } | { misuse: string }}
 */
export function parseFlags(args, options) {
    try {
        const { values, positionals } = parseArgs({ args, options, allowPositionals: true });
        return { values, positionals };
    } catch (error) {
        if (error instanceof Error && "code" in error && String(error.code).startsWith("ERR_PARSE_ARGS_")) {
            return { misuse: error.message.split("\n")[0] };
        }
        throw error;
    }
}

/**
 * Prints misuse: the first line says what is wrong, an optional list says more, then the usage of
 * the command and where to read more. Every line is escaped on its own, so a value the person typed
 * can not add a line of its own.
 * @param {(text: string) => void} err
 * @param {string} usage
 * @param {string} hint
 * @returns {(message: string, details?: string[]) => 2}
 */
export function misuseOf(err, usage, hint) {
    return (message, details = []) => {
        err(`certdrift: ${safe(message)}\n${details.map((line) => `  ${safe(line)}\n`).join("")}${usage}\n${hint}\n`);
        return 2;
    };
}

/**
 * What is read from a path, or from standard input when the path is `-`, and the name the messages
 * call it.
 * @param {string} path
 * @param {AsyncIterable<string | Uint8Array>} stdin
 * @returns {Promise<{ bytes: Uint8Array, described: string } | { code: 3, message: string }>}
 */
export async function readInput(path, stdin) {
    if (path !== "-") return readPath(path);
    return reading("standard input", () => readAll(stdin));
}

/**
 * What is read from a file, and never from standard input: `-` is a file called `-` here. A
 * command that must not read standard input for an option reads it through this.
 * @param {string} path
 * @returns {Promise<{ bytes: Uint8Array, described: string } | { code: 3, message: string }>}
 */
export function readPath(path) {
    return reading(path, () => readFile(path));
}

/**
 * @param {string} described
 * @param {() => Promise<Uint8Array>} read
 * @returns {Promise<{ bytes: Uint8Array, described: string } | { code: 3, message: string }>}
 */
async function reading(described, read) {
    try {
        return { bytes: await read(), described };
    } catch (error) {
        if (error instanceof Error && "code" in error) {
            return { code: 3, message: `certdrift: cannot read ${safe(described)}: ${safe(error.message)}\n` };
        }
        throw error;
    }
}

/** @param {AsyncIterable<string | Uint8Array>} stream */
async function readAll(stream) {
    /** @type {Uint8Array[]} */
    const chunks = [];
    for await (const chunk of stream) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    return Buffer.concat(chunks);
}

/**
 * The observation of some material, or the message and exit code of why there is none: material
 * that is not a certificate is exit 3, and a bundle with several certificates that could be the one
 * it is about is exit 2, with the candidates listed. Any other error is a bug and is not caught.
 * @param {Uint8Array} material
 * @param {Parameters<typeof inspect>[1]} options
 * @param {string} described What the messages call the material.
 * @returns {{ observation: Observation } | { code: 2 | 3, message: string }}
 */
export function observe(material, options, described) {
    try {
        return { observation: inspect(material, options) };
    } catch (error) {
        if (error instanceof ParseError) return { code: 3, message: `certdrift: ${safe(described)}: ${safe(error.message)}\n` };
        if (error instanceof AmbiguousTargetError) {
            return { code: 2, message: `certdrift: ${safe(described)}: ${perLine(error.message)}\nUse --select with the start of one sha256 to choose.\n` };
        }
        throw error;
    }
}

/**
 * The lines of an observation's warnings, as every command prints them: a heading, then one line
 * for each, with the code painted. The text of a warning can come from a certificate.
 * @param {Warning[]} warnings
 * @param {ReturnType<typeof painter>} paint
 * @returns {string[]} Empty when there are none.
 */
export function warningLines(warnings, paint) {
    if (warnings.length === 0) return [];
    return [
        paint("bold", "Warnings"),
        ...warnings.map(({ code, certificate, message }) => `  ${paint("yellow", safe(code))}${certificate === null ? "" : ` [${certificate}]`} ${safe(message)}`),
    ];
}
