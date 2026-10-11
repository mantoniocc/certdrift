import { readFile } from "node:fs/promises";
import { parseArgs, styleText } from "node:util";
import {
    inspect,
    serializeObservation,
    ParseError,
    AmbiguousTargetError,
    EXTENDED_KEY_USAGE_OIDS,
} from "../src/index.js";

// The command orchestrates and presents. Everything that interprets a certificate is in the
// library, and every value shown here comes from the observation or from its exports, so what
// the command does is what an import can do.

/** The flags of `certdrift inspect`. */
export const INSPECT_OPTIONS = /** @type {const} */ ({
    json: { type: "boolean" },
    verbose: { type: "boolean", short: "v" },
    quiet: { type: "boolean", short: "q" },
    // A list so that a repeated flag can be refused: parseArgs would silently keep the last one.
    select: { type: "string", multiple: true },
    help: { type: "boolean", short: "h" },
});

const USAGE = "Usage: certdrift inspect [--json | --verbose | --quiet] [--select <sha256>] <path | ->";

const HELP = `certdrift inspects X.509 certificates.

${USAGE}

Reads one certificate or a bundle, as PEM or DER, from a file, or from standard input when the
path is "-". Prints the certificate the material is about, with the rest of its chain.

Options:
  --json             Print the observation as JSON and nothing else on standard output.
  -v, --verbose      Add the full names, the serial, the public key fingerprint, the OIDs
                     beside the usage names and the detail of every certificate in the chain.
  -q, --quiet        Print nothing. The exit code still says what happened.
  --select <sha256>  Choose the certificate when a bundle has several that could be the one it
                     is about. A prefix of its sha256 is enough if it is unique.
  -h, --help         Print this text.

The output is coloured unless the NO_COLOR environment variable is set to a non-empty value.
Nothing else, such as whether a terminal is attached, changes it.

Exit codes:
  0  Success.
  2  Misuse, or a bundle whose certificate is ambiguous (the candidates are listed).
  3  The file is missing or unreadable, or the material is not a certificate.
`;

/**
 * @typedef {object} Io
 * @property {Record<string, string | undefined>} env
 * @property {AsyncIterable<string | Uint8Array>} stdin
 * @property {{ write(text: string): unknown, on(event: "error", listener: (error: Error & { code?: string }) => void): unknown }} stdout
 * @property {{ write(text: string): unknown, on(event: "error", listener: (error: Error & { code?: string }) => void): unknown }} stderr
 */

/**
 * Runs the command and gives its exit code. It never ends the process: `process.exit()` can cut
 * off output still waiting in a pipe, so the caller sets `process.exitCode` and lets Node.js
 * finish writing.
 * @param {string[]} argv The arguments after the executable.
 * @param {Io} io
 * @returns {Promise<number>}
 */
export async function main(argv, { env, stdin, stdout, stderr }) {
    // A reader that closes early (`| head`) is not an error of ours, and without a listener
    // Node.js would end the process with a stack trace and lose the exit code.
    for (const stream of [stdout, stderr]) {
        stream.on("error", (error) => {
            if (error.code !== "EPIPE") throw error;
        });
    }

    // Misuse is silent too: --quiet means nothing is printed, and the exit code is the answer.
    // The arguments are read leniently here because they may be invalid in other ways.
    const quiet = wantsQuiet(argv);
    const out = (/** @type {string} */ text) => { if (!quiet) stdout.write(text); };
    const err = (/** @type {string} */ text) => { if (!quiet) stderr.write(text); };
    /** @param {string} message */
    const misuse = (message) => {
        err(`certdrift: ${safe(message)}\n${USAGE}\nRun certdrift --help for the options.\n`);
        return 2;
    };

    const [command, ...rest] = argv;
    if (command === "-h" || command === "--help") {
        out(HELP);
        return 0;
    }
    if (command === undefined) return misuse("no command given");
    if (command !== "inspect") return misuse(`unknown command ${JSON.stringify(command)}`);

    /** @type {ReturnType<typeof parseArgs<{ options: typeof INSPECT_OPTIONS, allowPositionals: true }>>} */
    let parsed;
    try {
        parsed = parseArgs({ args: rest, options: INSPECT_OPTIONS, allowPositionals: true });
    } catch (error) {
        // Only the parser's own complaints are misuse; anything else is a bug and must show.
        if (error instanceof Error && "code" in error && String(error.code).startsWith("ERR_PARSE_ARGS_")) {
            return misuse(error.message.split("\n")[0]);
        }
        throw error;
    }
    const { values, positionals } = parsed;
    if (values.help) {
        out(HELP);
        return 0;
    }
    if (positionals.length === 0) return misuse('no path given; use "-" to read standard input');
    if (positionals.length > 1) return misuse(`expected one path, got ${positionals.length}`);
    if (values.select !== undefined && values.select.length > 1) return misuse("--select was given more than once");
    const select = values.select?.[0];
    if (select === "") return misuse("--select needs the start of a sha256, and it is empty");

    const [path] = positionals;
    const source = path === "-" ? { kind: "stdin", ref: "-" } : { kind: "file", ref: path };
    const described = path === "-" ? "standard input" : path;

    /** @type {Uint8Array} */
    let material;
    try {
        material = path === "-" ? await readAll(stdin) : await readFile(path);
    } catch (error) {
        if (error instanceof Error && "code" in error) {
            err(`certdrift: cannot read ${safe(described)}: ${safe(error.message)}\n`);
            return 3;
        }
        throw error;
    }

    let observation;
    try {
        observation = inspect(material, { source, ...(select === undefined ? {} : { select }) });
    } catch (error) {
        if (error instanceof ParseError) {
            err(`certdrift: ${safe(described)}: ${safe(error.message)}\n`);
            return 3;
        }
        if (error instanceof AmbiguousTargetError) {
            err(`certdrift: ${safe(described)}: ${perLine(error.message)}\nUse --select with the start of one sha256 to choose.\n`);
            return 2;
        }
        throw error;
    }

    if (values.json) out(serializeObservation(observation));
    else out(present(observation, { verbose: values.verbose === true, colour: !isSet(env.NO_COLOR) }));
    return 0;
}

/** @param {string[]} argv */
function wantsQuiet(argv) {
    try {
        return Boolean(parseArgs({ args: argv, options: INSPECT_OPTIONS, allowPositionals: true, strict: false }).values.quiet);
    } catch {
        return false;
    }
}

/**
 * NO_COLOR counts only when it has a value: no-color.org says an empty one is as good as unset.
 * @param {string | undefined} value
 */
function isSet(value) {
    return value !== undefined && value !== "";
}

/** @param {AsyncIterable<string | Uint8Array>} stream */
async function readAll(stream) {
    /** @type {Uint8Array[]} */
    const chunks = [];
    for await (const chunk of stream) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    return Buffer.concat(chunks);
}

/**
 * What a certificate puts in a name can be anything, and a terminal obeys control characters:
 * an escape sequence could retitle the window or repaint the screen, and a right-to-left mark
 * could reverse what comes after it. Control, format, line and paragraph separators and lone
 * surrogates are shown as `\u{XX}` so the person sees what the certificate holds.
 * @param {string} text
 */
function safe(text) {
    return text.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, (character) => `\\u{${/** @type {number} */ (character.codePointAt(0)).toString(16).toUpperCase()}}`);
}

/**
 * A message that is itself several lines, as the list of candidates is: the line breaks are the
 * library's own and stay, and what is inside each line is escaped.
 * @param {string} text
 */
function perLine(text) {
    return text.split("\n").map(safe).join("\n");
}

/**
 * @typedef {ReturnType<typeof inspect>} Observation
 * @typedef {Observation["certificates"][number]} Certificate
 */

/**
 * The readable text of an observation. Every value is the observation's own: nothing here is
 * computed about a certificate, and it says nothing about whether one is valid or expired.
 * @param {Observation} observation
 * @param {{ verbose: boolean, colour: boolean }} options
 */
export function present(observation, { verbose, colour }) {
    /** @param {Parameters<typeof styleText>[0]} format @param {string} text */
    const paint = (format, text) => (colour ? styleText(format, text, { validateStream: false }) : text);
    const { certificates, target, warnings } = observation;
    const lines = [paint("bold", "Target"), ...block(certificates[target], verbose)];

    const others = certificates.filter((certificate) => certificate.index !== target);
    if (others.length > 0) {
        lines.push("", paint("bold", "Chain"));
        for (const certificate of others) {
            if (verbose) lines.push(...block(certificate, true), "");
            else lines.push(`  [${certificate.index}] ${certificate.kind}  ${nameOf(certificate.subject)}  ${relation(certificate)}  ${certificate.sha256}`);
        }
        if (verbose) lines.pop();
    }

    if (warnings.length > 0) {
        lines.push("", paint("bold", "Warnings"));
        for (const { code, certificate, message } of warnings) {
            lines.push(`  ${paint("yellow", safe(code))}${certificate === null ? "" : ` [${certificate}]`} ${safe(message)}`);
        }
    }
    return `${lines.join("\n")}\n`;
}

/**
 * The lines about one certificate.
 * @param {Certificate} certificate
 * @param {boolean} verbose
 */
function block(certificate, verbose) {
    const { derived, key, san } = certificate;
    /** @type {[string, string[]][]} */
    const fields = [["certificate", [`[${certificate.index}] ${certificate.kind}  ${nameOf(certificate.subject)}`]]];
    if (verbose) fields.push(["subject", [safe(certificate.subject.dn)]], ["serial", [certificate.serial]]);

    const names = /** @type {const} */ (["dns", "ip", "email", "uri"])
        .filter((type) => san[type].length > 0)
        .map((type) => `${type}: ${san[type].map(safe).join(", ")}`);
    fields.push(["san", names.length > 0 ? names : ["none"]]);
    fields.push(["eku", [usages(certificate.eku, verbose)]]);

    fields.push(["validity", [`${certificate.notBefore} to ${certificate.notAfter}`]]);
    fields.push(["remaining", [`${days(derived.daysRemaining)}, ${fractionUsed(derived.lifetimeFraction)}`]]);
    fields.push(["key", [keyText(key)]]);
    fields.push(["issuer", [`${nameOf(certificate.issuer)}  ${relation(certificate)}`]]);
    if (verbose) fields.push(["issuer dn", [safe(certificate.issuer.dn)]]);

    fields.push(["sha256", [certificate.sha256]]);
    if (verbose) fields.push(["key sha256", [certificate.spkiSha256]]);

    return fields.flatMap(([label, values]) =>
        values.map((value, position) => `  ${(position === 0 ? label : "").padEnd(12)}${value}`),
    );
}

/** @param {{ cn: string | null, dn: string }} name */
function nameOf({ cn, dn }) {
    if (cn !== null) return safe(cn);
    return dn === "" ? "(empty name)" : safe(dn);
}

/**
 * How a certificate relates to the others in its material.
 * @param {Certificate} certificate
 */
function relation({ index, selfSigned, issuedBy }) {
    const signers = issuedBy.filter((position) => position !== index).map((position) => `[${position}]`);
    const parts = [];
    if (selfSigned) parts.push("self-signed");
    if (signers.length > 0) parts.push(`issued by ${signers.join(", ")}`);
    return `(${parts.length > 0 ? parts.join(", ") : "issuer not in the material"})`;
}

/**
 * `null` means the extension is absent, which restricts nothing; an empty list means it is
 * present and allows nothing. The two are not the same, so they are told apart.
 * @param {string[] | null} usages
 * @param {boolean} verbose
 */
function usages(usages, verbose) {
    if (usages === null) return "absent (no restriction)";
    if (usages.length === 0) return "empty";
    return usages
        .map((usage) => (verbose && Object.hasOwn(EXTENDED_KEY_USAGE_OIDS, usage) ? `${usage} (${EXTENDED_KEY_USAGE_OIDS[/** @type {keyof typeof EXTENDED_KEY_USAGE_OIDS} */ (usage)]})` : safe(usage)))
        .join(", ");
}

/** @param {number} value */
function days(value) {
    return `${value} ${Math.abs(value) === 1 ? "day" : "days"}`;
}

/**
 * The fraction as the percentage a person would type for a threshold. It has two decimals, so
 * rounding only removes the binary error of multiplying by a hundred.
 * @param {number | null} fraction
 */
function fractionUsed(fraction) {
    return fraction === null ? "no lifetime to measure" : `${Math.round(fraction * 100)}% of the lifetime used`;
}

/** @param {Certificate["key"]} key */
function keyText({ algorithm, size, curve }) {
    return `${safe(algorithm ?? "unknown")}${curve === null ? "" : ` ${safe(curve)}`}${size === null ? "" : ` (${size} bits)`}`;
}
