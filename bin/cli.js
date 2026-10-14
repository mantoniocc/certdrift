import { readFile } from "node:fs/promises";
import { parseArgs, styleText } from "node:util";
import {
    inspect,
    serializeObservation,
    ParseError,
    AmbiguousTargetError,
    EXTENDED_KEY_USAGE_OIDS,
    outsideValidity,
} from "../src/index.js";
import { HOST_OPTIONS, fetchHost, hostRequestOf, refusalOf } from "./host.js";
import { PathSyntaxError, labelOf, parsePath, printable, undeclaredAt, valueAt } from "./query.js";
import { safe } from "./safe.js";

/** @import { Source } from "../src/index.js" */

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
    // A list for the same reason as `select`.
    query: { type: "string", multiple: true },
    // --host, --servername and --timeout, defined once for every command that takes a host.
    ...HOST_OPTIONS,
    help: { type: "boolean", short: "h" },
});

/**
 * The schema of the document this command prints, and the name its messages give it. It is read
 * from the package, next to this file, and never from the working directory: the command must
 * answer the same from any directory and once the package is installed elsewhere.
 */
const OBSERVATION_SCHEMA = { name: "observation", url: new URL("../schema/observation.schema.json", import.meta.url) };

const USAGE = `Usage: certdrift inspect [--json | --verbose | --quiet | --query <path>] [--select <sha256>] <path | ->
       certdrift inspect [same options] [--servername <name>] [--timeout <ms>] --host <host[:port]>`;

// PENDING: name `certdrift check` once that command exists
// The help says "the checking command" until then, because naming a command that can not be run
// yet would send people to something that fails.

const HELP = `certdrift inspects X.509 certificates.

${USAGE}

Reads one certificate or a bundle, as PEM or DER, from a file, or from standard input when the
path is "-". With --host it reads the certificates a server sends instead. Prints the certificate
the material is about, with the rest of its chain.

Options:
  --json                Print the observation as JSON and nothing else on standard output.
  -v, --verbose         Add the full names, the serial, the public key fingerprint, the OIDs
                        beside the usage names and the detail of every certificate in the chain.
  -q, --quiet           Print nothing. The exit code still says what happened.
  --query <path>        Print one value of the observation, not the whole of it. See below.
  --select <sha256>     Choose the certificate when a bundle has several that could be the one it
                        is about. A prefix of its sha256 is enough if it is unique.
  --host <host[:port]>  Inspect the certificates a server sends, not a file. See below.
  --servername <name>   The server name to send in the handshake. Only with --host.
  --timeout <ms>        The longest to wait for the host, in milliseconds. Only with --host.
  -h, --help            Print this text.

Inspecting a server:
  --host connects over TLS and prints what the server sends as it prints a file. The host is
  a name or an address, with the port after a colon (443 unless given). An IPv6 address is
  written in brackets, and the argument quoted because a shell reads brackets as a pattern:

    certdrift inspect --host api.example.com:443
    certdrift inspect --host '[2001:db8::1]:443' --servername api.example.com

  The host is always given with --host. A path is always a file, whatever it looks like, so
  --host takes no path and no "-", and does not read standard input.

  The certificates are exactly the ones the server sent, in the order it sent them. Nothing is
  added from this machine's trust store, and nothing says whether this machine would trust them.

  --servername is the name sent in the handshake, which decides the certificate a server picks.
  It is the host name unless given, and an IP address sends none unless it is given.
  --timeout is the longest the whole attempt may take, as a positive whole number of
  milliseconds. It is 10000 unless given.

Extracting a value:
  To extract a value, use --query. To make a decision, use the checking command: --query only
  reads, and a value that is missing is not a failure of the certificate.

    certdrift inspect --query 'certificates[0].notAfter' server.pem

  A path is field names separated by dots, and numeric indices in square brackets. Nothing
  else: no filters, functions or expressions. Quote it, because a shell reads square brackets as
  a pattern.

  A string prints without quotes. A number, true, false and null print as JSON, and an array or
  an object as compact JSON on one line.

  The path is checked against the observation's schema before anything is read. A path the
  schema does not declare, such as a typo, exits 2 and prints nothing on standard output. A path
  it declares that has no value in this observation, such as an index past the end of a list,
  exits 0 and prints nothing on standard output, with a note on standard error.

  The contract tolerates fields it does not declare, so an observation may hold one. A field the
  contract tolerates but the schema does not declare does not exist for --query.

The output is coloured unless the NO_COLOR environment variable is set to a non-empty value.
Nothing else, such as whether a terminal is attached, changes it.

Exit codes:
  0  Success.
  2  Misuse, a --query path the schema does not declare, or a bundle whose certificate is
     ambiguous (the candidates are listed).
  3  The file is missing or unreadable, the material is not a certificate, or the host cannot be
     reached, refuses the connection, does not speak TLS or does not answer in time.
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
    const asked = hostRequestOf(values, { pathGiven: positionals.length > 0 });
    if ("misuse" in asked) return misuse(asked.misuse);
    const { request } = asked;
    if (request === undefined) {
        if (positionals.length === 0) return misuse('no path given; use "-" to read standard input, or --host to inspect a server');
        if (positionals.length > 1) return misuse(`expected one path, got ${positionals.length}`);
    }
    if (values.select !== undefined && values.select.length > 1) return misuse("--select was given more than once");
    const select = values.select?.[0];
    if (select === "") return misuse("--select needs the start of a sha256, and it is empty");
    if (values.query !== undefined && values.query.length > 1) return misuse("--query was given more than once");
    const query = values.query?.[0];
    // --query prints one value, so a flag that changes what the whole document looks like has
    // nothing to act on. Taking one over the other without a word would hide the mistake.
    if (query !== undefined && (values.json || values.verbose)) return misuse("--query can not be combined with --json or --verbose");

    // The path is checked before the material is read, so that a typo is a misuse whatever the
    // file holds, and never waits on standard input.
    /** @type {import("./query.js").Step[] | undefined} */
    let steps;
    if (query !== undefined) {
        try {
            steps = parsePath(query);
        } catch (error) {
            if (error instanceof PathSyntaxError) return misuse(`--query: ${error.message}`);
            throw error;
        }
        // A schema that can not be read means a broken installation, which is neither misuse
        // nor bad material, so it is not caught.
        const schema = JSON.parse(await readFile(OBSERVATION_SCHEMA.url, "utf8"));
        const unknown = undeclaredAt(schema, steps);
        if (unknown !== -1) return misuse(`unknown field in ${labelOf(OBSERVATION_SCHEMA.name, schema)}: ${steps[unknown].through}`);
    }

    /** @type {Uint8Array} */
    let material;
    /** @type {Source} */
    let source;
    /** What the messages call the material. */
    let described;
    if (request !== undefined) {
        // The TLS module's check of the arguments comes after every check the command makes itself.
        const refused = await refusalOf(request);
        if (refused !== undefined) return misuse(refused);
        const fetched = await fetchHost(request);
        if (!("chain" in fetched)) {
            err(fetched.message);
            return fetched.code;
        }
        ({ bytes: material, source } = fetched.chain);
        described = source.ref ?? request.target;
    } else {
        const [path] = positionals;
        source = path === "-" ? { kind: "stdin", ref: "-" } : { kind: "file", ref: path };
        described = path === "-" ? "standard input" : path;
        try {
            material = path === "-" ? await readAll(stdin) : await readFile(path);
        } catch (error) {
            if (error instanceof Error && "code" in error) {
                err(`certdrift: cannot read ${safe(described)}: ${safe(error.message)}\n`);
                return 3;
            }
            throw error;
        }
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

    if (steps !== undefined) {
        // The value comes from the document --json prints, so the two can not disagree.
        const found = valueAt(JSON.parse(serializeObservation(observation)), steps);
        if (found.found) out(printable(found.value));
        else err(`certdrift: no value for ${safe(query ?? "")}: ${safe(found.reason)}\n`);
    } else if (values.json) out(serializeObservation(observation));
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
 * The readable text of an observation. Every value is the observation's own, and the only thing
 * said about a certificate's validity is the label on the target's `remaining` line, which
 * `outsideValidity` decides from the dates and the observation's instant.
 * @param {Observation} observation
 * @param {{ verbose: boolean, colour: boolean }} options
 */
export function present(observation, { verbose, colour }) {
    /** @param {Parameters<typeof styleText>[0]} format @param {string} text */
    const paint = (format, text) => (colour ? styleText(format, text, { validateStream: false }) : text);
    const { certificates, target, warnings } = observation;
    const { at } = observation.observation;
    // Only the target is labelled. A server often keeps sending a cross-signed root that expired
    // years ago and clients ignore it, so a label on the rest of the chain would raise an alarm
    // over something that is not wrong.
    const { notBefore, notAfter } = certificates[target];
    const lines = [paint("bold", "Target"), ...block(certificates[target], verbose, outsideValidity(notBefore, notAfter, at))];

    const others = certificates.filter((certificate) => certificate.index !== target);
    if (others.length > 0) {
        lines.push("", paint("bold", "Chain"));
        for (const certificate of others) {
            if (verbose) lines.push(...block(certificate, true, []), "");
            else lines.push(`  [${certificate.index}] ${certificate.kind}  ${nameOf(certificate.subject)}  ${relation(certificate)}  until ${certificate.notAfter}, ${timeRemaining(certificate)}  ${certificate.sha256}`);
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
 * @param {("not yet valid" | "expired")[]} outside What `outsideValidity` found for this
 *   certificate, which the `remaining` line ends with, in parentheses, as plain text. The
 *   chain's certificates are given none.
 */
function block(certificate, verbose, outside) {
    const { key, san } = certificate;
    /** @type {[string, string[]][]} */
    const fields = [["certificate", [`[${certificate.index}] ${certificate.kind}  ${nameOf(certificate.subject)}`]]];
    if (verbose) fields.push(["subject", [safe(certificate.subject.dn)]], ["serial", [certificate.serial]]);

    const names = /** @type {const} */ (["dns", "ip", "email", "uri"])
        .filter((type) => san[type].length > 0)
        .map((type) => `${type}: ${san[type].map(safe).join(", ")}`);
    fields.push(["san", names.length > 0 ? names : ["none"]]);
    fields.push(["eku", [usages(certificate.eku, verbose)]]);

    fields.push(["validity", [`${certificate.notBefore} to ${certificate.notAfter}`]]);
    fields.push(["remaining", [outside.length === 0 ? timeRemaining(certificate) : `${timeRemaining(certificate)} (${outside.join(", ")})`]]);
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

/**
 * The text that says how much of a certificate's validity is left, for the target and for every
 * line of the chain, so that its wording is the same wherever it appears.
 *
 * It reads only `derived`, which is rounded: a certificate that expired an hour ago reads
 * `0 days`, the same as one that expires in an hour. It therefore says nothing about whether the
 * validity has ended. That is `outsideValidity`, from the dates, and its label is not added here
 * because the lines of the chain use this text too and are never labelled.
 * @param {Pick<Certificate, "derived">} validity
 */
export function timeRemaining({ derived }) {
    return `${days(derived.daysRemaining)}, ${fractionUsed(derived.lifetimeFraction)}`;
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
