import { evaluate, outsideValidity, PolicyError, policyProblems, serializeCheckResult } from "../src/index.js";
import {
    COLOUR_NOTE,
    colourOn,
    misuseOf,
    observe,
    painter,
    parseFlags,
    readInput,
    warningLines,
} from "./command.js";
import {
    ASKED,
    FLAGS,
    askedEntries,
    conflicts,
    entriesOf,
    flagProblems,
    inactiveCodes,
    mergePolicy,
    percentProblem,
    problemCount,
    problemLines,
    warnTargets,
} from "./policy-flags.js";
import { KEY_OPTIONS, keyRequestOf, readKey } from "./private-key.js";
import { safe } from "./safe.js";

/** @import { CheckResult } from "../src/index.js" */
/** @import { Context } from "./command.js" */

// The command decides nothing. The flags and the policy file make a policy, `policyProblems` says
// whether it is acceptable, `evaluate` applies it, and the command prints what comes back and exits
// from it: a rule that does not hold is a result with status `fail`, never an error of the command.

/** The flags of `certdrift check`. */
export const CHECK_OPTIONS = /** @type {const} */ ({
    // Lists, so that a repeated flag can be refused where it takes one value: parseArgs would
    // silently keep the last one. The requirement flags are one row each in `FLAGS`.
    "expect-eku": { type: "string", multiple: true },
    "eku-allows": { type: "string", multiple: true },
    "reject-eku": { type: "string", multiple: true },
    "expect-san": { type: "string", multiple: true },
    "expect-fingerprint": { type: "string", multiple: true },
    "expires-within": { type: "string", multiple: true },
    "lifetime-used": { type: "string", multiple: true },
    "warn-only": { type: "string", multiple: true },
    policy: { type: "string", multiple: true },
    "as-of": { type: "string", multiple: true },
    select: { type: "string", multiple: true },
    // --key and --key-passphrase-env, defined once for every command that takes a key.
    ...KEY_OPTIONS,
    json: { type: "boolean" },
    quiet: { type: "boolean", short: "q" },
    help: { type: "boolean", short: "h" },
});

/** The flags that take one value: given twice, they are misuse, in the order they are checked. */
const ONE_VALUE = /** @type {const} */ (["expect-fingerprint", "expires-within", "lifetime-used", "policy", "as-of", "select", "key", "key-passphrase-env"]);

export const CHECK_USAGE = "Usage: certdrift check [requirements] [--key <file> [--key-passphrase-env <VAR>]] [--policy <file>] [--as-of <date>] [--select <sha256>] [--json | --quiet] <path | ->";

export const CHECK_HELP = `certdrift check decides whether a certificate meets requirements.

${CHECK_USAGE}

Reads one certificate or a bundle, as PEM or DER, from a file, or from standard input when the
path is "-", as certdrift inspect does. Applies the requirements, given as options or as a policy
file, and prints one result for each: OK, WARN or FAIL, the name of the rule, the reason code and
a message. Exits 1 when any result fails.

Requirements, which make the policy (each adds one rule; the validity of the certificate is
always checked):
  --expect-eku <name|OID>        The certificate lists the usage. Repeatable.
  --eku-allows <name|OID>        The certificate lists the usage or has no Extended Key Usage
                                 extension. Repeatable.
  --reject-eku <name|OID>        The certificate does not list the usage. Repeatable.
  --expect-san <name|address>    The certificate lists the DNS name or the IP address. Repeatable.
  --expect-fingerprint <sha256>  The certificate has this SHA-256. Upper case and pairs separated
                                 by colons, as openssl prints them, are accepted.
  --expires-within <Nd|Nh>       At least this many days (30d) or hours (72h) of validity are left.
  --lifetime-used <N%>           No more than this percentage of the validity has gone: 66% or
                                 66.3%, from 0% to 100%.

Private key (adds the rule matchesPrivateKey, which says whether the key is the certificate's):
  --key <file>                  The private key, a PEM file. The result is OK when it belongs to the
                                certificate and FAIL when it is another key (KEY_MISMATCH) or the
                                file holds no readable private key (KEY_UNREADABLE, with the reason).
                                The severity is fail, or the one the policy file gives
                                matchesPrivateKey. --warn-only KEY_MISMATCH and --warn-only
                                KEY_UNREADABLE soften it. The key is never printed.
  --key-passphrase-env <VAR>    The passphrase of an encrypted key is the value of this environment
                                variable, exactly as it is (an empty variable is an empty
                                passphrase). A variable that is not defined is misuse, and so is
                                this option without --key.
  No option takes the passphrase itself, on purpose: a command line is shown to every user of the
  machine by the list of processes, and an environment is not. Set the variable without typing the
  passphrase in the command, for example with: read -rs KEY_PASSPHRASE && export KEY_PASSPHRASE

Options:
  --policy <file>       Read the requirements from a policy file, JSON with "contract": 1. The
                        options above add to it. An option that gives an entry the file already has
                        is misuse. "-" reads the policy from standard input.
  --warn-only <code>    Report a failure of the rule that gives this reason code as WARN, which does
                        not make the check fail. Repeatable. The rule has to be part of the run: a
                        code that does not exist, or whose rule is not checked, is misuse. EXPIRED
                        and NOT_YET_VALID always are.
  --as-of <date>        Check at this instant, not now: YYYY-MM-DD (that day at 00:00:00 UTC) or a
                        timestamp such as 2026-03-01T00:00:00Z. The output says the instant used.
  --select <sha256>     Choose the certificate when a bundle has several that could be the one it
                        is about. A prefix of its sha256 is enough if it is unique.
  --json                Print the check result as JSON and nothing else on standard output.
  -q, --quiet           Print nothing. The exit code still says what happened.
  -h, --help            Print this text.

With no requirement option, no --key and no --policy there is nothing to check, which is misuse.
--warn-only and --as-of alone do not count. A policy that lists matchesPrivateKey needs --key. A
policy with only "contract" is something to check, and says so with a POLICY_EMPTY warning.

    certdrift check --expect-san api.example.com --expires-within 30d server.pem
    certdrift check --policy policy.json --warn-only LIFETIME_USED_EXCEEDED server.pem
    certdrift check --key server.key --key-passphrase-env KEY_PASSPHRASE --expect-san api.example.com server.pem

${COLOUR_NOTE}

Exit codes:
  0  No result failed. A result that is a warning does not fail the check.
  1  A check failed: at least one result is FAIL. A key that is not the certificate's, or that
     cannot be read as a private key, is one.
  2  Misuse, a policy that is not valid (one that lists matchesPrivateKey with no --key is not), or
     a bundle whose certificate is ambiguous (the candidates are listed).
  3  The certificate, the key file or the policy file is missing or unreadable, the policy file is
     not JSON, or the material is not a certificate.
  4  The command crashed: an error it did not expect, which is a bug. The error is printed on
     standard error as it is, even with --quiet.
`;

/**
 * The instant `--as-of` stands for, as the timestamp text `evaluate` takes as `now`. A date is that
 * day at midnight UTC. Whether the text is an instant at all is the library's to say: its own
 * function is asked, so there is no second copy of the rule here.
 * @param {string} text
 * @returns {{ now: string } | { problem: string }}
 */
export function nowOf(text) {
    const now = /^\d{4}-\d\d-\d\d$/.test(text) ? `${text}T00:00:00Z` : text;
    try {
        outsideValidity(now, now, now);
    } catch (error) {
        if (error instanceof TypeError) return { problem: `--as-of needs a date such as 2026-03-01 or a timestamp such as 2026-03-01T00:00:00Z, and got ${JSON.stringify(text)}` };
        throw error;
    }
    return { now };
}

/**
 * The exit code of a check result: 1 when a result failed.
 * @param {CheckResult} result
 */
export function exitOf(result) {
    return result.summary.fail > 0 ? 1 : 0;
}

const LABELS = /** @type {const} */ ({ pass: ["OK", "green"], warn: ["WARN", "yellow"], fail: ["FAIL", "red"] });

/**
 * The readable text of a check result: the name of what was checked and the instant, one line for
 * each result, the observation's warnings and last the number of failures and the exit code. Text
 * that comes from a certificate or a file is escaped.
 * @param {CheckResult} result
 * @param {{ described: string, colour: boolean }} options
 */
export function presentCheck(result, { described, colour }) {
    const paint = painter(colour);
    const rows = result.results.map(({ status, rule, code, message }) => ({
        status,
        name: rule === null ? "-" : safe(rule.name),
        code: safe(code),
        message: safe(message),
    }));
    const widest = (/** @type {"name" | "code"} */ key) => rows.reduce((width, row) => Math.max(width, row[key].length), 0);
    const [nameWidth, codeWidth] = [widest("name"), widest("code")];

    const lines = [`${paint("bold", safe(described))}  checked at ${safe(result.now)}`];
    for (const row of rows) {
        const [label, format] = LABELS[row.status];
        lines.push(`  ${paint(format, label.padEnd(4))}  ${row.name.padEnd(nameWidth)}  ${row.code.padEnd(codeWidth)}  ${row.message}`);
    }
    // The observation's own warnings, so that a rule that passes never hides what was said about
    // the certificate it passed on: the kind of a certificate may be misread, and the rule on it
    // would otherwise say OK in silence.
    const warnings = warningLines(result.observation.warnings, paint);
    if (warnings.length > 0) lines.push("", ...warnings);
    lines.push("", `${result.summary.fail} failed · exit ${exitOf(result)}`);
    return `${lines.join("\n")}\n`;
}

/**
 * Runs `certdrift check`. Misuse is reported before anything is read; reading comes in the order
 * the policy file, the private key, then the material.
 * @param {string[]} args The arguments after `check`.
 * @param {Context} context
 * @returns {Promise<number>}
 */
export async function checkCommand(args, { env, stdin, out, err }) {
    const misuse = misuseOf(err, CHECK_USAGE, "Run certdrift check --help for the options.");

    const parsed = parseFlags(args, CHECK_OPTIONS);
    if ("misuse" in parsed) return misuse(parsed.misuse);
    const { values, positionals } = parsed;
    if (values.help) {
        out(CHECK_HELP);
        return 0;
    }
    for (const flag of ONE_VALUE) {
        if ((values[flag]?.length ?? 0) > 1) return misuse(`--${flag} was given more than once`);
    }
    if (positionals.length === 0) return misuse('no path given; use "-" to read standard input');
    if (positionals.length > 1) return misuse(`expected one path, got ${positionals.length}`);
    const [path] = positionals;
    const select = values.select?.[0];
    if (select === "") return misuse("--select needs the start of a sha256, and it is empty");
    const policyPath = values.policy?.[0];
    if (policyPath === "-" && path === "-") return misuse("--policy - and the path - both read standard input, which can be read once");
    const keyAsked = keyRequestOf(values, env);
    if ("misuse" in keyAsked) return misuse(keyAsked.misuse);
    const { request: keyRequest } = keyAsked;

    // The instant is checked before anything is read, as the typed forms are, so that a typo is
    // misuse whatever the files hold and never waits on standard input.
    /** @type {string | undefined} */
    let now;
    if (values["as-of"] !== undefined) {
        const asked = nowOf(values["as-of"][0]);
        if ("problem" in asked) return misuse(asked.problem);
        now = asked.now;
    }
    for (const text of values["lifetime-used"] ?? []) {
        const problem = percentProblem(text);
        if (problem !== null) return misuse(`--lifetime-used ${problem}, and got ${JSON.stringify(text)}`);
    }
    if ([...FLAGS, ...ASKED].every(({ flag }) => /** @type {Record<string, unknown>} */ (values)[flag] === undefined) && policyPath === undefined) {
        return misuse("nothing to check: give a requirement option or --policy");
    }

    const bad = flagProblems(values);
    if (bad.length > 0) return misuse(`the requirement options are not valid: ${bad.length} problem${bad.length === 1 ? "" : "s"}`, bad);
    const entries = entriesOf(values);
    const targets = warnTargets(values["warn-only"] ?? []);
    if (targets.unknown.length > 0) {
        return misuse("--warn-only needs the reason code of a rule that has a severity", targets.unknown.map((code) => `${JSON.stringify(code)} is not one`));
    }

    /** @type {Record<string, unknown>} */
    let file = { contract: 1 };
    let policyDescribed = "the policy";
    if (policyPath !== undefined) {
        const read = await readInput(policyPath, stdin);
        if ("code" in read) {
            err(read.message);
            return read.code;
        }
        policyDescribed = read.described;
        const parsedFile = jsonOf(read.bytes);
        if (parsedFile === undefined) {
            err(`certdrift: ${safe(read.described)}: the policy is not valid JSON\n`);
            return 3;
        }
        const problems = policyProblems(parsedFile.value);
        if (problems.length > 0) return misuse(`${read.described}: ${problemCount(problems)}`, problemLines(problems));
        file = /** @type {Record<string, unknown>} */ (parsedFile.value);
    }
    const clash = conflicts(file, entries);
    if (clash.length > 0) return misuse(`${policyDescribed}: the options and the policy file give the same entry`, clash);
    const present = [...Object.keys(entries), ...Object.keys(file), ...askedEntries(values)];
    const inactive = inactiveCodes(targets.entries, present);
    if (inactive.length > 0) return misuse("--warn-only names a rule this run does not check", inactive);
    const policy = mergePolicy(file, entries, new Set(targets.entries.values()));

    // The key is read after the policy file and before the material, so that every file an option
    // names is read before the certificate, and a missing key never waits on standard input.
    /** @type {import("../src/index.js").PrivateKey | undefined} */
    let privateKey;
    if (keyRequest !== undefined) {
        const key = await readKey(keyRequest.path);
        if ("code" in key) {
            err(key.message);
            return key.code;
        }
        privateKey = { material: key.material, passphrase: keyRequest.passphrase };
    }

    const read = await readInput(path, stdin);
    if ("code" in read) {
        err(read.message);
        return read.code;
    }
    const source = path === "-" ? { kind: "stdin", ref: "-" } : { kind: "file", ref: path };
    const observed = observe(read.bytes, { source, ...(select === undefined ? {} : { select }) }, read.described);
    if (!("observation" in observed)) {
        err(observed.message);
        return observed.code;
    }

    /** @type {CheckResult} */
    let result;
    try {
        result = evaluate(observed.observation, /** @type {import("../src/index.js").Policy} */ (policy), { now, privateKey });
    } catch (error) {
        // Only the policy is misuse. A `TypeError` here means this command built a wrong call, which
        // is a bug, and it must show as one.
        if (error instanceof PolicyError) return misuse(policyPath === undefined ? error.message : `${policyDescribed}: ${error.message}`, problemLines(error.problems));
        throw error;
    }

    if (values.json) out(serializeCheckResult(result));
    else out(presentCheck(result, { described: read.described, colour: colourOn(env) }));
    return exitOf(result);
}

/**
 * What a policy file holds as JSON, or `undefined` when it is not UTF-8 text or not JSON. One byte
 * order mark at the start is ignored. The message of the parser quotes the file, so nothing of it
 * is kept.
 * @param {Uint8Array} bytes
 * @returns {{ value: unknown } | undefined}
 */
function jsonOf(bytes) {
    try {
        return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) };
    } catch (error) {
        const code = error instanceof Error && "code" in error ? error.code : undefined;
        if (error instanceof SyntaxError || code === "ERR_ENCODING_INVALID_ENCODED_DATA") return undefined;
        throw error;
    }
}
