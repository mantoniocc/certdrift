import { POLICY_ENTRIES, PolicyError, entryOfCode, policyProblems } from "../src/index.js";

/** @import { PolicyProblem } from "../src/index.js" */

// The requirement flags of a command, turned into entries of a policy, and the policy of a file
// and the flags put together. Nothing here decides whether a rule holds, and nothing restates what a
// rule accepts: `policyProblems` says whether a value is acceptable, and this only turns the text
// someone typed into the value the policy holds (the percentage, the case and the colons of a
// fingerprint) and says which flag a problem belongs to. A command that takes more requirement
// flags adds a row to `FLAGS`.

/**
 * @typedef {object} Flag
 * @property {string} flag The name without the dashes.
 * @property {string} entry The entry of the policy it builds.
 * @property {boolean} [list] It can be repeated and gives a list of values; otherwise it takes one.
 * @property {(text: string) => unknown} [convert] Typed text to the value of the entry.
 */

/** @type {readonly Flag[]} */
export const FLAGS = [
    { flag: "expect-eku", entry: "expectEku", list: true },
    { flag: "eku-allows", entry: "ekuAllows", list: true },
    { flag: "reject-eku", entry: "rejectEku", list: true },
    { flag: "expect-san", entry: "expectSan", list: true },
    { flag: "expect-fingerprint", entry: "expectFingerprint", convert: fingerprintOf },
    { flag: "expires-within", entry: "expiresWithin" },
    { flag: "lifetime-used", entry: "maxLifetimeUsed", convert: fractionOf },
];

/**
 * The options that ask for an entry without building its value from their text. The entry is
 * evaluated whenever the option is given, whether the policy lists it or not, and the policy file
 * is still where its severity is set, so such an option never conflicts with the file.
 * @type {readonly { flag: string, entry: string }[]}
 */
export const ASKED = [{ flag: "key", entry: "matchesPrivateKey" }];

/**
 * The options that give an entry whose value the command reads from a file, not from the text of
 * the option. They are not rows of `FLAGS`, which build their value from the text and give each
 * entry to one flag, and they conflict like any flag that gives the entry.
 * @type {readonly { flag: string, entry: string }[]}
 */
export const FROM_FILE = [{ flag: "expect-fingerprint-of", entry: "expectFingerprint" }];

/**
 * The options of `FROM_FILE` that were given.
 * @param {Readonly<Record<string, unknown>>} given What `parseArgs` read.
 */
export function fromFileGiven(given) {
    return FROM_FILE.filter(({ flag }) => given[flag] !== undefined);
}

/**
 * The options that give an entry another option gives too. Two of them would fill one rule, and
 * neither is the one meant, so each pair is refused.
 * @param {Readonly<Record<string, unknown>>} given What `parseArgs` read.
 * @returns {string[]} One line for each entry that has more than one option.
 */
export function sameEntry(given) {
    const rows = [...FLAGS, ...FROM_FILE].filter(({ flag }) => given[flag] !== undefined);
    return [...new Set(rows.map(({ entry }) => entry))].flatMap((entry) => {
        const flags = rows.filter((row) => row.entry === entry).map(({ flag }) => `--${flag}`);
        return flags.length > 1 ? [`${flags.join(" and ")} both give ${entry}: give only one of them`] : [];
    });
}

/**
 * The entries the options ask for, among the ones that were given.
 * @param {Readonly<Record<string, unknown>>} given What `parseArgs` read.
 * @returns {string[]}
 */
export function askedEntries(given) {
    return ASKED.filter(({ flag }) => given[flag] !== undefined).map(({ entry }) => entry);
}

/**
 * The entries every run has, whether the policy lists them or not. `evaluate` always runs them
 * and a test keeps this list in step with it.
 */
export const ALWAYS_ENTRIES = ["validityStarted", "validityNotEnded"];

/** A percentage as typed: digits, optionally a point and digits, then `%`. */
const PERCENT = /^(\d+)(?:\.(\d+))?%$/;

/**
 * Why a percentage as typed cannot be read, or `null`. Only its form: whether the number it makes
 * is acceptable is for the policy to say.
 * @param {string} text
 * @returns {string | null}
 */
export function percentProblem(text) {
    return PERCENT.test(text) ? null : "needs a percentage such as 66% or 66.3%";
}

/**
 * The fraction a percentage stands for, built from the digits of the text and not by dividing:
 * `66.3 / 100` is not `0.663` in floating point, and moving the decimal point in the text and
 * reading it is. Text that is not a percentage is given back unchanged, for the policy to refuse.
 * @param {string} text
 * @returns {unknown}
 */
export function fractionOf(text) {
    const match = PERCENT.exec(text);
    if (match === null) return text;
    const [, whole, fraction = ""] = match;
    const digits = whole + fraction;
    const point = whole.length - 2;
    return Number(point <= 0 ? `0.${"0".repeat(-point)}${digits}` : `${digits.slice(0, point)}.${digits.slice(point)}`);
}

/**
 * A fingerprint the way `openssl` prints it, with upper case and pairs joined by colons, as the 64
 * lower case hexadecimal characters the policy wants. A colon is taken out only between pairs: any
 * other text is given back, with its letters lowered, for the policy to refuse.
 * @param {string} text
 * @returns {unknown}
 */
export function fingerprintOf(text) {
    const joined = /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+$/.test(text) ? text.replaceAll(":", "") : text;
    return joined.replace(/[A-F]/g, (letter) => letter.toLowerCase());
}

/**
 * @param {Readonly<Record<string, unknown>>} given
 * @param {string} flag
 * @returns {string[] | undefined}
 */
function textsOf(given, flag) {
    return /** @type {string[] | undefined} */ (given[flag]);
}

/**
 * The entries the flags build, each as `{ value }`. A flag that was not given builds nothing.
 * @param {Readonly<Record<string, unknown>>} given What `parseArgs` read: the values of each flag, as lists.
 * @returns {Record<string, { value: unknown }>}
 */
export function entriesOf(given) {
    /** @type {Record<string, { value: unknown }>} */
    const entries = {};
    for (const { flag, entry, list, convert } of FLAGS) {
        const texts = textsOf(given, flag);
        if (texts === undefined) continue;
        entries[entry] = { value: list === true ? [...texts] : (convert ?? String)(texts[0]) };
    }
    return entries;
}

/**
 * What is wrong with the values of the flags, each under the name of the flag and never under a
 * path in a policy. A value of a flag that can be repeated is shown as it was typed, because the
 * person cannot see its position among the others.
 * @param {Readonly<Record<string, unknown>>} given
 * @returns {string[]}
 */
export function flagProblems(given) {
    const entries = entriesOf(given);
    return policyProblems({ contract: 1, ...entries }).flatMap((problem) => {
        const entry = problem.path.split("/")[1];
        // The path of a problem of this policy is always one of its entries, and each entry is a row.
        const row = /** @type {Flag} */ (FLAGS.find((candidate) => candidate.entry === entry));
        const texts = /** @type {string[]} */ (textsOf(given, row.flag));
        if (row.list !== true) return [`--${row.flag}: ${problem.message}`];
        // Each value on its own, so that each bad one is named whatever the others are.
        const bad = texts.filter((text) => policyProblems({ contract: 1, [entry]: { value: [text] } }).length > 0);
        return bad.length === 0 ? [`--${row.flag}: ${problem.message}`] : bad.map((text) => `--${row.flag}: ${JSON.stringify(text)} is not a value this flag accepts`);
    });
}

/** The top-level properties of a policy file that are not entries and are accepted: `$schema` is what editors add to JSON files. */
const NOT_ENTRIES = ["contract", "$schema"];

/**
 * What a policy file has at its top level that this version does not know. The library tolerates it,
 * as the contract says, so that a program that passes its own policy keeps working; a file is typed
 * by a person, and a misspelled entry (`expectSAN`) would otherwise check nothing in silence. A value
 * that is not an object has no entries, and `policyProblems` already says what is wrong with it.
 * Properties inside an entry are not looked at.
 * @param {unknown} policy
 * @returns {PolicyProblem[]}
 */
export function unknownEntries(policy) {
    if (typeof policy !== "object" || policy === null || Array.isArray(policy)) return [];
    const known = new Set([...NOT_ENTRIES, ...POLICY_ENTRIES]);
    return Object.keys(policy)
        .filter((name) => !known.has(name))
        .sort()
        // A JSON Pointer (RFC 6901), as the library writes the path of a problem.
        .map((name) => ({ path: `/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`, message: "is not an entry this version knows" }));
}

/**
 * The problems of a policy as lines: the path, then what is wrong.
 * @param {PolicyProblem[]} problems
 * @returns {string[]}
 */
export function problemLines(problems) {
    return problems.map(({ path, message }) => `${path === "" ? "(the policy)" : path}: ${message}`);
}

/**
 * The count line of a list of problems, in the words of `PolicyError`.
 * @param {PolicyProblem[]} problems
 */
export function problemCount(problems) {
    return new PolicyError(problems).message;
}

/**
 * The entry each `--warn-only` code names, by the library's own answer.
 * @param {readonly string[]} codes
 * @returns {{ entries: Map<string, string>, unknown: string[] }} `unknown` holds the codes that name no entry.
 */
export function warnTargets(codes) {
    /** @type {Map<string, string>} */
    const entries = new Map();
    /** @type {string[]} */
    const unknown = [];
    for (const code of codes) {
        const entry = entryOfCode(code);
        if (entry === null) unknown.push(code);
        else entries.set(code, entry);
    }
    return { entries, unknown };
}

/**
 * The codes whose entry is not part of this run, with what would put it there.
 * @param {Map<string, string>} targets From `warnTargets`.
 * @param {Iterable<string>} present The entries the run has besides the two it always has.
 * @returns {string[]} One line for each.
 */
export function inactiveCodes(targets, present) {
    const run = new Set([...ALWAYS_ENTRIES, ...present]);
    return [...targets].filter(([, entry]) => !run.has(entry)).map(([code, entry]) => {
        const asked = ASKED.find((candidate) => candidate.entry === entry);
        const row = FLAGS.find((candidate) => candidate.entry === entry);
        // An entry that only an option asks for is refused when the file lists it without one.
        const how = asked !== undefined ? `give --${asked.flag}` : row === undefined ? `list ${entry} in the policy` : `give --${row.flag} or list ${entry} in the policy`;
        return `--warn-only: ${code} belongs to ${entry}, which this run does not check: ${how}`;
    });
}

/**
 * The flags that name an entry the policy file already has. A flag never changes a shared policy
 * without anyone seeing it, so each is refused, whatever its value.
 * @param {Readonly<Record<string, unknown>>} file
 * @param {Record<string, { value: unknown }>} entries From `entriesOf`.
 * @param {readonly { flag: string, entry: string }[]} [fromFile] The options of `FROM_FILE` that were
 *   given, whose entries are not in `entries` until their files are read.
 * @returns {string[]} One line for each.
 */
export function conflicts(file, entries, fromFile = []) {
    return [
        ...FLAGS.filter(({ entry }) => Object.hasOwn(entries, entry)),
        ...fromFile,
    ]
        .filter(({ entry }) => Object.hasOwn(file, entry))
        .map(({ flag, entry }) => `--${flag} gives ${entry}, which the policy file has: use --warn-only to soften a rule of the file, or take the entry out of one of them`);
}

/**
 * The policy of a file and of the flags together, with each `--warn-only` entry set to `warn`.
 * Nothing it is given is changed. An entry the policy lacks, such as one of the two validity
 * entries, is created with only its severity.
 * @param {Readonly<Record<string, unknown>>} file The policy file, or `{ contract: 1 }`.
 * @param {Record<string, { value: unknown }>} entries From `entriesOf`.
 * @param {Iterable<string>} soften The entries to set to `warn`.
 * @returns {Record<string, unknown>}
 */
export function mergePolicy(file, entries, soften) {
    // Spread, not assigned: a `__proto__` key of a file is a property like any other here.
    /** @type {Record<string, unknown>} */
    const policy = { ...file, ...entries };
    for (const entry of soften) {
        policy[entry] = { ...(Object.hasOwn(policy, entry) ? /** @type {object} */ (policy[entry]) : {}), severity: "warn" };
    }
    return policy;
}
