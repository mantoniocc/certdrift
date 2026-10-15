import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { AmbiguousTargetError, inspect } from "../../src/index.js";
import { main } from "../../bin/cli.js";

// Running the command the way the tests of `certdrift check` need: as a child process, the way a
// person runs it, so that the real streams and the exit code are part of what is tested, and in this
// process, for the cases that run it many times.

const root = new URL("../../", import.meta.url);

/** The directory the command is run in: the repository, where `test/fixtures/...` is a path. */
export const CWD = new URL(root).pathname;
const BIN = new URL("bin/certdrift.js", root).pathname;

/** @param {string} name File name in test/fixtures/. */
export function fixture(name) {
    return readFileSync(new URL(`test/fixtures/${name}`, root));
}

/** The path of a fixture as someone in the repository would type it. @param {string} name */
export const typed = (name) => `test/fixtures/${name}`;

/**
 * @typedef {object} Result
 * @property {number | null} code
 * @property {string} stdout
 * @property {string} stderr
 */

/**
 * @typedef {object} RunOptions
 * @property {Uint8Array | string} [input] Written to standard input, which is then closed.
 * @property {boolean} [openStdin] Leaves standard input open and never writes to it.
 * @property {Record<string, string | undefined>} [env] Added to a minimal environment; `undefined` removes a key.
 * @property {string} [cwd]
 * @property {string[]} [nodeArguments] Placed before the script, e.g. `--import`.
 * @property {string} [script] The executable to run, when it is not this repository's.
 * @property {number} [killAfterMs] Kills the command after this long, so that one that does not end fails its test instead of holding the run.
 */

/**
 * Runs the command. The environment is minimal and has NO_COLOR set unless a test says otherwise,
 * so that nothing inherited from the machine changes the output.
 * @param {string[]} args
 * @param {RunOptions} [options]
 * @returns {Promise<Result>}
 */
export function run(args, { input, openStdin, env = {}, cwd = CWD, nodeArguments = [], script = BIN, killAfterMs = 30_000 } = {}) {
    /** @type {Record<string, string | undefined>} */
    const merged = { PATH: process.env.PATH, NO_COLOR: "1", ...env };
    for (const key of Object.keys(merged)) if (merged[key] === undefined) delete merged[key];

    const child = spawn(process.execPath, [...nodeArguments, script, ...args], {
        cwd,
        env: /** @type {Record<string, string>} */ (merged),
        stdio: [input === undefined && !openStdin ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const { stdout, stderr } = child;
    if (stdout === null || stderr === null) throw new Error("the child has no output streams");
    const killer = setTimeout(() => child.kill("SIGKILL"), killAfterMs);
    if (input !== undefined) child.stdin?.end(input);

    return new Promise((resolve, reject) => {
        /** @type {Buffer[]} */ const out = [];
        /** @type {Buffer[]} */ const err = [];
        stdout.on("data", (chunk) => out.push(chunk));
        stderr.on("data", (chunk) => err.push(chunk));
        child.stdin?.on("error", () => {});
        child.on("error", reject);
        child.on("close", (code) => {
            child.stdin?.destroy();
            clearTimeout(killer);
            resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
        });
    });
}

/**
 * Runs `main()` in this process, with standard input made of `input` and no colour.
 * @param {string[]} args
 * @param {{ input?: Uint8Array | string, env?: Record<string, string | undefined> }} [options]
 * @returns {Promise<Result>}
 */
export async function runMain(args, { input = "", env = { NO_COLOR: "1" } } = {}) {
    let stdout = "";
    let stderr = "";
    const code = await main(args, {
        env,
        stdin: (async function* () { yield input; })(),
        stdout: { write: (text) => (stdout += text), on() {} },
        stderr: { write: (text) => (stderr += text), on() {} },
    });
    return { code, stdout, stderr };
}

/**
 * The target of a fixture as the library reads it, with a bundle that is ambiguous resolved by a
 * prefix of its first candidate, and the arguments that make the command do the same.
 * @param {string} name
 * @returns {{ certificate: ReturnType<typeof inspect>["certificates"][number], select: string[] }}
 */
export function targetOf(name) {
    const bytes = fixture(name);
    /** @type {string[]} */
    let select = [];
    /** @type {ReturnType<typeof inspect>} */
    let observation;
    try {
        observation = inspect(bytes);
    } catch (error) {
        if (!(error instanceof AmbiguousTargetError)) throw error;
        select = ["--select", error.candidates[0].sha256.slice(0, 16)];
        observation = inspect(bytes, { select: select[1] });
    }
    return { certificate: observation.certificates[observation.target], select };
}
