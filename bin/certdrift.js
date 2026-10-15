#!/usr/bin/env node
import { inspect } from "node:util";
import { perLine } from "./safe.js";

// An unexpected error is a bug of this tool, and it ends with its own exit code, 4, so that a
// script never takes it for a failed check (1), for misuse (2) or for bad material (3). Nothing is
// turned into a message of the command: the error is printed as it is, and only the code is ours.
//
// Only this file and its two small imports are loaded before the guard is in place. The command is
// imported inside it, so that a file of the package that cannot be loaded is a crash too.

/** Whether a crash has been reported. Only the first is: see `crash`. */
let crashed = false;

/**
 * What to print for a thrown value. A string is quoted, so that a thrown text can never read as one
 * of the command's own messages. This must not throw: a throw inside the handler of an uncaught
 * error ends the process with exit 7 and nothing printed, so a value that cannot be inspected
 * (a custom inspector or a getter on `stack` that throws) is shown as plainly as it can be.
 * @param {unknown} thrown
 */
function describe(thrown) {
    // No depth limit: the default stops two levels down and would drop the deeper causes.
    try {
        return inspect(thrown, { depth: Infinity });
    } catch {
        try {
            return inspect(thrown, { depth: Infinity, customInspect: false });
        } catch {
            return "The thrown value cannot be shown: inspecting it throws too.";
        }
    }
}

/**
 * Reports a crash and sets the exit code. Only the first one counts: when standard error itself is
 * broken, writing the report raises an error that comes back here, and reporting that one too
 * would never stop.
 *
 * It writes to the real standard error and not to the one the command was given, so `--quiet`, which
 * silences what the command chooses to print, does not hide a bug. Everything printed goes through
 * `perLine`, because an error's message or a property can hold text from a certificate.
 * @param {unknown} thrown
 */
function crash(thrown) {
    if (crashed) return;
    crashed = true;
    // Set, not passed to a call that ends the process: that can cut off output still waiting in a pipe.
    process.exitCode = 4;
    process.stderr.write(`${perLine(describe(thrown))}\n`);
    // The command may be waiting for standard input, which a pipe can keep open for as long as its
    // writer lives. Nothing it read after a bug would be used, and the process must end by itself.
    process.stdin.destroy();
}

// What no `try` around `main()` can see: a listener that rethrows (the command installs one on its
// streams) and a promise that is rejected and never awaited. Node.js would end the process with
// exit 1 and its own, unescaped, report. The process still ends by itself, once what it was
// waiting for ends: a crash while connecting keeps it alive until the connection's timeout.
process.on("uncaughtException", crash);

/**
 * A stream as the command sees it, which says nothing once the process has crashed. The command
 * is left running when the error came from outside it, and what it would print after a bug (a host
 * failure, an observation) would be printed after the report as if nothing had happened.
 * @param {NodeJS.WriteStream} stream
 */
function untilCrash(stream) {
    return {
        write: (/** @type {string} */ text) => crashed || stream.write(text),
        on: (/** @type {"error"} */ event, /** @type {(error: Error & { code?: string }) => void} */ listener) => stream.on(event, listener),
    };
}

try {
    const { main } = await import("./cli.js");
    const code = await main(process.argv.slice(2), {
        env: process.env,
        stdin: process.stdin,
        stdout: untilCrash(process.stdout),
        stderr: untilCrash(process.stderr),
    });
    // A crash outside the command may have happened while it ran, and its code is the one that counts.
    if (!crashed) process.exitCode = code;
} catch (error) {
    crash(error);
}
