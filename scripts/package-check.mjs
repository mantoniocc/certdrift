// Packs certdrift, installs the tarball into a directory outside the repository and checks what
// arrives there, because that is what a consumer gets and what the tests, which run against the
// working copy, cannot see: a file missing from the allowlist, a wrong entry point, an executable
// without its permission bit, a relative import that resolves here and not once installed.
//
//   npm run package:check
//
// It is not part of `npm run check`: packing and installing take seconds and `check` is the
// command to run without thinking. CI runs it on pull requests and by hand before a release.
// It runs as a `node:test` file so a failure names the check that broke; the `.mjs` extension
// keeps `npm test`, which only runs `*.test.js`, from picking it up.
//
// Nothing here publishes anything. The install is offline: the package has no dependencies, so the
// tarball is all it needs.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect, serializeObservation } from "../src/index.js";
import { validatorFor } from "../test/helpers/schema.js";
import { expectedContents, holdsPrivateKey } from "./package-contents.mjs";

const root = new URL("../", import.meta.url);
const repository = fileURLToPath(root);
const errorsOf = validatorFor("observation");
const FIXTURES = ["leaf-p256.pem", "leaf-p256.der"];
const AT = new Date("2026-09-15T14:02:11Z");

/**
 * @typedef {object} Result
 * @property {number | null} code
 * @property {string} stdout
 * @property {string} stderr
 */

/**
 * Runs a program and collects what it prints. Standard input is closed unless `input` is given.
 * @param {string} command
 * @param {string[]} args
 * @param {string} cwd
 * @param {string | Uint8Array} [input]
 * @returns {Promise<Result>}
 */
function run(command, args, cwd, input) {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd,
            env: { ...process.env, NO_COLOR: "1" },
            stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
        });
        /** @type {Buffer[]} */ const out = [];
        /** @type {Buffer[]} */ const err = [];
        child.stdout?.on("data", (chunk) => out.push(chunk));
        child.stderr?.on("data", (chunk) => err.push(chunk));
        child.stdin?.on("error", () => {});
        if (input !== undefined) child.stdin?.end(input);
        child.on("error", reject);
        child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    });
}

/**
 * What a failed command printed, for the message of the assertion that follows it.
 * @param {Result} result
 */
const shown = (result) => `exit ${result.code}\n${result.stdout}\n${result.stderr}`;

/**
 * Runs `npm pack --json` and returns the report of the one tarball. The report is read from
 * standard output; when it is not there, the message shows both streams, because a failing
 * `prepack` (the type declarations) prints its reason there.
 * @param {string[]} args
 * @returns {Promise<{ filename: string, files: { path: string, mode: number }[] }>}
 */
async function pack(args) {
    const result = await run("npm", ["pack", "--json", ...args], repository);
    if (result.code !== 0) throw new Error(`npm pack ${args.join(" ")} failed: ${shown(result)}`);
    try {
        return JSON.parse(result.stdout)[0];
    } catch {
        throw new Error(`npm pack ${args.join(" ")} printed no report: ${shown(result)}`);
    }
}

/**
 * Every file under a directory, as a path relative to it with forward slashes.
 * @param {string} directory
 * @returns {string[]}
 */
function filesUnder(directory) {
    return readdirSync(directory, { recursive: true, encoding: "utf8" })
        .map((path) => path.replaceAll("\\", "/"))
        .filter((path) => statSync(join(directory, path)).isFile())
        .sort();
}

/**
 * The two ways a list can differ from the one it should be, so a failure names the files.
 * @param {string[]} actual
 * @param {string[]} expected
 */
function difference(actual, expected) {
    return {
        unexpected: actual.filter((path) => !expected.includes(path)),
        missing: expected.filter((path) => !actual.includes(path)),
    };
}

const NOTHING = { unexpected: [], missing: [] };

/** @param {string} parent @param {string} child */
function isInside(parent, child) {
    const path = relative(parent, child);
    return !(path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path));
}

/**
 * What the package.json of the working copy declares that this suite reads.
 * @typedef {object} Manifest
 * @property {string[]} files
 * @property {Record<string, string>} bin
 * @property {unknown} exports
 * @property {string} types
 */

/**
 * @typedef {object} Setup
 * @property {string} directory Holds the tarball and the consumer.
 * @property {string} tarball The packed file.
 * @property {string} consumer The directory the tarball is installed into.
 * @property {string} installed `node_modules/certdrift` inside it.
 * @property {Manifest} manifest
 * @property {string[]} tracked `git ls-files` of the repository.
 * @property {string[]} dryRun The paths `npm pack --dry-run` lists, sorted.
 * @property {{ path: string, mode: number }[]} packed The files and modes of the real tarball.
 * @property {string[]} installedFiles Everything the install put under `installed`, sorted.
 */

/** @type {Setup} */
let setup;

// Set as soon as the directory exists, so that a packing or install that fails still gets it removed.
/** @type {string | undefined} */
let temporary;

before(async () => {
    // A declaration an earlier build left behind. Packing must not carry it, so it is put there
    // before packing, and the packed list is what shows whether it travelled.
    mkdirSync(new URL("types/", root), { recursive: true });
    writeFileSync(new URL("types/stale.d.ts", root), "export {};\n");

    // The path has a space and a non-ASCII letter, which a consumer's home directory may well
    // have and a script that builds a shell command by hand would break on.
    const directory = mkdtempSync(join(tmpdir(), "certdrift package-check ñ-"));
    temporary = directory;
    const consumer = join(directory, "consumer");
    mkdirSync(consumer);
    writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
    for (const name of FIXTURES) writeFileSync(join(consumer, name), readFileSync(new URL(`test/fixtures/${name}`, root)));

    const dryRun = await pack(["--dry-run"]);
    const packed = await pack(["--pack-destination", directory]);

    const install = await run("npm", ["install", "--offline", "--no-audit", "--no-fund", join(directory, packed.filename)], consumer);
    assert.equal(install.code, 0, `npm install failed: ${shown(install)}`);

    const tracked = await run("git", ["ls-files", "-z"], repository);
    assert.equal(tracked.code, 0, shown(tracked));
    const installed = join(consumer, "node_modules", "certdrift");

    setup = {
        directory,
        tarball: join(directory, packed.filename),
        consumer,
        installed,
        manifest: JSON.parse(readFileSync(new URL("package.json", root), "utf8")),
        tracked: tracked.stdout.split("\0").filter(Boolean),
        dryRun: dryRun.files.map((file) => file.path).sort(),
        packed: packed.files,
        installedFiles: filesUnder(installed),
    };
}, { timeout: 180_000 });

after(() => {
    if (temporary) rmSync(temporary, { recursive: true, force: true });
});

/** Whether the tarball carries the TLS entry point, which decides what importing it must do. */
const carriesTls = () => setup.installedFiles.includes("src/tls/index.js");

/**
 * Runs a script file in the consumer directory with the Node.js that runs this suite.
 * @param {string} name
 * @param {string} source
 * @param {string[]} [args]
 * @returns {Promise<Result>}
 */
function runInConsumer(name, source, args = []) {
    writeFileSync(join(setup.consumer, name), source);
    return run(process.execPath, [name, ...args], setup.consumer);
}

// ---------------------------------------------------------------------------------------------
// Where and what

test("it works in a temporary directory outside the repository, whose path has a space and a non-ASCII letter", () => {
    assert.equal(isInside(realpathSync(repository), realpathSync(setup.consumer)), false, setup.consumer);
    assert.match(setup.consumer, / /);
    assert.match(setup.consumer, /ñ/);

    // A copy out of a tarball, not a link back to the working copy, which `npm install <directory>` makes.
    assert.equal(lstatSync(setup.installed).isSymbolicLink(), false);
    const command = join(setup.consumer, "node_modules", ".bin", "certdrift");
    assert.equal(realpathSync(command), join(realpathSync(setup.installed), "bin", "certdrift.js"));
});

test("npm pack --dry-run lists exactly the published allowlist: the tracked files of src/, bin/ and schema/, one declaration per source file, README.md, LICENSE and package.json", () => {
    // A file that is on disk but not tracked (a scratch file, a stray key) is "unexpected" here:
    // npm would ship it, and git does not know about it.
    const expected = expectedContents(setup.manifest.files, setup.tracked);
    assert.deepEqual(difference(setup.dryRun, expected), NOTHING);
});

test("a declaration left in types/ by an earlier build is not packed", () => {
    assert.equal(setup.dryRun.includes("types/stale.d.ts"), false);
    assert.equal(existsSync(new URL("types/stale.d.ts", root)), false, "the build that packing runs empties types/ first");
});

test("the files installed are exactly the ones npm pack --dry-run listed", () => {
    assert.deepEqual(difference(setup.installedFiles, setup.dryRun), NOTHING);
    assert.deepEqual(difference(setup.packed.map((file) => file.path).sort(), setup.dryRun), NOTHING);
});

test("the tarball holds nothing from test/ and no private key", () => {
    assert.deepEqual(setup.installedFiles.filter((path) => path.startsWith("test/") || path.endsWith(".key")), []);
    const keys = setup.installedFiles.filter((path) => holdsPrivateKey(readFileSync(join(setup.installed, path), "utf8")));
    assert.deepEqual(keys, []);
});

// ---------------------------------------------------------------------------------------------
// The installed package works

test("the library imports from the installed package and inspects a certificate as the working copy does", async () => {
    const result = await runInConsumer("library.mjs", `
        import { readFileSync } from "node:fs";
        import * as library from "certdrift";
        const bytes = readFileSync("leaf-p256.pem");
        const observation = library.inspect(bytes, { at: new Date(${AT.getTime()}), source: { kind: "file", ref: "leaf-p256.pem" } });
        console.log(JSON.stringify({
            resolved: import.meta.resolve("certdrift"),
            exports: Object.keys(library).sort(),
            observation: JSON.parse(library.serializeObservation(observation)),
        }));
    `);
    assert.equal(result.code, 0, shown(result));
    const installed = JSON.parse(result.stdout);

    assert.ok(installed.resolved.includes("/node_modules/certdrift/"), installed.resolved);
    const working = await import("../src/index.js");
    assert.deepEqual(installed.exports, Object.keys(working).sort());
    const reference = inspect(readFileSync(new URL("test/fixtures/leaf-p256.pem", root)), { at: AT, source: { kind: "file", ref: "leaf-p256.pem" } });
    assert.deepEqual(installed.observation, JSON.parse(serializeObservation(reference)));
});

test("the installed executable inspects a certificate, and --query finds the schema it carries", async () => {
    // Through the link npm creates in node_modules/.bin, run directly: that needs the shebang
    // and the permission bit, and it is how a consumer's scripts and `npx` start it.
    const command = join(setup.consumer, "node_modules", ".bin", "certdrift");
    const json = await run(command, ["inspect", "--json", "leaf-p256.pem"], setup.consumer);
    assert.equal(json.code, 0, shown(json));
    const installed = JSON.parse(json.stdout);
    assert.deepEqual(errorsOf(installed), []);

    // The clock is the command's own, so the reference is built at the moment the command chose.
    const reference = inspect(readFileSync(new URL("test/fixtures/leaf-p256.pem", root)), {
        at: new Date(installed.observation.at),
        source: { kind: "file", ref: "leaf-p256.pem" },
    });
    assert.deepEqual(installed, JSON.parse(serializeObservation(reference)));

    const query = await run(command, ["inspect", "--query", "certificates[0].sha256", "leaf-p256.pem"], setup.consumer);
    assert.deepEqual([query.code, query.stdout], [0, `${reference.certificates[0].sha256}\n`], shown(query));

    // A path the schema does not declare is refused, which only a schema read from the install can do.
    const unknown = await run(command, ["inspect", "--query", "certificates[0].noSuchField", "leaf-p256.pem"], setup.consumer);
    assert.equal(unknown.code, 2, shown(unknown));
    assert.match(unknown.stderr, /unknown field in observation v1/);
    assert.equal(unknown.stdout, "");
});

test("the installed executable reads a DER file and standard input", async () => {
    const command = join(setup.consumer, "node_modules", ".bin", "certdrift");
    const sha256 = inspect(readFileSync(new URL("test/fixtures/leaf-p256.pem", root)), { at: AT }).certificates[0].sha256;

    const der = await run(command, ["inspect", "--query", "certificates[0].sha256", "leaf-p256.der"], setup.consumer);
    assert.deepEqual([der.code, der.stdout], [0, `${sha256}\n`], shown(der));

    const stdin = await run(command, ["inspect", "--query", "certificates[0].sha256", "-"], setup.consumer, readFileSync(join(setup.consumer, "leaf-p256.pem")));
    assert.deepEqual([stdin.code, stdin.stdout], [0, `${sha256}\n`], shown(stdin));
});

test("the TLS entry point fails with ERR_MODULE_NOT_FOUND while it does not exist, and imports once it does", async () => {
    const result = await runInConsumer("tls.mjs", `
        try {
            await import("certdrift/tls");
            console.log(JSON.stringify({ imported: true }));
        } catch (error) {
            console.log(JSON.stringify({ code: error.code, message: error.message }));
        }
    `);
    assert.equal(result.code, 0, shown(result));
    const outcome = JSON.parse(result.stdout);

    // The entry stays declared either way: a removed export would be ERR_PACKAGE_PATH_NOT_EXPORTED,
    // which says "this package has no such thing" and is not the same as "not written yet".
    const installedManifest = JSON.parse(readFileSync(join(setup.installed, "package.json"), "utf8"));
    assert.ok("./tls" in installedManifest.exports);

    if (carriesTls()) {
        assert.deepEqual(outcome, { imported: true });
        assert.ok(setup.installedFiles.includes("types/tls/index.d.ts"), "the TLS entry point has no declarations");
    } else {
        assert.equal(outcome.code, "ERR_MODULE_NOT_FOUND", outcome.message);
        assert.match(outcome.message, /node_modules[\\/]certdrift[\\/]src[\\/]tls[\\/]index\.js/);
        assert.deepEqual(setup.installedFiles.filter((path) => path.startsWith("types/tls/")), []);
    }
});

// ---------------------------------------------------------------------------------------------
// What the package declares is there

/**
 * Every path a package.json points at: the leaves of `exports`, the `bin` entries and `types`.
 * @param {unknown} value
 * @returns {string[]}
 */
function targetsOf(value) {
    if (typeof value === "string") return value.startsWith("./") ? [value] : [];
    if (typeof value !== "object" || value === null) return [];
    return [...new Set(Object.values(value).flatMap(targetsOf))];
}

test("every entry point in exports and bin exists in the installed package", () => {
    const installedManifest = JSON.parse(readFileSync(join(setup.installed, "package.json"), "utf8"));
    const targets = targetsOf([installedManifest.exports, installedManifest.bin, installedManifest.types]);
    assert.ok(targets.includes("./src/index.js") && targets.includes("./bin/certdrift.js") && targets.includes("./types/index.d.ts"), targets.join(", "));

    const missing = targets
        .filter((target) => {
            // A pattern such as ./schema/* → ./schema/*.json needs at least one file that fits it.
            const pattern = new RegExp(`^${target.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace("*", ".+")}$`);
            return !setup.installedFiles.some((path) => pattern.test(`./${path}`));
        })
        .sort();
    // Until the TLS module is written, its two targets are the only ones allowed to be absent,
    // and the test above this section is the one that says what importing them does.
    assert.deepEqual(missing, carriesTls() ? [] : ["./src/tls/index.js", "./types/tls/index.d.ts"]);
});

test("the command is declared as bin.certdrift, which npm pkg fix drops while the file is missing", () => {
    assert.equal(setup.manifest.bin?.certdrift, "./bin/certdrift.js");
});

test("the executable has its permission bit and an unbroken shebang line in the tarball, where npm install would repair both unseen", async () => {
    // `npm install` makes whatever `bin` names executable and rewrites a CRLF shebang line, so the
    // installed file proves nothing about the tarball: the mode in the pack report and the bytes
    // inside the tarball do.
    for (const target of Object.values(setup.manifest.bin)) {
        const path = target.replace(/^\.\//, "");
        const entry = setup.packed.find((file) => file.path === path);
        assert.ok(entry, `${path} is not in the tarball`);
        assert.equal(entry.mode & 0o111, 0o111, `${path} has mode ${entry.mode.toString(8)} in the tarball`);
        assert.ok((statSync(join(setup.installed, path)).mode & 0o111) !== 0, `${path} is not executable once installed`);
        const stored = await run("tar", ["-xzOf", setup.tarball, `package/${path}`], setup.directory);
        assert.equal(stored.code, 0, shown(stored));
        assert.equal(stored.stdout.split("\n")[0], "#!/usr/bin/env node", `${path} starts with the wrong first line in the tarball`);
    }
});

test("the schemas, README.md and LICENSE are installed byte for byte, and every schema imports through certdrift/schema/*", async () => {
    const shipped = setup.tracked.filter((path) => path.startsWith("schema/") || path === "README.md" || path === "LICENSE");
    assert.ok(shipped.includes("schema/observation.schema.json") && shipped.includes("README.md") && shipped.includes("LICENSE"), shipped.join(", "));
    for (const path of shipped) {
        const original = readFileSync(new URL(path, root));
        assert.ok(original.equals(readFileSync(join(setup.installed, path))), `${path} differs once installed`);
    }

    // The exports pattern appends `.json`, so the specifier has no extension, and Node.js wants
    // the import attribute for a JSON module.
    const schemas = shipped.filter((path) => path.startsWith("schema/") && path.endsWith(".json"));
    const specifiers = schemas.map((path) => `certdrift/${path.slice(0, -".json".length)}`);
    const result = await runInConsumer("schemas.mjs", `
        const documents = [];
        for (const specifier of process.argv.slice(2)) {
            documents.push((await import(specifier, { with: { type: "json" } })).default);
        }
        console.log(JSON.stringify(documents));
    `, specifiers);
    assert.equal(result.code, 0, shown(result));
    assert.deepEqual(JSON.parse(result.stdout), schemas.map((path) => JSON.parse(readFileSync(new URL(path, root), "utf8"))));
});

const TSC = fileURLToPath(new URL("node_modules/typescript/bin/tsc", root));
let typeChecks = 0;

/**
 * Compiles TypeScript or JavaScript files in a directory of the consumer, with the repository's
 * own TypeScript, against the installed tarball: the package resolves from `node_modules`, as it
 * does for anyone who installs it. Each call gets its own directory, so a file one check wrote
 * cannot hide a missing import in the next.
 * @param {Record<string, string>} files File name to text.
 * @param {Record<string, unknown>} [compilerOptions] Added to the strict `nodenext` defaults.
 * @returns {Promise<Result & { directory: string }>}
 */
async function typeCheckInConsumer(files, compilerOptions = {}) {
    const directory = join(setup.consumer, `types-${typeChecks++}`);
    mkdirSync(directory);
    for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, name), text);
    writeFileSync(join(directory, "tsconfig.json"), JSON.stringify({
        compilerOptions: {
            module: "nodenext",
            moduleResolution: "nodenext",
            target: "es2023",
            strict: true,
            noEmit: true,
            // The consumer of a Node.js library has Node.js types; the repository's stand in for them.
            types: ["node"],
            typeRoots: [fileURLToPath(new URL("node_modules/@types", root))],
            ...compilerOptions,
        },
        files: Object.keys(files),
    }));
    return { ...(await run(process.execPath, [TSC, "-p", "tsconfig.json"], directory)), directory };
}

test("the generated type declarations type-check a TypeScript consumer", async () => {
    const result = await typeCheckInConsumer({
        "consumer.ts": `
        import { inspect, serializeObservation, ParseError } from "certdrift";

        const observation = inspect(new Uint8Array(), { at: new Date(0) });
        export const contract: 1 = observation.contract;
        // Fails as an unused directive if the declarations collapse to \`any\`, which type-checks everything.
        // @ts-expect-error: the contract number is a literal, not a string
        export const wrong: string = observation.contract;
        export const text: string = serializeObservation(observation);
        export const error: Error = new ParseError("x", 1);
    `,
    });
    assert.deepEqual([result.code, result.stdout], [0, ""], shown(result));
});

// ---------------------------------------------------------------------------------------------
// The types of the entry point

/** Exact type equality, which assignability alone cannot give: `any` is assignable both ways. */
const TYPE_HELPERS = `
    type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
    type Expect<T extends true> = T;
`;

test("Observation, CertificateObservation, Source and Warning import as types from the installed package", async () => {
    const result = await typeCheckInConsumer({
        "named.ts": `
        import type { Observation, CertificateObservation, Source, Warning } from "certdrift";
        import { inspect } from "certdrift";

        export const source: Source = { kind: "file", ref: "leaf-p256.pem" };
        export const observation: Observation = inspect(new Uint8Array(), { source });
        export const certificate: CertificateObservation = observation.certificates[0];
        export const warning: Warning = observation.warnings[0];

        // Each of these fails as an unused directive if its type collapses to \`any\`.
        // @ts-expect-error: the contract number is 1
        export const notObservation: Observation = { contract: 2 };
        // @ts-expect-error: a certificate has fields
        export const notCertificate: CertificateObservation = {};
        // @ts-expect-error: a source is an object
        export const notSource: Source = 42;
        // @ts-expect-error: a warning code is text
        export const notWarning: Warning = { code: 1, certificate: null, message: "" };
    `,
    });
    assert.deepEqual([result.code, result.stdout], [0, ""], shown(result));
});

test("the TypeScript check fails with TS2305 when a type it imports is not exported", async () => {
    // The detector for the test above: a name the package does not export must fail the compile,
    // so a type dropped from the entry point cannot pass unseen.
    const result = await typeCheckInConsumer({
        "missing.ts": `import type { Observation, NoSuchType } from "certdrift";\nexport type Both = [Observation, NoSuchType];\n`,
    });
    assert.notEqual(result.code, 0, shown(result));
    assert.match(result.stdout, /TS2305.*'NoSuchType'/, shown(result));
});

test("a value inspect() returns is an Observation, its source option takes a Source, and CertificateObservation and Warning are the observation's own entries", async () => {
    const result = await typeCheckInConsumer({
        "equal.ts": `
        import type { Observation, CertificateObservation, Source, Warning } from "certdrift";
        import { inspect, serializeObservation } from "certdrift";
        ${TYPE_HELPERS}
        type Options = NonNullable<Parameters<typeof inspect>[1]>;

        export type Checks = [
            Expect<Equal<Observation, ReturnType<typeof inspect>>>,
            Expect<Equal<Observation, Parameters<typeof serializeObservation>[0]>>,
            Expect<Equal<Source, NonNullable<Options["source"]>>>,
            Expect<Equal<Source, Observation["observation"]["source"]>>,
            Expect<Equal<CertificateObservation, Observation["certificates"][number]>>,
            Expect<Equal<Warning, Observation["warnings"][number]>>,
            // None of the four is \`any\`, which would be equal to a type that is \`any\` too.
            Expect<Equal<Equal<Observation, any>, false>>,
            Expect<Equal<Equal<CertificateObservation, any>, false>>,
            Expect<Equal<Equal<Source, any>, false>>,
            Expect<Equal<Equal<Warning, any>, false>>,
        ];

        // A Source made apart from the call is accepted by it as it is, and the result is an Observation.
        const source: Source = { kind: "host", ref: "example.test:443", servername: null };
        export const observation: Observation = inspect(new Uint8Array(), { source });
    `,
    });
    assert.deepEqual([result.code, result.stdout], [0, ""], shown(result));
});

test("a consumer that emits declarations names every type it infers from inspect() through certdrift, nested shapes included", async () => {
    // A type that is only an alias of one declared in another file cannot be written into the
    // consumer's declarations (TS2883), and a consumer that exports a value inferred from
    // inspect() would have to annotate it by hand.
    const result = await typeCheckInConsumer({
        "emit.ts": `
        import { inspect } from "certdrift";
        const observation = inspect(new Uint8Array());
        export const whole = observation;
        export const certificate = observation.certificates[0];
        export const subject = observation.certificates[0].subject;
        export const san = observation.certificates[0].san;
        export const key = observation.certificates[0].key;
        export const derived = observation.certificates[0].derived;
        export const source = observation.observation.source;
        export const warnings = observation.warnings;
    `,
    }, { noEmit: false, declaration: true, emitDeclarationOnly: true, outDir: "out" });
    assert.deepEqual([result.code, result.stdout], [0, ""], shown(result));

    const declarations = readFileSync(join(result.directory, "out", "emit.d.ts"), "utf8");
    for (const name of ["Observation", "CertificateObservation", "DistinguishedName", "SubjectAltNames", "Source", "Warning"]) {
        assert.match(declarations, new RegExp(`import\\("certdrift"\\)\\.${name}\\b`), `${name} is not named through certdrift`);
    }
    assert.doesNotMatch(declarations, /certdrift\/types|certdrift\/src/, "the declarations point into the package's files");
});

test("the types import from JavaScript through JSDoc and under the strictest compiler options", async () => {
    const javascript = await typeCheckInConsumer({
        "typed.js": `
        /** @import { Observation, Source } from "certdrift" */
        import { inspect } from "certdrift";

        /** @type {Source} */
        const source = { kind: "file", ref: "leaf-p256.pem" };
        /** @type {Observation} */
        export const observation = inspect(new Uint8Array(), { source });
        // Fails as an unused directive if the type is not checked at all.
        /** @type {Observation} */
        // @ts-expect-error: the contract number is 1
        export const wrong = { contract: 2 };
    `,
    }, { allowJs: true, checkJs: true });
    assert.deepEqual([javascript.code, javascript.stdout], [0, ""], shown(javascript));

    const strictest = await typeCheckInConsumer({
        "strictest.ts": `
        import { inspect, type Observation, type CertificateObservation, type Source, type Warning } from "certdrift";

        const source: Source = { kind: "host", ref: "example.test:443", servername: "example.test" };
        export const observation: Observation = inspect(new Uint8Array(), { source });
        export const certificate: CertificateObservation | undefined = observation.certificates[0];
        export const warning: Warning | undefined = observation.warnings[0];
    `,
    }, { exactOptionalPropertyTypes: true, noUncheckedIndexedAccess: true, noPropertyAccessFromIndexSignature: true, verbatimModuleSyntax: true, isolatedModules: true, skipLibCheck: false });
    assert.deepEqual([strictest.code, strictest.stdout], [0, ""], shown(strictest));
});

test("each exported type has the schema's property names and required ones, and accepts any string where the schema leaves a value open", async () => {
    const schema = JSON.parse(readFileSync(join(setup.installed, "schema", "observation.schema.json"), "utf8"));
    /** @type {[string, { properties: Record<string, unknown>, required: string[] }][]} */
    const table = [
        ["Observation", schema],
        ['Observation["observation"]', schema.properties.observation],
        ["Source", schema.$defs.source],
        ["CertificateObservation", schema.$defs.certificate],
        ["DistinguishedName", schema.$defs.name],
        ["SubjectAltNames", schema.$defs.san],
        ['CertificateObservation["key"]', schema.$defs.key],
        ['CertificateObservation["derived"]', schema.$defs.derived],
        ["Warning", schema.$defs.warning],
    ];
    /** @param {string[]} names */
    const union = (names) => (names.length === 0 ? "never" : names.map((name) => JSON.stringify(name)).join(" | "));
    const checks = table.flatMap(([type, node]) => [
        `Expect<Equal<keyof ${type}, ${union(Object.keys(node.properties))}>>`,
        `Expect<Equal<RequiredKeys<${type}>, ${union(node.required)}>>`,
    ]);

    const result = await typeCheckInConsumer({
        "schema.ts": `
        import type { Observation, CertificateObservation, Source, Warning, DistinguishedName, SubjectAltNames } from "certdrift";
        ${TYPE_HELPERS}
        type RequiredKeys<T> = { [K in keyof T]-?: {} extends Pick<T, K> ? never : K }[keyof T];

        export type Checks = [
            ${checks.join(",\n            ")},
        ];

        // The schema says to tolerate unknown values in these, so a value this version has never
        // produced has to be assignable. A union of today's values would reject it.
        declare const anything: string;
        export const sourceKind: Source["kind"] = anything;
        export const certificateKind: CertificateObservation["kind"] = anything;
        export const warningCode: Warning["code"] = anything;
        export const keyAlgorithm: CertificateObservation["key"]["algorithm"] = anything;
        export type Unused = [Observation, DistinguishedName, SubjectAltNames];
    `,
    });
    assert.deepEqual([result.code, result.stdout], [0, ""], shown(result));
});
