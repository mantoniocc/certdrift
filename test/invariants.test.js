// The architecture invariants of certdrift. This file is their canonical statement:
// changing a rule here changes the architecture, not just a test.
//
//   1. The core (src/, except src/tls/) imports only the built-in modules listed in
//      CORE_BUILTINS below, and only other files of the core. A built-in nobody listed is
//      refused, so a module that reaches the file system, the network or another process
//      cannot get in unnoticed: allowing one more means editing that list, in the same change.
//      A relative import that resolves into src/tls/ or outside src/ is refused too. The check
//      reads each file on its own and does not follow imports, so a core file importing the TLS
//      module would carry its socket imports into the core unseen.
//   2. The CLI (bin/) never imports node:crypto or node:tls.
//   3. The library (all of src/) never uses process.argv, console.log or process.exit.
//   4. The CLI (bin/) imports from src/ only the files package.json "exports" points to, so
//      a library user can do with an import everything the command does.
//   5. The TLS module (src/tls/) imports from the rest of src/ only types, written in JSDoc
//      comments, so loading it runs no core code; and it imports nothing from bin/, not even a
//      type. The module is the only one allowed to open sockets, which is a reason to keep it
//      from depending on what the core does, and the core from depending on it (rule 1).
//
// The checks read the source as text, so a match inside a comment or a string counts too:
// write "the argument vector", not the global's name. They catch mistakes, not deliberate
// evasion such as `process["argv"]`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { builtinModules, isBuiltin } from "node:module";
import { dirname, join, normalize } from "node:path/posix";

const root = new URL("../", import.meta.url);

// The only built-in modules the core may import, by name without the `node:` prefix and
// whatever the subpath. The core works on bytes it is given, so it needs hashing and parsing
// (crypto) and type checks (util) and nothing that reaches the file system, the network or
// another process. Rule 1 refuses every other built-in; to allow one, add it here and say why.
const CORE_BUILTINS = ["crypto", "util"];

/**
 * Every JavaScript file under a directory, as a repository-relative path with forward slashes.
 * @param {string} directory e.g. `"src"`
 * @returns {string[]}
 */
function sourceFiles(directory) {
    return readdirSync(new URL(`${directory}/`, root), { recursive: true, encoding: "utf8" })
        .map((path) => `${directory}/${path.replaceAll("\\", "/")}`)
        .filter((path) => /\.[cm]?js$/.test(path))
        .sort();
}

/** @param {string} path */
function read(path) {
    return readFileSync(new URL(path, root), "utf8");
}

/**
 * Line number (1-based) of a position in a text.
 * @param {string} text
 * @param {number} index
 */
function lineOf(text, index) {
    return text.slice(0, index).split("\n").length;
}

// A module name right after `from` or `import` in quotes, or as the argument of `import(`,
// `require(` or `getBuiltinModule(` (also called as `getBuiltinModule?.(`) in quotes or in a
// template literal. That covers
// `import x from "m"`, `export { x } from "m"`, `import "m"`, `import("m")`, `require("m")`
// and `process.getBuiltinModule("m")`, on one line or several. A template literal is read only
// as an argument: after `from` it is no import, and prose such as "read from `x`" must not count.
const SPECIFIER =
    /\b(?:from|import)\s*(["'])(?<plain>[^"'\n]+)\1|\b(?:import|require|getBuiltinModule)\s*(?:\?\.\s*)?\(\s*(["'`])(?<called>[^"'`\n]+)\3/g;

/**
 * Built-in module behind a specifier: `node:fs/promises` and `fs/promises` are both `fs`.
 * Anything that is not a Node.js built-in (`./parse.js`, `fs-extra`) gives `null`.
 *
 * Whatever starts with `node:` is a built-in, even one this Node.js does not know: the list
 * `isBuiltin` reads changes between versions and is behind an experimental flag for some
 * modules, so trusting it alone would let a module pass here that another Node.js loads.
 * @param {string} specifier
 * @returns {string | null}
 */
function builtinOf(specifier) {
    if (specifier.startsWith("node:")) return specifier.slice("node:".length).split("/")[0];
    return isBuiltin(specifier) ? specifier.split("/")[0] : null;
}

/**
 * Every module a source text imports, with the line it appears on and whether it is only a type.
 *
 * An import is only a type when its line starts, after any spaces, with a documentation comment
 * (`/**`) or one of its continuation lines (`*`): that is where JSDoc writes `@import` and
 * `import("…")` types, and nothing there runs. A comment that starts after some code on the same
 * line, or a line comment, does not count: the import is then taken as one that runs, which
 * fails on the safe side.
 * @param {string} text
 * @returns {{ builtin: string | null, specifier: string, line: number, typeOnly: boolean }[]}
 */
function importsOf(text) {
    const lines = text.split("\n");
    return [...text.matchAll(SPECIFIER)].map((match) => {
        const specifier = match.groups?.plain ?? match.groups?.called ?? "";
        const line = lineOf(text, match.index);
        return { builtin: builtinOf(specifier), specifier, line, typeOnly: /^\s*(?:\/\*\*|\*)/.test(lines[line - 1]) };
    });
}

/**
 * Violations of "this file never imports these built-ins" in a source text, one string per
 * offending import.
 * @param {string} path Repository-relative path, for the message.
 * @param {string} text
 * @param {string[]} forbidden built-in names without the `node:` prefix, e.g. `["crypto", "tls"]`
 */
function forbiddenIn(path, text, forbidden) {
    return importsOf(text)
        .filter((found) => found.builtin !== null && forbidden.includes(found.builtin))
        .map((found) => `${path}:${found.line} imports "${found.specifier}"`);
}

/**
 * Violations of "these files never import these built-ins", one string per offending import.
 * @param {string[]} files
 * @param {string[]} forbidden built-in names without the `node:` prefix, e.g. `["crypto", "tls"]`
 */
function forbiddenImports(files, forbidden) {
    return files.flatMap((path) => forbiddenIn(path, read(path), forbidden));
}

/**
 * Whether a repository-relative path belongs to the core: src/ except src/tls/.
 * @param {string} path
 */
function isCoreFile(path) {
    return /^src\/(?!tls(?:\/|$))/.test(path);
}

/**
 * Violations of "the core imports only these built-ins and other core files" in a source
 * text, one string per offending import. A relative import is judged by where it resolves.
 * @param {string} path Repository-relative path of the importing file.
 * @param {string} text
 * @param {string[]} allowed built-in names without the `node:` prefix
 */
function refusedInCore(path, text, allowed) {
    return importsOf(text)
        .filter((found) =>
            found.builtin !== null
                ? !allowed.includes(found.builtin)
                : found.specifier.startsWith(".") && !isCoreFile(join(dirname(path), found.specifier)),
        )
        .map((found) => `${path}:${found.line} imports "${found.specifier}"`);
}

/**
 * Violations of rule 1 over files, one string per offending import.
 * @param {string[]} files
 */
function importsOutsideCore(files) {
    return files.flatMap((path) => refusedInCore(path, read(path), CORE_BUILTINS));
}

/**
 * Whether a repository-relative path belongs to the TLS module: src/tls/.
 * @param {string} path
 */
function isTlsFile(path) {
    return /^src\/tls\//.test(path);
}

/**
 * Violations of rule 5 in a source text of the TLS module, one string per offending import.
 * Built-ins and other packages are not its business. Whatever resolves into bin/ is refused,
 * type or not. A type may come from anywhere else, and an import that runs may come only from
 * the module's own files: not from the core, not from outside src/, and not from the package
 * itself, which is the core and the module again by another name.
 * @param {string} path Repository-relative path of the importing file.
 * @param {string} text
 */
function refusedInTls(path, text) {
    return importsOf(text)
        .filter((found) => {
            if (found.specifier === "certdrift" || found.specifier.startsWith("certdrift/")) return !found.typeOnly;
            if (!found.specifier.startsWith(".")) return false;
            const target = join(dirname(path), found.specifier);
            if (target === "bin" || target.startsWith("bin/") || target.startsWith("../bin/")) return true;
            return !found.typeOnly && !isTlsFile(target);
        })
        .map((found) => `${path}:${found.line} imports "${found.specifier}"`);
}

const USAGE = /\bprocess\.argv\b|\bconsole\.log\b|\bprocess\.exit\b/g;

/**
 * Every use of process.argv, console.log or process.exit in a source text, with its line.
 * @param {string} text
 * @returns {{ usage: string, line: number }[]}
 */
function usagesOf(text) {
    return [...text.matchAll(USAGE)].map((match) => ({ usage: match[0], line: lineOf(text, match.index) }));
}

/**
 * Violations of "these files never use these globals", one string per occurrence.
 * @param {string[]} files
 */
function forbiddenUsages(files) {
    return files.flatMap((path) =>
        usagesOf(read(path)).map((found) => `${path}:${found.line} uses ${found.usage}`),
    );
}

/**
 * The files of src/ that a package.json `exports` map points to, whatever the condition
 * (`default`, `types`, …) and however deep, as repository-relative paths. A target outside src/
 * (the generated declarations) is not a source file and is left out. A target need not exist
 * yet: the TLS entry point is allowed before it is written.
 * @param {unknown} exports
 * @returns {string[]}
 */
function exportedSources(exports) {
    if (typeof exports === "string") return exports.startsWith("./src/") ? [normalize(exports)] : [];
    if (typeof exports !== "object" || exports === null) return [];
    return [...new Set(Object.values(exports).flatMap(exportedSources))].sort();
}

/**
 * Every import of a file under src/, with the repository-relative path it resolves to and its
 * line. Built-ins and packages are not imports of src/.
 * @param {string} path Repository-relative path of the importing file.
 * @param {string} text
 * @returns {{ target: string, specifier: string, line: number }[]}
 */
function sourceImportsOf(path, text) {
    return importsOf(text)
        .filter((found) => found.specifier.startsWith("."))
        .map((found) => ({ target: join(dirname(path), found.specifier), specifier: found.specifier, line: found.line }))
        .filter((found) => found.target.startsWith("src/"));
}

/**
 * Violations of "these files import from src/ only these files", one string per offending import.
 * @param {string[]} files
 * @param {string[]} allowed
 */
function forbiddenSourceImports(files, allowed) {
    return files.flatMap((path) =>
        sourceImportsOf(path, read(path))
            .filter((found) => !allowed.includes(found.target))
            .map((found) => `${path}:${found.line} imports "${found.specifier}", which package.json does not export`),
    );
}

const library = sourceFiles("src");
const core = library.filter(isCoreFile);
const tlsModule = library.filter(isTlsFile);
const cli = sourceFiles("bin");

// A scan that finds no files passes every rule below without checking anything.
test("the scan finds the source files", () => {
    assert.ok(core.includes("src/index.js"), `src/index.js not found; scanned: ${library.join(", ")}`);
});

// The rules below pass when nothing matches, so the detector itself is pinned on known input.
test("the detector recognises every import form", () => {
    const text = [
        'import { readFile } from "node:fs/promises";',
        "import tls from 'tls';",
        'export { connect } from "node:tls";',
        'import "node:crypto";',
        'const lazy = await import("fs");',
        'const legacy = require("node:fs");',
        "import {",
        "    X509Certificate,",
        '} from "node:crypto";',
        'import { parse } from "./parse.js";',
        'import extra from "fs-extra";',
        'const loaded = process.getBuiltinModule("node:net");',
        "const quoted = await import(`node:net`);",
        "const legacyQuoted = require(`fs`);",
        "// the bytes come from `node:net`, not from a file",
        '/** @type {import("node:tls").TLSSocket} */',
        'const optional = process.getBuiltinModule?.("node:dns");',
    ].join("\n");
    assert.deepEqual(
        importsOf(text).map((found) => `${found.line} ${found.builtin ?? "-"}`),
        ["1 fs", "2 tls", "3 tls", "4 crypto", "5 fs", "6 fs", "9 crypto", "10 -", "11 -", "12 net", "13 net", "14 fs", "16 tls", "17 dns"],
    );
});

test("the detector recognises every forbidden usage", () => {
    const text = [
        "const args = process.argv.slice(2);",
        'console.log("hi");',
        'console.error("not forbidden");',
        "process.exit(1);",
    ].join("\n");
    assert.deepEqual(
        usagesOf(text).map((found) => `${found.line} ${found.usage}`),
        ["1 process.argv", "2 console.log", "4 process.exit"],
    );
});

test(`the core imports only ${CORE_BUILTINS.map((name) => `node:${name}`).join(" and ")}`, () => {
    assert.deepEqual(
        importsOutsideCore(core),
        [],
        "the core may import only the built-ins in CORE_BUILTINS and other core files; to allow another, edit the list on purpose",
    );
});

test("the core is src/ without src/tls/", () => {
    assert.equal(isCoreFile("src/inspect.js"), true);
    assert.equal(isCoreFile("src/deep/parse.js"), true);
    assert.equal(isCoreFile("src/tls.js"), true);
    assert.equal(isCoreFile("src/tls/index.js"), false);
    assert.equal(isCoreFile("src/tls/deep/socket.js"), false);
    assert.equal(isCoreFile("src/tls"), false);
    assert.equal(isCoreFile("bin/cli.js"), false);
    assert.equal(isCoreFile("test/invariants.test.js"), false);
});

test("the allowlist refuses every built-in this Node.js ships except the ones it lists", () => {
    assert.ok(builtinModules.includes("net") && builtinModules.includes("child_process"), "the list of built-ins is empty");
    for (const specifier of builtinModules.flatMap((name) => (name.startsWith("node:") ? [name] : [name, `node:${name}`]))) {
        const base = specifier.replace(/^node:/, "").split("/")[0];
        assert.deepEqual(
            refusedInCore("src/probe.js", `import x from "${specifier}";`, CORE_BUILTINS),
            CORE_BUILTINS.includes(base) ? [] : [`src/probe.js:1 imports "${specifier}"`],
            specifier,
        );
    }
});

test("a refused import names the file, the line and the module in every import form, with and without node:", () => {
    for (const prefix of ["node:", ""]) {
        const text = [
            `import net from "${prefix}net";`,
            `export { connect } from '${prefix}tls';`,
            `import "${prefix}dns";`,
            `const lazy = await import("${prefix}http");`,
            `const legacy = require("${prefix}https");`,
            `const loaded = process.getBuiltinModule(\`${prefix}http2\`);`,
            "import {",
            "    Socket,",
            `} from "${prefix}dgram";`,
            `import { spawn } from "${prefix}child_process";`,
            `import { Worker } from "${prefix}worker_threads";`,
            `import { readFile } from "${prefix}fs/promises";`,
            `import { createHash } from "${prefix}crypto";`,
        ].join("\n");
        assert.deepEqual(refusedInCore("src/probe.js", text, CORE_BUILTINS), [
            `src/probe.js:1 imports "${prefix}net"`,
            `src/probe.js:2 imports "${prefix}tls"`,
            `src/probe.js:3 imports "${prefix}dns"`,
            `src/probe.js:4 imports "${prefix}http"`,
            `src/probe.js:5 imports "${prefix}https"`,
            `src/probe.js:6 imports "${prefix}http2"`,
            `src/probe.js:9 imports "${prefix}dgram"`,
            `src/probe.js:10 imports "${prefix}child_process"`,
            `src/probe.js:11 imports "${prefix}worker_threads"`,
            `src/probe.js:12 imports "${prefix}fs/promises"`,
        ]);
    }
});

test("the allowlist passes an allowed built-in in every import form, with and without node:", () => {
    for (const prefix of ["node:", ""]) {
        for (const name of [...CORE_BUILTINS, "util/types"]) {
            const text = [
                `import x from "${prefix}${name}";`,
                `export { y } from '${prefix}${name}';`,
                `import "${prefix}${name}";`,
                `const lazy = await import("${prefix}${name}");`,
                `const legacy = require("${prefix}${name}");`,
                `const loaded = process.getBuiltinModule(\`${prefix}${name}\`);`,
                "import {",
                "    z,",
                `} from "${prefix}${name}";`,
            ].join("\n");
            assert.deepEqual(refusedInCore("src/probe.js", text, CORE_BUILTINS), [], `${prefix}${name}`);
        }
    }
});

test("a node: specifier counts as a built-in even when this Node.js does not know it", () => {
    const text = [
        'import "node:quic";',
        'import "node:nonexistent";',
        'import "node:Crypto";',
        "const computed = await import(`node:${name}`);",
    ].join("\n");
    assert.deepEqual(refusedInCore("src/probe.js", text, CORE_BUILTINS), [
        'src/probe.js:1 imports "node:quic"',
        'src/probe.js:2 imports "node:nonexistent"',
        'src/probe.js:3 imports "node:Crypto"',
        'src/probe.js:4 imports "node:${name}"',
    ]);
});

test("an import named only in a type comment counts as an import", () => {
    const text = '/** @type {import("node:net").Socket} */';
    assert.deepEqual(refusedInCore("src/probe.js", text, CORE_BUILTINS), ['src/probe.js:1 imports "node:net"']);
});

test("a package is not a built-in, so the rule on built-ins leaves it alone", () => {
    const text = ['import extra from "fs-extra";', 'import "net-tools";', 'import "test";'].join("\n");
    assert.deepEqual(refusedInCore("src/probe.js", text, CORE_BUILTINS), []);
});

test("the core never imports a file outside the core", () => {
    const text = [
        'export { fetchChain } from "./tls/index.js";',
        'import "../bin/cli.js";',
        'import "../scripts/generate.mjs";',
        'const lazy = await import("./tls");',
        'import { ParseError } from "./errors.js";',
        'const viaDot = await import("./a/../names.js");',
    ].join("\n");
    assert.deepEqual(refusedInCore("src/inspect.js", text, CORE_BUILTINS), [
        'src/inspect.js:1 imports "./tls/index.js"',
        'src/inspect.js:2 imports "../bin/cli.js"',
        'src/inspect.js:3 imports "../scripts/generate.mjs"',
        'src/inspect.js:4 imports "./tls"',
    ]);
    assert.deepEqual(refusedInCore("src/deep/parse.js", 'import "../tls/index.js";\nimport "../errors.js";', CORE_BUILTINS), [
        'src/deep/parse.js:1 imports "../tls/index.js"',
    ]);
});

test("the detector tells a type-only import in a documentation comment from one that runs", () => {
    const text = [
        '/** @import { Source } from "../index.js" */',
        "/**",
        ' * @param {import("../inspect.js").Options} options',
        ' * @returns {Promise<import("../index.js").Observation>}',
        " */",
        '    /** @type {import("../chain.js").Chain} */',
        'import { inspect } from "../inspect.js";',
        'const lazy = await import("../index.js");',
        '// import("../index.js") named in a line comment',
        'const typed = /** @type {import("../index.js").Source} */ ({});',
        'export { x } from "../chain.js"; /** import("../names.js") */',
    ].join("\n");
    assert.deepEqual(
        importsOf(text).map((found) => `${found.line} ${found.typeOnly ? "type" : "runs"}`),
        ["1 type", "3 type", "4 type", "6 type", "7 runs", "8 runs", "9 runs", "10 runs", "11 runs", "11 runs"],
    );
});

test("the TLS module imports from the rest of src/ only types, and nothing from bin/", () => {
    assert.deepEqual(tlsModule.flatMap((path) => refusedInTls(path, read(path))), []);
});

test("the rule for src/tls/ refuses a runtime import of the core, of bin/ or of the package itself in every form, and passes a type, the module's own files and built-ins", () => {
    const text = [
        'import { inspect } from "../inspect.js";',
        'export { inspect } from "../index.js";',
        'import "../chain.js";',
        'const lazy = await import("../index.js");',
        'const legacy = require("../san.js");',
        "import {",
        "    ParseError,",
        '} from "../errors.js";',
        'import { cli } from "../../bin/cli.js";',
        'import { certdrift } from "certdrift";',
        'import { fetchChain } from "certdrift/tls";',
        'import { helper } from "../../scripts/helper.mjs";',
        'import { targetOf } from "./target.js";',
        'import { deeper } from "./deep/more.js";',
        'import tls from "node:tls";',
        'import extra from "fs-extra";',
    ].join("\n");
    assert.deepEqual(refusedInTls("src/tls/index.js", text), [
        'src/tls/index.js:1 imports "../inspect.js"',
        'src/tls/index.js:2 imports "../index.js"',
        'src/tls/index.js:3 imports "../chain.js"',
        'src/tls/index.js:4 imports "../index.js"',
        'src/tls/index.js:5 imports "../san.js"',
        'src/tls/index.js:8 imports "../errors.js"',
        'src/tls/index.js:9 imports "../../bin/cli.js"',
        'src/tls/index.js:10 imports "certdrift"',
        'src/tls/index.js:11 imports "certdrift/tls"',
        'src/tls/index.js:12 imports "../../scripts/helper.mjs"',
    ]);

    const types = [
        '/** @import { Source } from "../index.js" */',
        "/**",
        ' * @returns {Promise<import("../inspect.js").Options>}',
        ' * @param {import("certdrift").Source} source',
        " */",
    ].join("\n");
    assert.deepEqual(refusedInTls("src/tls/index.js", types), []);

    // A type from bin/ is refused too: the module must not know about the command that uses it.
    const fromBin = [
        '/** @import { Options } from "../../bin/cli.js" */',
        ' * @param {import("../../bin/query.js").Path} path',
    ].join("\n");
    assert.deepEqual(refusedInTls("src/tls/index.js", fromBin), [
        'src/tls/index.js:1 imports "../../bin/cli.js"',
        'src/tls/index.js:2 imports "../../bin/query.js"',
    ]);

    // Relative to where the file is: from a deeper directory, ../ no longer leaves the module.
    assert.deepEqual(refusedInTls("src/tls/deep/socket.js", 'import "../target.js";\nimport "../../inspect.js";'), [
        'src/tls/deep/socket.js:2 imports "../../inspect.js"',
    ]);
});

test("the scan finds the TLS module, so the rule on the argument vector, console output and exiting covers it", () => {
    assert.ok(tlsModule.includes("src/tls/index.js"), `src/tls/index.js not found; scanned: ${library.join(", ")}`);
    assert.ok(library.includes("src/tls/index.js"));
    assert.equal(core.includes("src/tls/index.js"), false);
    assert.deepEqual(forbiddenUsages(tlsModule), []);
});

test("bin/ never imports node:crypto or node:tls", () => {
    assert.deepEqual(forbiddenImports(cli, ["crypto", "tls"]), []);
});

test("the rule for bin/ flags node:crypto and node:tls in every form and nothing else", () => {
    const text = [
        'import { createHash } from "node:crypto";',
        "import tls from 'tls';",
        'const lazy = await import("node:tls");',
        'const legacy = require("crypto");',
        'import { readFile } from "node:fs/promises";',
        'import net from "node:net";',
    ].join("\n");
    assert.deepEqual(forbiddenIn("bin/probe.js", text, ["crypto", "tls"]), [
        'bin/probe.js:1 imports "node:crypto"',
        'bin/probe.js:2 imports "tls"',
        'bin/probe.js:3 imports "node:tls"',
        'bin/probe.js:4 imports "crypto"',
    ]);
});

test("the library never uses process.argv, console.log or process.exit", () => {
    assert.deepEqual(forbiddenUsages(library), []);
});

test("the detector reads the exported source files of an exports map", () => {
    const exports = {
        ".": { types: "./types/index.d.ts", default: "./src/index.js" },
        "./tls": { types: "./types/tls/index.d.ts", default: "./src/tls/index.js" },
        "./schema/*": "./schema/*.json",
        "./deep": { node: { import: "./src/./deep/main.js" } },
    };
    assert.deepEqual(exportedSources(exports), ["src/deep/main.js", "src/index.js", "src/tls/index.js"]);
    assert.deepEqual(exportedSources("./bin/cli.js"), []);
    assert.deepEqual(exportedSources(undefined), []);
});

test("the detector recognises every import that reaches into src/", () => {
    const text = [
        'import { inspect } from "../src/index.js";',
        'import { chainOf } from "../src/chain.js";',
        'export { connect } from "../src/tls/index.js";',
        'const lazy = await import("../src/./names.js");',
        'import { run } from "./cli.js";',
        'import { readFile } from "node:fs/promises";',
        'import { elsewhere } from "../scripts/other.js";',
        "import {",
        "    commonName,",
        '} from "../src/names.js";',
    ].join("\n");
    assert.deepEqual(
        sourceImportsOf("bin/certdrift.js", text).map((found) => `${found.line} ${found.target}`),
        ["1 src/index.js", "2 src/chain.js", "3 src/tls/index.js", "4 src/names.js", "10 src/names.js"],
    );
    assert.deepEqual(sourceImportsOf("bin/deep/run.js", 'import "../../src/chain.js";').map((found) => found.target), ["src/chain.js"]);
});

test("bin/ imports from src/ only the files package.json exports", () => {
    const { exports } = JSON.parse(read("package.json"));
    const allowed = exportedSources(exports);
    assert.ok(allowed.includes("src/index.js"), `package.json exports no src/index.js; found: ${allowed.join(", ")}`);
    assert.deepEqual(forbiddenSourceImports(cli, allowed), []);
});
