// The architecture invariants of certdrift. This file is their canonical statement:
// changing a rule here changes the architecture, not just a test.
//
//   1. The core (src/, except src/tls/) never imports node:fs or node:tls.
//   2. The CLI (bin/) never imports node:crypto or node:tls.
//   3. The library (all of src/) never uses process.argv, console.log or process.exit.
//
// The checks read the source as text, so a match inside a comment or a string counts too:
// write "the argument vector", not the global's name. They catch mistakes, not deliberate
// evasion such as `process["argv"]`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { isBuiltin } from "node:module";

const root = new URL("../", import.meta.url);

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

// A module name in quotes right after `from`, `import`, `import(` or `require(`.
// That covers `import x from "m"`, `export { x } from "m"`, `import "m"`, `import("m")`
// and `require("m")`, on one line or several.
const SPECIFIER = /(?:\bfrom|\bimport|\bimport\s*\(|\brequire\s*\()\s*["']([^"']+)["']/g;

/**
 * Built-in module behind a specifier: `node:fs/promises` and `fs/promises` are both `fs`.
 * Anything that is not a Node.js built-in (`./parse.js`, `fs-extra`) gives `null`.
 * @param {string} specifier
 * @returns {string | null}
 */
function builtinOf(specifier) {
    if (!isBuiltin(specifier)) return null;
    const name = specifier.startsWith("node:") ? specifier.slice("node:".length) : specifier;
    return name.split("/")[0];
}

/**
 * Every module a source text imports, with the line it appears on.
 * @param {string} text
 * @returns {{ builtin: string | null, specifier: string, line: number }[]}
 */
function importsOf(text) {
    return [...text.matchAll(SPECIFIER)].map((match) => ({
        builtin: builtinOf(match[1]),
        specifier: match[1],
        line: lineOf(text, match.index),
    }));
}

/**
 * Violations of "these files never import these built-ins", one string per offending import.
 * @param {string[]} files
 * @param {string[]} forbidden built-in names without the `node:` prefix, e.g. `["fs", "tls"]`
 */
function forbiddenImports(files, forbidden) {
    return files.flatMap((path) =>
        importsOf(read(path))
            .filter((found) => found.builtin !== null && forbidden.includes(found.builtin))
            .map((found) => `${path}:${found.line} imports "${found.specifier}"`),
    );
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

const library = sourceFiles("src");
const core = library.filter((path) => !path.startsWith("src/tls/"));
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
    ].join("\n");
    assert.deepEqual(
        importsOf(text).map((found) => `${found.line} ${found.builtin ?? "-"}`),
        ["1 fs", "2 tls", "3 tls", "4 crypto", "5 fs", "6 fs", "9 crypto", "10 -", "11 -"],
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

test("the core never imports node:fs or node:tls", () => {
    assert.deepEqual(forbiddenImports(core, ["fs", "tls"]), []);
});

test("bin/ never imports node:crypto or node:tls", () => {
    assert.deepEqual(forbiddenImports(cli, ["crypto", "tls"]), []);
});

test("the library never uses process.argv, console.log or process.exit", () => {
    assert.deepEqual(forbiddenUsages(library), []);
});