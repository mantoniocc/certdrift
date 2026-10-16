import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import * as library from "../src/index.js";
import * as tlsModule from "../src/tls/index.js";
import { declarationOf, expectedContents, holdsPrivateKey } from "../scripts/package-contents.mjs";

// What can be checked about packaging without packing anything. Packing and installing the
// tarball is `npm run package:check` (scripts/package-check.mjs); it takes seconds and installs
// into a temporary directory, so it is not part of `npm run check`, and this file pins that it is
// not, that it runs on pull requests, and the pure rules it applies.

const root = new URL("../", import.meta.url);

/** @param {string} path */
function read(path) {
    return readFileSync(new URL(path, root), "utf8");
}

/** @type {{ scripts: Record<string, string>, files: string[], name: string, version: string, license: string }} */
const manifest = JSON.parse(read("package.json"));

// ---------------------------------------------------------------------------------------------
// The script

test("package:check runs scripts/package-check.mjs", () => {
    assert.equal(manifest.scripts["package:check"], "node scripts/package-check.mjs");
    assert.ok(existsSync(new URL("scripts/package-check.mjs", root)));
});

/**
 * Every script that running one of them can run: the scripts it names with `npm run`, `npm test`
 * or `npm t`, and the `pre` and `post` hooks of each one reached, since npm runs those unasked.
 * @param {Record<string, string>} scripts
 * @param {string} name
 * @param {Set<string>} [reached]
 * @returns {Set<string>}
 */
function reachedFrom(scripts, name, reached = new Set()) {
    if (reached.has(name) || !(name in scripts)) return reached;
    reached.add(name);
    for (const hook of [`pre${name}`, `post${name}`]) reachedFrom(scripts, hook, reached);
    for (const match of scripts[name].matchAll(/\bnpm\s+(?:(?:run|run-script)\s+(?:--\s+)?([\w:.-]+)|(test|t)\b)/g)) {
        reachedFrom(scripts, match[1] ?? "test", reached);
    }
    return reached;
}

test("the detector follows npm run, npm test and the hooks npm runs unasked", () => {
    const scripts = {
        check: "npm run typecheck && npm test",
        precheck: "npm run lint",
        lint: "node lint.js",
        typecheck: "tsc --noEmit",
        test: "node --test",
        posttest: "npm run-script cleanup",
        cleanup: "node cleanup.js",
        unrelated: "node other.js",
    };
    assert.deepEqual([...reachedFrom(scripts, "check")].sort(), ["check", "cleanup", "lint", "precheck", "posttest", "test", "typecheck"].sort());
    assert.deepEqual([...reachedFrom({ a: "npm t", test: "x" }, "a")].sort(), ["a", "test"]);
});

test("npm run check never reaches package:check, through another script or a pre or post hook", () => {
    const reached = reachedFrom(manifest.scripts, "check");
    assert.ok(reached.has("typecheck") && reached.has("test"), `check reaches: ${[...reached].join(", ")}`);
    assert.equal(reached.has("package:check"), false);
    for (const name of reached) {
        assert.doesNotMatch(manifest.scripts[name], /package[:-]check/, `${name} runs the package check`);
    }
    assert.equal("precheck" in manifest.scripts || "postcheck" in manifest.scripts, false);
});

// ---------------------------------------------------------------------------------------------
// What the entry point exports

test("the entry point exports at runtime exactly inspect, evaluate, entryOfCode, matchesPrivateKey, serializeObservation, serializeCheckResult, serializeDelta, outsideValidity, policyProblems, ParseError, AmbiguousTargetError, PolicyError and EXTENDED_KEY_USAGE_OIDS", () => {
    // Types leave no runtime export, so declaring or moving one cannot change this list. It is
    // written out so that adding or removing a name is an edit someone makes on purpose.
    assert.deepEqual(Object.keys(library).sort(), ["AmbiguousTargetError", "EXTENDED_KEY_USAGE_OIDS", "ParseError", "PolicyError", "entryOfCode", "evaluate", "inspect", "matchesPrivateKey", "outsideValidity", "policyProblems", "serializeCheckResult", "serializeDelta", "serializeObservation"]);
});

test("certdrift/tls exports at runtime exactly fetchChain, ConnectionError, HandshakeError and TimeoutError", () => {
    // The target parser is internal: it is not named by `exports`, so it is not part of this list.
    assert.deepEqual(Object.keys(tlsModule).sort(), ["ConnectionError", "HandshakeError", "TimeoutError", "fetchChain"]);
});

// ---------------------------------------------------------------------------------------------
// What the tarball may hold

test("the published allowlist is src/, bin/, schema/, types/, README.md and LICENSE, and names nothing of test/", () => {
    // Widening this list is a publishing decision: whatever it names is shipped, including a
    // private key that sits next to a fixture.
    assert.deepEqual([...manifest.files].sort(), ["LICENSE", "README.md", "bin/", "schema/", "src/", "types/"]);
});

test("the expected contents come from tracked files, so an untracked file and a stale declaration are unexpected", () => {
    const tracked = [
        "bin/certdrift.js",
        "src/index.js",
        "src/tls/index.js",
        "src/tls/.gitkeep",
        "schema/observation.schema.json",
        "test/fixtures/leaf.key",
        "scripts/package-check.mjs",
        "README.md",
        "LICENSE",
        "package.json",
    ];
    const files = ["src/", "bin/", "schema/", "types/", "README.md", "LICENSE"];
    assert.deepEqual(expectedContents(files, tracked), [
        "LICENSE",
        "README.md",
        "bin/certdrift.js",
        "package.json",
        "schema/observation.schema.json",
        "src/index.js",
        "src/tls/.gitkeep",
        "src/tls/index.js",
        "types/index.d.ts",
        "types/tls/index.d.ts",
    ]);

    // Not tracked, so not expected: a scratch file in an allowed directory and a declaration
    // that no source produces.
    const expected = expectedContents(files, tracked);
    assert.equal(expected.includes("src/scratch.tmp"), false);
    assert.equal(expected.includes("types/stale.d.ts"), false);
    // package.json is always there, listed or not; a directory names only what is tracked in it.
    assert.deepEqual(expectedContents([], ["src/index.js"]), ["package.json"]);
    assert.deepEqual(expectedContents(["src/"], ["src/index.js", "srcs/other.js"]), ["package.json", "src/index.js"]);

    assert.equal(declarationOf("src/chain.js"), "types/chain.d.ts");
    assert.equal(declarationOf("src/tls/index.js"), "types/tls/index.d.ts");
    assert.equal(declarationOf("src/tls/.gitkeep"), null);
    assert.equal(declarationOf("bin/certdrift.js"), null);
});

test("a PEM private key is detected in any of its forms, and the parser's mention of the words is not", () => {
    for (const label of ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY"]) {
        assert.equal(holdsPrivateKey(`-----BEGIN ${label}-----\nMIIB\n-----END ${label}-----\n`), true, label);
    }
    // Inside a string, with Windows line endings, and after other text on the line.
    assert.equal(holdsPrivateKey('{"key":"-----BEGIN PRIVATE KEY-----\\nMIIB"}'), true);
    assert.equal(holdsPrivateKey("x\r\n-----BEGIN EC PRIVATE KEY-----\r\nMIIB"), true);

    // A certificate, a public key and a request are not private keys.
    for (const label of ["CERTIFICATE", "PUBLIC KEY", "CERTIFICATE REQUEST", "EC PARAMETERS"]) {
        assert.equal(holdsPrivateKey(`-----BEGIN ${label}-----\nMIIB\n-----END ${label}-----\n`), false, label);
    }
    // The material parser names these labels without the dashes, to refuse them.
    assert.match(read("src/material.js"), /PRIVATE KEY/);
    assert.equal(holdsPrivateKey(read("src/material.js")), false);
    // The fixtures' keys are what the allowlist keeps out of the tarball.
    assert.equal(holdsPrivateKey(read("test/fixtures/leaf-p256.key")), true);
});

// ---------------------------------------------------------------------------------------------
// Continuous integration

/**
 * The jobs of the workflow, by name, as the text of each. The workflow is read as text because no
 * YAML parser is a dependency; its jobs are the keys indented four spaces under `jobs:`.
 * @param {string} workflow
 * @returns {Map<string, string>}
 */
function jobsOf(workflow) {
    const [, section = ""] = workflow.split(/^jobs:\s*$/m);
    const parts = section.split(/^ {4}([A-Za-z][\w-]*):[ \t]*$/m);
    /** @type {Map<string, string>} */
    const jobs = new Map();
    for (let i = 1; i < parts.length; i += 2) jobs.set(parts[i], parts[i + 1]);
    return jobs;
}

test("the detector reads the jobs of a workflow", () => {
    const text = ["name: X", "jobs:", "    first:", "        runs-on: a", "    second-job:", "        needs: first", ""].join("\n");
    assert.deepEqual([...jobsOf(text).keys()], ["first", "second-job"]);
    assert.match(jobsOf(text).get("second-job") ?? "", /needs: first/);
});

test("continuous integration runs package:check on pull requests and by hand, and ci-passed waits for it except on a push to main", () => {
    const workflow = read(".github/workflows/ci.yml");
    const jobs = jobsOf(workflow);

    // Triggers: the package job needs a pull request or a manual run, and a manual run needs the trigger.
    assert.match(workflow, /^ {4}pull_request:/m);
    assert.match(workflow, /^ {4}workflow_dispatch:/m);
    assert.match(workflow, /^ {4}push:\s*\n\s+branches: \[main\]/m);
    // A manual run on main must not share a group with the push run on main and cancel it.
    assert.match(workflow, /group: .*github\.event_name/);
    assert.match(workflow, /^permissions:\s*\n\s+contents: read/m);

    const check = jobs.get("check") ?? "";
    const pack = jobs.get("package") ?? "";
    assert.ok(pack, `no package job; jobs: ${[...jobs.keys()].join(", ")}`);
    assert.match(pack, /run: npm run package:check\s*$/m);
    assert.match(pack, /node: \[24, 26\]/);
    assert.match(check, /node: \[24, 26\]/);
    assert.match(pack, /fail-fast: false/);
    for (const action of pack.matchAll(/uses: (\S+)/g)) assert.match(action[1], /@v\d+$/, "an action is pinned by major version");

    // Only these two events run it, and not a push to main.
    const condition = /^ {8}if: (.*)$/m.exec(pack)?.[1] ?? "";
    assert.match(condition, /github\.event_name == 'pull_request'/);
    assert.match(condition, /github\.event_name == 'workflow_dispatch'/);
    assert.doesNotMatch(condition, /push/);
    // And `check` stays what a person runs locally.
    assert.doesNotMatch(check, /package/);

    // The aggregate job the branch protection requires waits for it ...
    const aggregate = jobs.get("ci-passed") ?? "";
    assert.match(aggregate, /^ {8}needs: \[check, package\]\s*$/m);
    assert.match(aggregate, /^ {8}if: always\(\)\s*$/m);
    assert.match(aggregate, /needs\.package\.result != 'success'/);
    // ... and counts the job as skipped only on a push, where it does not run.
    assert.match(aggregate, /needs\.package\.result != 'success' && !\(github\.event_name == 'push' && needs\.package\.result == 'skipped'\)/);
});
