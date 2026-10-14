import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// How the fixture generator decides where it runs and what it refuses. It runs on a copy of the
// two scripts in a temporary directory, with a stub `docker` or `openssl` first on the path, so
// the repository's fixtures are never touched, nothing needs docker or a particular OpenSSL, and
// the test does not wait for a real generation. That the commands the generator runs work with
// both OpenSSL builds is checked by running it, which `npm run fixtures` does.

const scripts = new URL("../scripts/", import.meta.url);

/**
 * A copy of the generator with a fixtures directory that holds only a sentinel, and a directory
 * for stubs. The scripts work relative to the directory above their own, so the copy is a
 * repository of its own.
 */
function copyOfGenerator() {
    const directory = mkdtempSync(join(tmpdir(), "certdrift-generator-"));
    mkdirSync(join(directory, "scripts"));
    mkdirSync(join(directory, "test", "fixtures"), { recursive: true });
    mkdirSync(join(directory, "stubs"));
    for (const name of ["generate.sh", "generate-certs.sh"]) cpSync(new URL(name, scripts), join(directory, "scripts", name));
    writeFileSync(join(directory, "test", "fixtures", "sentinel"), "kept\n");
    return directory;
}

/**
 * @param {string} directory
 * @param {string} name
 * @param {string} body Shell, run by `sh`.
 */
function stub(directory, name, body) {
    const path = join(directory, "stubs", name);
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
}

/**
 * Runs the copy's generate.sh with its stubs first on the path.
 * @param {string} directory
 * @param {Record<string, string>} environment
 */
function generate(directory, environment) {
    /** @type {Record<string, string | undefined>} */
    const env = { ...process.env, PATH: `${join(directory, "stubs")}:${process.env.PATH}` };
    delete env.OPENSSL_MODE;
    delete env.OPENSSL_IMAGE;
    const result = spawnSync("bash", [join(directory, "scripts", "generate.sh")], { env: { ...env, ...environment }, encoding: "utf8" });
    return { status: result.status, stderr: result.stderr, fixtures: readdirSync(join(directory, "test", "fixtures")) };
}

test("the generator runs in the pinned OpenSSL image by default, an image named by digest that is the one generate.sh declares", () => {
    const directory = copyOfGenerator();
    try {
        const log = join(directory, "docker-run.txt");
        // `docker info` answers at once so that generate.sh reaches `docker run`, which is recorded
        // and fails: the run is about where the generator runs, not about generating.
        stub(directory, "docker", `[ "$1" = info ] && exit 0\nprintf '%s\\n' "$@" > '${log}'\nexit 1`);

        const result = generate(directory, {});
        assert.equal(result.status, 1);
        assert.match(result.stderr, /generating in docker mode/);

        const declared = /^OPENSSL_IMAGE="\$\{OPENSSL_IMAGE:-([^}]+)\}"$/m.exec(readFileSync(join(directory, "scripts", "generate.sh"), "utf8"));
        assert.ok(declared, "generate.sh declares a default image");
        assert.match(declared[1], /@sha256:[0-9a-f]{64}$/, "the default image is pinned by digest");

        const args = readFileSync(log, "utf8").trimEnd().split("\n");
        assert.equal(args[0], "run");
        const image = args[args.indexOf("generate-certs.sh") - 1];
        assert.equal(image, declared[1]);

        // A failed generation leaves what was published alone.
        assert.deepEqual(result.fixtures, ["sentinel"]);
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
});

test("a generation that succeeds replaces the fixtures and records the mode and the image it ran with", () => {
    const directory = copyOfGenerator();
    try {
        // The container is a stub that writes one file where the generator would write its output,
        // the directory it is given last, and succeeds.
        stub(directory, "docker", `[ "$1" = info ] && exit 0\nfor last; do :; done\nprintf 'made\\n' > "$last/made.txt"\nexit 0`);
        const result = generate(directory, {});
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(result.fixtures, ["GENERATED.txt", "made.txt"]);

        const declared = /^OPENSSL_IMAGE="\$\{OPENSSL_IMAGE:-([^}]+)\}"$/m.exec(readFileSync(join(directory, "scripts", "generate.sh"), "utf8"));
        const record = readFileSync(join(directory, "test", "fixtures", "GENERATED.txt"), "utf8");
        assert.match(record, /^mode: docker$/m);
        assert.ok(declared && record.split("\n").includes(`image: ${declared[1]}`));
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
});

test("OPENSSL_IMAGE replaces the image, and a mode other than docker or local is refused before anything runs", () => {
    const directory = copyOfGenerator();
    try {
        const log = join(directory, "docker-run.txt");
        stub(directory, "docker", `[ "$1" = info ] && exit 0\nprintf '%s\\n' "$@" > '${log}'\nexit 1`);
        generate(directory, { OPENSSL_IMAGE: "example/openssl:test" });
        assert.ok(readFileSync(log, "utf8").split("\n").includes("example/openssl:test"));

        const refused = generate(directory, { OPENSSL_MODE: "podman" });
        assert.equal(refused.status, 1);
        assert.match(refused.stderr, /OPENSSL_MODE must be 'docker' or 'local'/);
        assert.deepEqual(refused.fixtures, ["sentinel"]);
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
});

test("in local mode the generator refuses LibreSSL and an OpenSSL older than 3.5, and accepts 3.5 and later", async (t) => {
    const cases = [
        { version: "LibreSSL 3.3.6", accepted: false },
        { version: "LibreSSL 4.0.0", accepted: false },
        { version: "OpenSSL 1.1.1w  11 Sep 2023", accepted: false },
        { version: "OpenSSL 3.0.13 30 Jan 2024", accepted: false },
        { version: "OpenSSL 3.4.0 22 Oct 2024", accepted: false },
        { version: "OpenSSL 3.5.0 8 Apr 2025", accepted: true },
        { version: "OpenSSL 3.5.8 25 Aug 2026", accepted: true },
        { version: "OpenSSL 3.10.0 1 Jan 2030", accepted: true },
        { version: "OpenSSL 4.0.0 1 Jan 2031", accepted: true },
    ];
    for (const { version, accepted } of cases) {
        await t.test(`${version} is ${accepted ? "accepted" : "refused"}`, () => {
            const directory = copyOfGenerator();
            try {
                // Past the version check the stub fails on the first command that needs OpenSSL, so
                // "accepted" is shown by the generator getting as far as its first scenario.
                stub(directory, "openssl", `[ "$1" = version ] && { echo '${version}'; exit 0; }\nexit 1`);
                const result = generate(directory, { OPENSSL_MODE: "local" });
                assert.equal(result.status, 1);
                assert.equal(/→ root CA/.test(result.stderr), accepted, result.stderr);
                if (!accepted) assert.match(result.stderr, /OpenSSL (>= 3\.5 )?required, found/);
                assert.deepEqual(result.fixtures, ["sentinel"]);
            } finally {
                rmSync(directory, { recursive: true, force: true });
            }
        });
    }
});
