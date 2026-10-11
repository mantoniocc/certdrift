// What a packed certdrift tarball must hold, and what it must never hold. These are pure
// functions of their input so that `npm test` can pin them without packing anything; the suite
// that packs and installs the tarball is scripts/package-check.mjs.

/**
 * Where a source file's declaration lands: `tsconfig.types.json` reads `src/` and writes `types/`.
 * @param {string} source Repository-relative path, e.g. `"src/tls/index.js"`.
 * @returns {string | null} `"types/tls/index.d.ts"`, or `null` for a file that is not a source.
 */
export function declarationOf(source) {
    const match = /^src\/(.+)\.js$/.exec(source);
    return match === null ? null : `types/${match[1]}.d.ts`;
}

/**
 * The files a tarball holds, given the `files` allowlist of package.json and the files git
 * tracks. Only tracked files count: `npm pack` also ships an untracked file that happens to sit in
 * an allowed directory, and that is exactly what this list is compared against. `types/` is build
 * output that git does not track, so it is derived from the sources it is built from; a
 * declaration left there by an earlier build is therefore not expected.
 * @param {string[]} files The `files` field of package.json.
 * @param {string[]} tracked `git ls-files`, as repository-relative paths with forward slashes.
 * @returns {string[]} Sorted.
 */
export function expectedContents(files, tracked) {
    const paths = new Set(["package.json"]);
    for (const entry of files) {
        if (!entry.endsWith("/")) {
            paths.add(entry);
        } else if (entry === "types/") {
            for (const source of tracked) {
                const declaration = declarationOf(source);
                if (declaration !== null) paths.add(declaration);
            }
        } else {
            for (const path of tracked) if (path.startsWith(entry)) paths.add(path);
        }
    }
    return [...paths].sort();
}

// A boundary line of a private key in any of its PEM forms (`PRIVATE KEY`, `RSA PRIVATE KEY`,
// `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, …). It is not anchored to the start of a line,
// so a key pasted inside a string or a JSON value counts, and it needs the dashes, so source that
// merely talks about the words (the parser's list of labels it refuses) does not.
const PRIVATE_KEY_BOUNDARY = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

/**
 * Whether a text holds a PEM private key.
 * @param {string} text
 */
export function holdsPrivateKey(text) {
    return PRIVATE_KEY_BOUNDARY.test(text);
}
