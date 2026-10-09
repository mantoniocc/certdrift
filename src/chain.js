import { AmbiguousTargetError } from "./errors.js";
import { commonName } from "./names.js";

// How the certificates of one material relate to each other. The order of the material says
// nothing: a bundle may start with the root, lack the leaf or repeat a certificate, so every
// relation here comes from names and verified signatures.

/**
 * @typedef {import("./material.js").CertificateRead} CertificateRead
 */

/**
 * @typedef {object} Chain
 * @property {CertificateRead[]} members The certificates without duplicates, in input order.
 *   A certificate's index everywhere else is its position here.
 * @property {number[][]} issuedBy For each member, the ascending positions of the members
 *   whose subject equals its issuer and whose public key verifies its signature. A
 *   self-signed member includes itself.
 * @property {number} target The one member that signs no other member.
 * @property {import("./inspect.js").Warning[]} warnings One per duplicate dropped.
 * @throws {AmbiguousTargetError}
 */

/**
 * @param {CertificateRead[]} reads Every certificate of the material, in input order.
 * @returns {Chain}
 * @throws {AmbiguousTargetError}
 */
export function chainOf(reads) {
    const { members, warnings } = withoutDuplicates(reads);
    const issuedBy = issuersOf(members);
    return { members, issuedBy, target: targetOf(members, issuedBy), warnings };
}

/**
 * Keeps the first occurrence of each certificate, judged by fingerprint. The copies would
 * otherwise count as extra issuers and as extra candidates for the target.
 * @param {CertificateRead[]} reads
 */
function withoutDuplicates(reads) {
    /** @type {CertificateRead[]} */
    const members = [];
    /** @type {Map<string, number>} */
    const positions = new Map();
    /** @type {import("./inspect.js").Warning[]} */
    const warnings = [];

    for (const read of reads) {
        const kept = positions.get(read.sha256);
        if (kept === undefined) {
            positions.set(read.sha256, members.length);
            members.push(read);
        } else {
            warnings.push({
                code: "DUPLICATE_CERTIFICATE",
                certificate: kept,
                message: `input block ${read.block} duplicates input block ${members[kept].block} and was dropped`,
            });
        }
    }
    return { members, warnings };
}

/**
 * Name match plus a verified signature. `checkIssued()` is not used: it also demands
 * `keyCertSign`, so a self-signed server certificate with only `digitalSignature` would not be
 * its own issuer. Using one check for every pair keeps `selfSigned` and `issuedBy` consistent:
 * a certificate is self-signed exactly when it is in its own `issuedBy`.
 *
 * `verify()` returns false rather than throwing for keys of another type and for signatures it
 * cannot check, and the name comparison comes first so it runs only for plausible issuers.
 * @param {CertificateRead[]} members
 * @returns {number[][]}
 */
function issuersOf(members) {
    // Node.js gives undefined, not "", for an empty name.
    const subjects = members.map(({ certificate }) => certificate.subject ?? "");
    const keys = members.map(({ certificate }) => certificate.publicKey);

    return members.map(({ certificate }) => {
        const issuer = certificate.issuer ?? "";
        const found = [];
        for (let position = 0; position < members.length; position += 1) {
            if (subjects[position] === issuer && certificate.verify(keys[position])) {
                found.push(position);
            }
        }
        return found;
    });
}

/**
 * The one member that signs no other. A self-signed member lists itself in `issuedBy`, and that
 * does not count: it would make every root a signer and the chain would have no end.
 * @param {CertificateRead[]} members
 * @param {number[][]} issuedBy
 * @returns {number}
 * @throws {AmbiguousTargetError}
 */
function targetOf(members, issuedBy) {
    const signers = new Set();
    issuedBy.forEach((issuers, position) => {
        for (const issuer of issuers) {
            if (issuer !== position) signers.add(issuer);
        }
    });

    const candidates = members.map((_, position) => position).filter((position) => !signers.has(position));
    if (candidates.length === 1) return candidates[0];

    // With no candidate every certificate signs another one, as with a root and its renewal
    // under the same key. None can be preferred, so all of them are listed.
    const listed = candidates.length === 0 ? members.map((_, position) => position) : candidates;
    const described = listed.map((position) => {
        const { sha256, block, certificate } = members[position];
        return { sha256, cn: commonName(certificate.subject), block };
    });
    const why = candidates.length === 0
        ? "every certificate in the material signs another one"
        : `${candidates.length} certificates in the material sign no other one`;
    const lines = described.map(({ block, cn, sha256 }) => `input block ${block}: ${cn === null ? "no common name" : `CN ${JSON.stringify(cn)}`}, sha256 ${sha256}`);
    throw new AmbiguousTargetError(
        `${why}, so the target is ambiguous; candidates:\n${lines.join("\n")}`,
        described.map(({ sha256, cn }) => ({ sha256, cn })),
    );
}
