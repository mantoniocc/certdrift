import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { inspect, AmbiguousTargetError } from "../src/index.js";

// Relations between the certificates of one material: kind, who issued whom, and which
// certificate the observation is about. Nothing here may depend on a fixture's exact bytes,
// because `npm run fixtures` replaces them, so every expectation comes from the scenario that
// generates the fixture (its extensions, its names, its keys) or from Node.js itself.

const fixturesUrl = new URL("fixtures/", import.meta.url);
const examplesUrl = new URL("../schema/examples/observation/", import.meta.url);
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/** @param {string} name */
function pem(name) {
    return fixture(name).toString("latin1").trim();
}

/** @param {string} name */
function certificate(name) {
    return new X509Certificate(fixture(name));
}

/**
 * Fingerprint of a fixture, from Node.js itself so that the library is not its own oracle.
 * @param {string} name
 */
function fingerprint(name) {
    return certificate(name).fingerprint256.replaceAll(":", "").toLowerCase();
}

/**
 * The observation of fixtures put one after the other, one block each.
 * @param {...string} names
 */
function observe(...names) {
    return inspect(names.map(pem).join("\n"), { at: AT });
}

/**
 * The fixtures an observation is about, by name, so a test reads as "resolves to the leaf".
 * @param {ReturnType<typeof inspect>} observation
 */
function targetHash(observation) {
    return observation.certificates[observation.target].sha256;
}

/** @param {() => unknown} action */
function ambiguity(action) {
    try {
        action();
    } catch (error) {
        assert.ok(error instanceof AmbiguousTargetError, `expected an AmbiguousTargetError, got ${error}`);
        return error;
    }
    return assert.fail("expected an AmbiguousTargetError, but nothing was thrown");
}

// The single certificates of the scenarios, each with the extensions it was generated from.
const SINGLES = readdirSync(fixturesUrl)
    .filter((name) => name.endsWith(".pem") && !name.startsWith("bundle-"))
    .sort();

test("kind is end-entity when basicConstraints does not mark the certificate as a CA, and ca when it does", async (t) => {
    assert.ok(SINGLES.length >= 25, `expected the single-certificate fixtures, found ${SINGLES.length}`);
    for (const name of SINGLES) {
        await t.test(name, () => {
            const extensions = readFileSync(new URL(name.replace(/\.pem$/, ".ext"), fixturesUrl), "utf8");
            const expected = /CA:TRUE/.test(extensions) ? "ca" : "end-entity";
            assert.equal(observe(name).certificates[0].kind, expected);
        });
    }
});

test("selfSigned is true when the issuer name equals the subject and verify() passes with the certificate's own key", async (t) => {
    const expected = {
        "root-ca.pem": true,
        "legacy-root.pem": true,
        "root-ca-renewed.pem": true,
        "selfsigned-leaf.pem": true,
        "intermediate.pem": false,
        "leaf-p256.pem": false,
        "root-ca-cross.pem": false,
    };
    for (const [name, selfSigned] of Object.entries(expected)) {
        await t.test(`${name}: ${selfSigned}`, () => {
            assert.equal(observe(name).certificates[0].selfSigned, selfSigned);
        });
    }

    // checkIssued() would say otherwise: it rejects a Key Usage without keyCertSign even
    // against the certificate itself, and this certificate only has digitalSignature.
    await t.test("selfsigned-leaf has Key Usage digitalSignature only, and checkIssued() would reject it", () => {
        const extensions = readFileSync(new URL("selfsigned-leaf.ext", fixturesUrl), "utf8");
        assert.match(extensions, /keyUsage = critical, digitalSignature\n/);
        const self = certificate("selfsigned-leaf.pem");
        assert.equal(self.verify(self.publicKey), true);
        assert.equal(self.checkIssued(self), false);

        const [only] = observe("selfsigned-leaf.pem").certificates;
        assert.equal(only.selfSigned, true);
        assert.deepEqual(only.issuedBy, [0]);
    });
});

test("issuedBy lists in ascending order the certificates that verify its signature, is empty and never null when the issuer is not in the material, and includes itself when self-signed", async (t) => {
    await t.test("each certificate points at its issuer wherever it sits in the material", () => {
        // root-ca, leaf-p256, intermediate
        const { certificates } = observe("bundle-shuffled.pem");
        assert.deepEqual(certificates.map((c) => c.issuedBy), [[0], [2], [0]]);
    });

    await t.test("empty, not null, when the issuer is missing", () => {
        const [leaf] = observe("leaf-p256.pem").certificates;
        assert.deepEqual(leaf.issuedBy, []);
        const { certificates } = observe("intermediate.pem", "leaf-p256.pem");
        assert.deepEqual(certificates.map((c) => c.issuedBy), [[], [0]]);
    });

    await t.test("a self-signed certificate includes itself", () => {
        assert.deepEqual(observe("root-ca.pem").certificates[0].issuedBy, [0]);
    });

    // Two certificates verify the intermediate: the root and its cross-signed copy.
    await t.test("several issuers come in ascending order whichever order the material has", () => {
        const orders = [
            ["root-ca.pem", "root-ca-cross.pem", "intermediate.pem"],
            ["root-ca-cross.pem", "root-ca.pem", "intermediate.pem"],
            ["intermediate.pem", "root-ca-cross.pem", "root-ca.pem"],
            ["legacy-root.pem", "root-ca-cross.pem", "intermediate.pem", "root-ca.pem"],
        ];
        for (const order of orders) {
            const { certificates } = observe(...order);
            const position = order.indexOf("intermediate.pem");
            const issuers = ["root-ca.pem", "root-ca-cross.pem"].map((name) => order.indexOf(name)).sort((a, b) => a - b);
            assert.deepEqual(certificates[position].issuedBy, issuers, order.join(" "));
        }
    });
});

test("bundle-cross-signed gives the intermediate two issuers, in the shape of the stdin-cross-signed example", () => {
    const example = JSON.parse(readFileSync(new URL("stdin-cross-signed.json", examplesUrl), "utf8"));
    // The example is the intermediate followed by the bundle, so the intermediate appears twice.
    const observation = observe("intermediate.pem", "bundle-cross-signed.pem");

    const relations = (/** @type {typeof example} */ source) => ({
        target: source.target,
        certificates: source.certificates.map((/** @type {any} */ c) => [c.index, c.kind, c.selfSigned, c.issuedBy]),
        warnings: source.warnings,
    });
    assert.deepEqual(relations(observation), relations(example));
    assert.deepEqual(observation.certificates[0].issuedBy, [1, 2]);
});

test("duplicates are removed by sha256 before issuedBy and the target: the first occurrence is kept, index is renumbered and DUPLICATE_CERTIFICATE points at the kept copy", async (t) => {
    await t.test("bundle-duplicates.pem", () => {
        // leaf, intermediate, intermediate, root
        const observation = inspect(fixture("bundle-duplicates.pem"), { at: AT });
        assert.deepEqual(
            observation.certificates.map((c) => [c.index, c.sha256]),
            ["leaf-p256.pem", "intermediate.pem", "root-ca.pem"].map((name, index) => [index, fingerprint(name)]),
        );
        assert.deepEqual(observation.warnings, [
            { code: "DUPLICATE_CERTIFICATE", certificate: 1, message: "input block 3 duplicates input block 2 and was dropped" },
        ]);
        // The leaf has one issuer, not one per copy of the intermediate.
        assert.deepEqual(observation.certificates[0].issuedBy, [1]);
        assert.equal(targetHash(observation), fingerprint("leaf-p256.pem"));
    });

    await t.test("a copy is the same certificate however its base64 is wrapped", () => {
        const body = pem("intermediate.pem").split("\n").slice(1, -1).join("");
        const rewrapped = `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,40}/g)?.join("\n")}\n-----END CERTIFICATE-----`;
        const observation = inspect(`${pem("intermediate.pem")}\n${rewrapped}\n`, { at: AT });
        assert.equal(observation.certificates.length, 1);
        assert.equal(observation.warnings.length, 1);
    });

    await t.test("block numbers in the message count every PEM block, a key included", () => {
        const material = [pem("leaf-p256.pem"), pem("leaf-p256.key"), pem("leaf-p256.pem")].join("\n");
        const { warnings } = inspect(material, { at: AT });
        assert.deepEqual(warnings.map((w) => [w.certificate, w.message]), [[0, "input block 3 duplicates input block 1 and was dropped"]]);
    });

    await t.test("the first occurrence is the one kept, whatever comes between", () => {
        const { certificates, warnings } = observe("intermediate.pem", "leaf-p256.pem", "intermediate.pem", "root-ca.pem", "leaf-p256.pem");
        assert.deepEqual(certificates.map((c) => c.sha256), ["intermediate.pem", "leaf-p256.pem", "root-ca.pem"].map(fingerprint));
        assert.deepEqual(warnings.map((w) => [w.certificate, w.message]), [
            [0, "input block 3 duplicates input block 1 and was dropped"],
            [1, "input block 5 duplicates input block 2 and was dropped"],
        ]);
    });

    await t.test("every extra copy gets its own warning, all pointing at the kept one", () => {
        const { certificates, warnings } = observe("root-ca.pem", "root-ca.pem", "root-ca.pem");
        assert.equal(certificates.length, 1);
        assert.deepEqual(warnings.map((w) => [w.certificate, w.message]), [
            [0, "input block 2 duplicates input block 1 and was dropped"],
            [0, "input block 3 duplicates input block 1 and was dropped"],
        ]);
    });

    // Without the removal the two copies of the leaf would both be candidates for the target.
    await t.test("a copy of the target does not make the target ambiguous", () => {
        const observation = observe("leaf-p256.pem", "leaf-p256.pem", "intermediate.pem", "root-ca.pem");
        assert.equal(targetHash(observation), fingerprint("leaf-p256.pem"));
    });
});

test("the target is the only certificate that signs no other one, and signing itself does not count", async (t) => {
    await t.test("a self-signed certificate alone is its own target", () => {
        // It is in its own issuedBy. If that counted it would sign another one and nothing would be left.
        const observation = observe("root-ca.pem");
        assert.deepEqual([observation.target, observation.certificates[0].issuedBy], [0, [0]]);
    });

    await t.test("a root and its cross-signed copy: the copy signs the root, so the root is the target", () => {
        const observation = observe("root-ca-cross.pem", "root-ca.pem");
        assert.equal(targetHash(observation), fingerprint("root-ca.pem"));
        assert.equal(observation.target, 1);
    });

    await t.test("the target is the end of the chain, not the first or the last certificate", () => {
        const observation = observe("intermediate.pem", "leaf-p256.pem", "root-ca.pem");
        assert.equal(observation.target, 1);
    });
});

test("a single certificate is its own target whatever its kind: intermediate.pem alone is the target with kind ca", () => {
    const observation = observe("intermediate.pem");
    assert.equal(observation.target, 0);
    assert.equal(observation.certificates[0].kind, "ca");
    for (const name of SINGLES) {
        assert.equal(observe(name).target, 0, name);
    }
});

test("bundle-ordered and bundle-shuffled both resolve to the leaf, and bundle-no-leaf to the intermediate", () => {
    for (const name of ["bundle-ordered.pem", "bundle-shuffled.pem"]) {
        const observation = inspect(fixture(name), { at: AT });
        assert.equal(targetHash(observation), fingerprint("leaf-p256.pem"), name);
        assert.equal(observation.certificates[observation.target].kind, "end-entity");
    }
    const observation = inspect(fixture("bundle-no-leaf.pem"), { at: AT });
    assert.equal(targetHash(observation), fingerprint("intermediate.pem"));
});

test("more than one candidate throws an AmbiguousTargetError listing the candidates with their sha256 and common name", () => {
    const error = ambiguity(() => inspect(fixture("bundle-two-leaves.pem"), { at: AT }));
    assert.equal(error.name, "AmbiguousTargetError");
    assert.ok(error instanceof Error);
    assert.deepEqual(error.candidates, [
        { sha256: fingerprint("leaf-rsa.pem"), cn: "rsa.example" },
        { sha256: fingerprint("leaf-p256.pem"), cn: "p256.example" },
    ]);
    for (const { sha256, cn } of error.candidates) {
        assert.ok(error.message.includes(sha256), "the message names each fingerprint");
        assert.ok(error.message.includes(String(cn)), "the message names each common name");
    }
    assert.match(error.message, /input block 1\b.*\n.*input block 2\b/);
});

// What follows are cases the criteria do not name and the purpose of the chain covers.

test("a self-issued certificate under another key is not self-signed, and a key of another type does not verify the root", () => {
    // root-ca-rollover has the root's name, an RSA key, and the root's signature.
    const rollover = certificate("root-ca-rollover.pem");
    assert.equal(rollover.subject, rollover.issuer);
    assert.equal(rollover.verify(rollover.publicKey), false);

    const alone = observe("root-ca-rollover.pem").certificates[0];
    assert.deepEqual([alone.selfSigned, alone.issuedBy], [false, []]);

    // The root carries the same issuer and subject text as the rollover, but its key is an EC key.
    const { certificates, target } = observe("root-ca.pem", "root-ca-rollover.pem");
    assert.deepEqual(certificates.map((c) => [c.selfSigned, c.issuedBy]), [[true, [0]], [false, [0]]]);
    assert.equal(target, 1);
});

test("when every certificate signs another one, as with a root renewed under the same key, none is the target and all are candidates", () => {
    const error = ambiguity(() => inspect(fixture("bundle-renewed-root.pem"), { at: AT }));
    assert.deepEqual(error.candidates.map((c) => c.sha256), ["root-ca.pem", "root-ca-renewed.pem"].map(fingerprint));
    assert.match(error.message, /every certificate/);
    assert.deepEqual(error.candidates.map((c) => c.cn), ["certdrift test root CA", "certdrift test root CA"]);
});

test("an issuer name that differs only in case is not the issuer, even when its key verifies the signature", () => {
    const intermediate = certificate("intermediate.pem");
    const recased = certificate("root-ca-recased.pem");
    assert.equal(intermediate.verify(recased.publicKey), true);
    assert.notEqual(intermediate.issuer, recased.subject);
    assert.equal(intermediate.issuer.toLowerCase(), recased.subject.toLowerCase());

    // Were they linked, the intermediate would be the only certificate that signs no other.
    const error = ambiguity(() => observe("intermediate.pem", "root-ca-recased.pem"));
    assert.deepEqual(error.candidates.map((c) => c.sha256), ["intermediate.pem", "root-ca-recased.pem"].map(fingerprint));
});

test("a candidate without a subject is listed with a null common name", () => {
    const error = ambiguity(() => observe("leaf-no-cn.pem", "leaf-p256.pem", "intermediate.pem"));
    assert.deepEqual(error.candidates, [
        { sha256: fingerprint("leaf-no-cn.pem"), cn: null },
        { sha256: fingerprint("leaf-p256.pem"), cn: "p256.example" },
    ]);
    assert.match(error.message, /no common name/);
});

test("a candidate whose subject has a comma in its common name is listed unescaped", () => {
    const error = ambiguity(() => observe("leaf-multi-dn.pem", "leaf-p256.pem", "intermediate.pem"));
    assert.deepEqual(error.candidates.map((c) => c.cn), ["multi.example", "p256.example"]);
});

test("AmbiguousTargetError is an Error that carries its candidates", () => {
    const candidates = [{ sha256: "a".repeat(64), cn: null }];
    const error = new AmbiguousTargetError("two candidates", candidates);
    assert.ok(error instanceof Error);
    assert.deepEqual([error.name, error.message, error.candidates], ["AmbiguousTargetError", "two candidates", candidates]);
});
