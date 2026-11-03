// Observations built by hand, for the tests of what is done with an observation and not of how
// one is made from a certificate: no certificate, no fixture, and so nothing here changes when the
// fixtures are generated again. The shape is the one `inspect()` writes, in the same key order.

/**
 * A 64-character lowercase hexadecimal text that stands for a certificate's SHA-256. Each number
 * is another certificate.
 * @param {number} number
 * @returns {string}
 */
export function hashOf(number) {
    return number.toString(16).padStart(64, "0");
}

/**
 * A certificate as `inspect()` writes one, with the fields a test names replaced. A name may be a
 * path (`"san.dns"`), which replaces one field inside an object.
 * @param {Record<string, unknown>} [replacing]
 * @returns {any}
 */
export function certificateWith(replacing = {}) {
    /** @type {any} */
    const certificate = {
        index: 0,
        kind: "end-entity",
        selfSigned: false,
        issuedBy: [],
        subject: { cn: "service.example", dn: "CN=service.example" },
        issuer: { cn: "Example CA", dn: "CN=Example CA" },
        serial: "01",
        notBefore: "2026-01-01T00:00:00Z",
        notAfter: "2026-04-01T00:00:00Z",
        san: { dns: ["service.example"], ip: [], email: [], uri: [] },
        eku: ["serverAuth"],
        key: { algorithm: "ec", size: 256, curve: "P-256" },
        sha256: hashOf(1),
        spkiSha256: hashOf(2),
        derived: { daysRemaining: 10, lifetimeFraction: 0.5 },
    };
    for (const [path, value] of Object.entries(replacing)) {
        const keys = path.split(".");
        const last = /** @type {string} */ (keys.pop());
        const holder = keys.reduce((object, key) => object[key], certificate);
        holder[last] = value;
    }
    return certificate;
}

/**
 * An observation as `inspect()` returns it.
 *
 * `target` replaces fields of the target certificate (see `certificateWith`). `chain` is the
 * `sha256` of each certificate other than the target, in order, and `targetAt` is where the target
 * sits among all the certificates, 0 unless a test says: the observation lists the target first
 * only when nothing signs it from the material.
 * @param {{ target?: Record<string, unknown>, chain?: string[], targetAt?: number, at?: string, source?: Record<string, unknown>, warnings?: unknown[] }} [options]
 * @returns {any}
 */
export function make({ target = {}, chain = [], targetAt = 0, at = "2026-09-15T14:02:11Z", source = { kind: "file", ref: "service.pem" }, warnings = [] } = {}) {
    const others = chain.map((sha256) => certificateWith({ kind: "ca", "subject.cn": "Link", sha256 }));
    const certificates = [...others.slice(0, targetAt), certificateWith(target), ...others.slice(targetAt)];
    certificates.forEach((certificate, index) => {
        certificate.index = index;
    });
    return { contract: 1, format: "x509", observation: { at, source }, target: targetAt, certificates, warnings };
}

/**
 * The same value with the keys of every object in the opposite order, and so built another way:
 * what is compared or written from it must not depend on the order a caller made its objects in.
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function withKeysReversed(value) {
    if (Array.isArray(value)) return /** @type {any} */ (value.map(withKeysReversed));
    if (typeof value !== "object" || value === null) return value;
    return /** @type {any} */ (Object.fromEntries(Object.entries(value).reverse().map(([key, inside]) => [key, withKeysReversed(inside)])));
}

/**
 * Freezes a value and everything inside it.
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function deepFrozen(value) {
    if (typeof value === "object" && value !== null) {
        for (const inside of Object.values(value)) deepFrozen(inside);
        Object.freeze(value);
    }
    return value;
}
