/** The Extended Key Usage OIDs the contract names. Any other OID stays as text. */
const NAMES = new Map([
    ["1.3.6.1.5.5.7.3.1", "serverAuth"],
    ["1.3.6.1.5.5.7.3.2", "clientAuth"],
    ["1.3.6.1.5.5.7.3.3", "codeSigning"],
    ["1.3.6.1.5.5.7.3.4", "emailProtection"],
    ["1.3.6.1.5.5.7.3.8", "timeStamping"],
    ["1.3.6.1.5.5.7.3.9", "OCSPSigning"],
]);

/**
 * The extended key usages of a certificate, sorted. Node.js exposes them as `keyUsage`, a
 * misleading name: the OIDs are those of the Extended Key Usage extension, and the property is
 * `undefined` when the extension is absent, which is `null` here. An extension that is present
 * and empty is `[]`: the two differ, since an absent extension restricts nothing.
 *
 * Repeated entries are kept, so the output shows what the certificate holds. Sorting is by code
 * unit, which does not depend on the machine's locale.
 * @param {readonly string[] | undefined} oids
 * @returns {string[] | null}
 */
export function extendedKeyUsage(oids) {
    if (oids === undefined) return null;
    return oids.map((oid) => NAMES.get(oid) ?? oid).sort();
}
