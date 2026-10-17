/**
 * The Extended Key Usage OIDs the contract names, by name. Any other OID stays as text in the
 * observation.
 */
export const EXTENDED_KEY_USAGE_OIDS = Object.freeze({
    serverAuth: "1.3.6.1.5.5.7.3.1",
    clientAuth: "1.3.6.1.5.5.7.3.2",
    codeSigning: "1.3.6.1.5.5.7.3.3",
    emailProtection: "1.3.6.1.5.5.7.3.4",
    timeStamping: "1.3.6.1.5.5.7.3.8",
    OCSPSigning: "1.3.6.1.5.5.7.3.9",
});

/**
 * The OID of anyExtendedKeyUsage. It is not one of the six names, so the observation shows it as
 * this text. An extension that lists it forbids no usage (RFC 5280, 4.2.1.12).
 */
export const ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

/** @type {Map<string, string>} */
const NAMES = new Map(Object.entries(EXTENDED_KEY_USAGE_OIDS).map(([name, oid]) => [oid, name]));

/**
 * The name the observation gives a usage: its name when the contract has one for the OID, the OID
 * itself otherwise. A usage in a policy is read the same way, so an OID and its name are one usage.
 * @param {string} usage A name or an OID as dotted text.
 * @returns {string}
 */
export function usageName(usage) {
    return NAMES.get(usage) ?? usage;
}

/**
 * The extended key usages of a certificate, sorted. Node.js exposes them as `keyUsage`, a
 * misleading name: the OIDs are those of the Extended Key Usage extension, and the property is
 * `undefined` when the extension is absent, which is `null` here. An extension that is present
 * and empty is `[]`: the two differ, since an absent extension restricts nothing. It is also
 * `undefined` for an extension that is present and that Node.js cannot read, because it appears
 * more than once or its value does not decode, and that is `null` here too: `inspect()` adds an
 * EKU_UNRELIABLE warning to the observation for it.
 *
 * Repeated entries are kept, so the output shows what the certificate holds. Sorting is by code
 * unit, which does not depend on the machine's locale.
 * @param {readonly string[] | undefined} oids
 * @returns {string[] | null}
 */
export function extendedKeyUsage(oids) {
    if (oids === undefined) return null;
    return oids.map(usageName).sort();
}
