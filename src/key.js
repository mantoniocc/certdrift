/** The NIST names of the curves Node.js reports under their OpenSSL names, with their size in bits. */
const NIST_CURVES = new Map([
    ["prime256v1", { name: "P-256", size: 256 }],
    ["secp384r1", { name: "P-384", size: 384 }],
    ["secp521r1", { name: "P-521", size: 521 }],
]);

/**
 * What the contract says about a certificate's public key.
 *
 * `asymmetricKeyDetails` is read field by field and never copied as a whole: for RSA it holds
 * `publicExponent` as a BigInt, which `JSON.stringify` refuses, and for RSA-PSS and others it
 * holds fields the contract does not describe.
 *
 * - `size` is the modulus length for RSA and RSA-PSS, and the size of a NIST curve. Everything
 *   else, including DSA and curves outside the map, has none.
 * - `curve` is the NIST name when there is one, otherwise the name Node.js reports, so an
 *   unexpected curve is visible instead of silently missing.
 * @param {{ asymmetricKeyType?: string, asymmetricKeyDetails?: { modulusLength?: number, namedCurve?: string } }} publicKey
 * @returns {{ algorithm: string | null, size: number | null, curve: string | null }}
 */
export function publicKeyOf(publicKey) {
    const algorithm = publicKey.asymmetricKeyType?.toLowerCase() ?? null;
    const details = publicKey.asymmetricKeyDetails;

    if (algorithm === "rsa" || algorithm === "rsa-pss") {
        const bits = details?.modulusLength;
        return { algorithm, size: typeof bits === "number" && Number.isInteger(bits) && bits > 0 ? bits : null, curve: null };
    }
    if (algorithm === "ec") {
        const reported = details?.namedCurve;
        if (typeof reported !== "string" || reported === "") return { algorithm, size: null, curve: null };
        const nist = NIST_CURVES.get(reported);
        return { algorithm, size: nist?.size ?? null, curve: nist?.name ?? reported };
    }
    return { algorithm, size: null, curve: null };
}
