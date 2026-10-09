/**
 * The common name in the text Node.js gives for a subject or an issuer: one component per
 * line, `TYPE=value`, the components of a multi-valued RDN joined by ` + `, and a value
 * written with a backslash before every character that would be ambiguous (`\,`, `\+`, `\\`,
 * a leading `\#` or `\ `) and `\XX` for control characters.
 *
 * With more than one CN it is the last one: names are in certificate order, so the last is the
 * most specific.
 * @param {string | undefined} text `undefined` is what Node.js gives for an empty name.
 * @returns {string | null} `null` when the name has no CN component.
 */
export function commonName(text) {
    /** @type {string | null} */
    let found = null;
    for (const line of (text ?? "").split("\n")) {
        // A plus inside a value is always written `\+`, so a space, a plus and a space can only be
        // the separator of a multi-valued RDN.
        for (const attribute of line.split(" + ")) {
            const equals = attribute.indexOf("=");
            if (equals !== -1 && attribute.slice(0, equals) === "CN") {
                found = unescape(attribute.slice(equals + 1));
            }
        }
    }
    return found;
}

/**
 * `\XX` is one byte of the value's UTF-8; `\` before anything else stands for that character.
 * @param {string} value
 */
function unescape(value) {
    const characters = Array.from(value);
    /** @type {Buffer[]} */
    const bytes = [];
    for (let i = 0; i < characters.length; i += 1) {
        const hex = characters.slice(i + 1, i + 3).join("");
        if (characters[i] === "\\" && /^[0-9A-Fa-f]{2}$/.test(hex)) {
            bytes.push(Buffer.from(hex, "hex"));
            i += 2;
        } else if (characters[i] === "\\" && i + 1 < characters.length) {
            bytes.push(Buffer.from(characters[i + 1]));
            i += 1;
        } else {
            bytes.push(Buffer.from(characters[i]));
        }
    }
    return Buffer.concat(bytes).toString("utf8");
}
