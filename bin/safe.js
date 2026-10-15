/**
 * What a certificate puts in a name can be anything, and a terminal obeys control characters:
 * an escape sequence could retitle the window or repaint the screen, and a right-to-left mark
 * could reverse what comes after it. Control, format, line and paragraph separators and lone
 * surrogates are shown as `\u{XX}` so the person sees what the certificate holds.
 *
 * Everything a command prints that it did not write itself goes through this one function, so
 * every command escapes the same characters the same way.
 * @param {string} text
 */
export function safe(text) {
    return text.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, (character) => `\\u{${/** @type {number} */ (character.codePointAt(0)).toString(16).toUpperCase()}}`);
}

/**
 * Text that is itself several lines, as a list of candidates or an error's stack is: the line
 * breaks are the writer's own and stay, and what is inside each line is escaped, because `safe`
 * would turn the breaks into text too.
 * @param {string} text
 */
export function perLine(text) {
    return text.split("\n").map(safe).join("\n");
}
