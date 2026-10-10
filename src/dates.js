import { types } from "node:util";
import { ParseError } from "./errors.js";

/**
 * A validity date of a certificate, as Node.js reads it.
 *
 * For a time that is not a real instant (30 February, a leap second) OpenSSL cannot convert it,
 * and `validFrom` and `validTo` say "Bad time value". The `Date` Node.js gives for that same
 * time cannot be trusted: it is built from memory nothing has written, so it is an Invalid Date
 * in one call and a date thousands of years away in the next, on the same certificate. The text
 * is the only reliable signal, so a date is accepted only when its text is a date too. The text
 * is never used for the value: it cannot say a year before 100.
 * @param {Date | undefined} date `validFromDate` or `validToDate`.
 * @param {string | undefined} text `validFrom` or `validTo`, the same instant as text.
 * @param {number} block Position of the input block, for the error.
 * @param {"notBefore" | "notAfter"} field
 * @returns {Date}
 * @throws {ParseError}
 */
export function validityDate(date, text, block, field) {
    if (typeof text !== "string" || Number.isNaN(Date.parse(text)) || !types.isDate(date) || Number.isNaN(date.getTime())) {
        throw new ParseError(`input block ${block} has a ${field} date that is not a valid instant`, block);
    }
    return date;
}
