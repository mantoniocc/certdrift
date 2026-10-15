import { types } from "node:util";

/**
 * Values computed from the observation instant. Both are rounded to the nearest value with
 * halves away from zero, using integer arithmetic on whole seconds: a certificate stores whole
 * seconds and `at` is cut to the second, so the quotient is exact up to the rounding.
 * `Math.round` rounds halves toward positive infinity and can return `-0`, and `toFixed` rounds
 * the binary representation of the quotient instead of the quotient.
 *
 * Checks evaluate the dates themselves, never these rounded values: `outsideValidity` below is
 * that evaluation for the validity period.
 * @param {Date} notBefore
 * @param {Date} notAfter
 * @param {Date} at
 * @returns {{ daysRemaining: number, lifetimeFraction: number | null }}
 */
export function derivedOf(notBefore, notAfter, at) {
    const start = seconds(notBefore);
    const end = seconds(notAfter);
    const now = seconds(at);
    const duration = end - start;
    return {
        daysRemaining: scaled(end - now, 86400, 10),
        // A validity period with no duration, or a negative one, has no fraction to speak of.
        lifetimeFraction: duration > 0 ? scaled(now - start, duration, 100) : null,
    };
}

/** @param {Date} date */
function seconds(date) {
    return Math.floor(date.getTime() / 1000);
}

/**
 * `numerator / denominator` rounded to `1 / steps` (10 is one decimal, 100 is two).
 * @param {number} numerator
 * @param {number} denominator Positive.
 * @param {number} steps
 */
function scaled(numerator, denominator, steps) {
    const magnitude = Math.floor((2 * steps * Math.abs(numerator) + denominator) / (2 * denominator));
    if (magnitude === 0) return 0;
    return (numerator < 0 ? -magnitude : magnitude) / steps;
}

/**
 * The pattern of the contract's timestamps: ISO 8601 in UTC with whole seconds. Anything else
 * that `Date.parse` accepts, such as a time with no `Z` (read as local time) or a fraction, is
 * not an instant the observation can hold.
 */
const TIMESTAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

/**
 * In which ways an instant falls outside a validity period: `"not yet valid"` when `notBefore`
 * is after it and `"expired"` when `notAfter` is before it. It is `[]` for an instant inside the
 * period, and both ends belong to the period, so an instant equal to either of them is inside.
 *
 * The two conditions are independent, as the reason codes `NOT_YET_VALID` and `EXPIRED` are, and
 * a period whose `notAfter` is before its `notBefore` can fail both between its dates. A caller
 * that decides one of them asks for its word with `includes`, and one that writes a message
 * uses the word itself, so the rule and the words exist only here.
 *
 * It decides from the dates and never from `daysRemaining`, which is rounded: a certificate that
 * expired an hour ago reads `0 days`. The instant is any instant, not the observation's `at`: an
 * evaluation can ask about another one.
 *
 * Each argument is the observation's timestamp text, or a `Date`, which is cut to the whole
 * second as `inspect()` cuts `at`, because the instant an evaluation records has whole seconds.
 * @param {string | Date} notBefore
 * @param {string | Date} notAfter
 * @param {string | Date} now
 * @returns {("not yet valid" | "expired")[]}
 * @throws {TypeError} An argument is not a valid instant. Returning an answer for one would read
 *   a mistake as a current validity.
 */
export function outsideValidity(notBefore, notAfter, now) {
    const start = instant(notBefore, "notBefore");
    const end = instant(notAfter, "notAfter");
    const at = instant(now, "now");
    /** @type {("not yet valid" | "expired")[]} */
    const outside = [];
    if (start > at) outside.push("not yet valid");
    if (end < at) outside.push("expired");
    return outside;
}

/**
 * An instant as whole seconds. A text must have exactly the form of the contract's timestamps and
 * be a real instant: `Date.parse` moves 30 February to 2 March and reads 24:00:00 as the next
 * day, so the text is written back and has to come out the same.
 *
 * A `Date` is read through the engine's own `getTime`, not the object's: a subclass can override
 * the method to answer anything, and a comparison with something that is not a number is false
 * both ways, which would read as a current validity.
 * @param {unknown} value
 * @param {string} name What the value is, for the message.
 * @returns {number} Whole seconds since the epoch, rounded down: `Math.floor` moves an instant
 *   before 1970 back, where `Math.trunc` would move it forward.
 * @throws {TypeError} The value is not a valid instant.
 */
export function instant(value, name) {
    const date = typeof value === "string" ? new Date(value) : value;
    const time = types.isDate(date) ? Date.prototype.getTime.call(date) : Number.NaN;
    const valid =
        typeof value === "string"
            ? TIMESTAMP.test(value) && Number.isFinite(time) && new Date(time).toISOString().replace(".000Z", "Z") === value
            : Number.isFinite(time);
    if (!valid) throw new TypeError(`${name} must be a valid Date or a timestamp such as 2026-09-15T14:02:11Z`);
    return Math.floor(time / 1000);
}

/**
 * The contract's timestamp for an instant given as whole seconds since the epoch: ISO 8601 in UTC,
 * with no fraction. The contract's pattern has four digits for the year, so an instant outside the
 * years 0 to 9999, which `toISOString()` writes with a signed six-digit year, cannot be written.
 * @param {number} seconds
 * @param {string} name What the instant is, for the message.
 * @returns {string}
 * @throws {TypeError} The instant is outside the years 0 to 9999.
 */
export function timestampOf(seconds, name) {
    const text = new Date(seconds * 1000).toISOString();
    if (!/^\d{4}-/.test(text)) throw new TypeError(`${name} must fall between the years 0 and 9999`);
    return text.replace(".000Z", "Z");
}
