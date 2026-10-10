/**
 * Values computed from the observation instant. Both are rounded to the nearest value with
 * halves away from zero, using integer arithmetic on whole seconds: a certificate stores whole
 * seconds and `at` is cut to the second, so the quotient is exact up to the rounding.
 * `Math.round` rounds halves toward positive infinity and can return `-0`, and `toFixed` rounds
 * the binary representation of the quotient instead of the quotient.
 *
 * Checks evaluate the dates themselves, never these rounded values.
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
