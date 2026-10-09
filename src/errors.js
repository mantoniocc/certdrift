/**
 * The material given to the library is not a certificate, or not a readable one.
 * The message says which input block failed; `block` carries the same number for programs.
 */
export class ParseError extends Error {
    /**
     * @param {string} message
     * @param {{ block?: number | null, cause?: unknown }} [options]
     *   `block` is the 1-based position of the failing block in the input, or `null` when the
     *   failure is not about one block (for example, empty material).
     */
    constructor(message, { block = null, cause } = {}) {
        super(message, cause === undefined ? undefined : { cause });
        this.name = "ParseError";
        /** @type {number | null} */
        this.block = block;
    }
}
