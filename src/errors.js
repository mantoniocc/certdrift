/**
 * The material handed to the library is not a readable certificate or set of certificates.
 * It is about the bytes, never about how the library was called: a wrong argument type is a
 * plain `TypeError`.
 */
export class ParseError extends Error {
    /**
     * @param {string} message Says which input block failed, counting blocks from 1.
     * @param {number | null} block The failing input block, or `null` when the material
     *   has no blocks to point at (it is empty, or holds no certificate).
     * @param {{ cause?: unknown }} [options] `cause` is the error Node.js raised, if any.
     */
    constructor(message, block, options) {
        super(message, options);
        this.name = "ParseError";
        /** @type {number | null} */
        this.block = block;
    }
}
