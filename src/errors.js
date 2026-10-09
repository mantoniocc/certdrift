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

/**
 * The material holds more than one certificate that could be the one it is about, and nothing
 * in the material says which. Picking one by position would make the answer depend on the order
 * of the file.
 */
export class AmbiguousTargetError extends Error {
    /**
     * @param {string} message Lists the candidates, with their input block.
     * @param {{ sha256: string, cn: string | null }[]} candidates In the order of the material.
     */
    constructor(message, candidates) {
        super(message);
        this.name = "AmbiguousTargetError";
        this.candidates = candidates;
    }
}
