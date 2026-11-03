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

/**
 * Two observations that `diff` was asked to compare do not describe the same kind of document:
 * they have another `contract` number or another `format`. What a field means depends on both, so
 * comparing them would read one version's fields as the other's. It is not about the certificates,
 * whose differences are never an error, and not a wrong call either: a program that keeps old
 * observations meets it when the library moves on, and catches it apart from `TypeError`.
 *
 * `field` says which of the two differs. When both do, it is `contract`, the one that decides what
 * `format` can mean. The message never quotes the format, which is text of the caller's.
 */
export class ContractMismatchError extends Error {
    /**
     * @param {"contract" | "format"} field
     * @param {string} message
     */
    constructor(field, message) {
        super(message);
        this.name = "ContractMismatchError";
        this.field = field;
    }
}

/**
 * The policy given to `evaluate` is not one it can apply: its shape is wrong, its `contract` is not
 * one this version knows, or it lists an entry that needs an input `evaluate` was not given. That
 * is misuse of the call, not a failed check, so it is an error and not a result.
 *
 * The message says how many problems there are and nothing else: a policy is a document people
 * share, and a value in the wrong place may be a secret. Each problem has a `path` and a message
 * that quotes no value of the policy.
 */
export class PolicyError extends Error {
    /**
     * @param {{ path: string, message: string }[]} problems What is wrong, at least one.
     */
    constructor(problems) {
        super(`the policy is not valid: ${problems.length} problem${problems.length === 1 ? "" : "s"}`);
        this.name = "PolicyError";
        /** @type {{ path: string, message: string }[]} */
        this.problems = problems.map(({ path, message }) => ({ path, message }));
    }
}
