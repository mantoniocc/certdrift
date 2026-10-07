import test from "node:test";
import assert from "node:assert/strict";

test("fails on purpose to prove that a red check blocks the merge", () => {
    assert.equal(1, 2);
});
