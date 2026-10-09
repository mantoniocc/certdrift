import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import { commonName } from "../src/names.js";

// The input is the text Node.js gives for a subject or an issuer: one component per line, a
// backslash before every ambiguous character, `\XX` for control characters.

/** @type {[string, string | undefined, string | null][]} */
const CASES = [
    ["an empty name, which Node.js gives as undefined", undefined, null],
    ["an empty string", "", null],
    ["a plain common name", "CN=example.com", "example.com"],
    ["a name without a CN", "C=CL\nO=Acme", null],
    ["the CN among other components", "C=CL\nO=Acme\nOU=Platform\nCN=multi.example", "multi.example"],
    ["an escaped comma", "CN=Doe\\, John", "Doe, John"],
    ["an escaped comma in another component", "O=Acme\\, Inc.\nCN=x", "x"],
    ["the text CN= inside another value is not a component", "O=a\\, CN=b", null],
    ["a CN= after a space inside another value is not a component", "O=x CN=fake", null],
    ["two CNs: the last, the most specific", "CN=first\nCN=second", "second"],
    ["a multi-valued RDN, CN first", "CN=a + O=b\nOU=x", "a"],
    ["a multi-valued RDN, CN last", "O=b + CN=a", "a"],
    ["an escaped plus is part of the value", "CN=a \\+ b", "a + b"],
    ["an escaped backslash right before a separator", "CN=a\\\\ + O=b", "a\\"],
    ["a leading escaped space and a trailing one", "CN=\\ padded\\ ", " padded "],
    ["a leading escaped hash", "CN=\\#tag", "#tag"],
    ["an escaped quote, angle brackets and semicolon", 'CN=\\"x\\"\\<\\>\\;', '"x"<>;'],
    ["a control character as hex", "CN=line\\0Abreak", "line\nbreak"],
    ["a character written as the hex of its UTF-8 bytes", "CN=\\C3\\91and\\C3\\BA", "Ñandú"],
    ["a character written as is", "CN=Ñandú ✓", "Ñandú ✓"],
    ["a backslash that escapes nothing at the end", "CN=a\\", "a\\"],
    ["an empty CN", "CN=", ""],
];

for (const [name, text, expected] of CASES) {
    test(`commonName: ${name}`, () => {
        assert.equal(commonName(text), expected);
    });
}

test("commonName reads the subject of the fixtures that carry the awkward cases", () => {
    /** @param {string} file */
    const subject = (file) => new X509Certificate(readFileSync(new URL(`fixtures/${file}`, import.meta.url))).subject;
    assert.equal(commonName(subject("leaf-multi-dn.pem")), "multi.example");
    assert.equal(commonName(subject("leaf-no-cn.pem")), null);
    assert.equal(commonName(subject("root-ca-recased.pem")), "Certdrift Test Root CA");
});
