import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspect, ParseError } from "../src/index.js";
import { subjectAltNames, canonicalAddress } from "../src/san.js";
import { validatorFor } from "./helpers/schema.js";

const fixturesUrl = new URL("fixtures/", import.meta.url);
const errorsOf = validatorFor("observation");
const AT = new Date("2026-09-15T14:02:11Z");

/** @param {string} name File name in test/fixtures/. */
function fixture(name) {
    return readFileSync(new URL(name, fixturesUrl));
}

/** @param {string} name The certificate alone, as a one-certificate observation. */
function observe(name) {
    return inspect(fixture(name), { at: AT });
}

/** @param {string} name */
function sanOf(name) {
    return observe(name).certificates[0].san;
}

/**
 * The names in a SAN text, as the lists the observation holds.
 * @param {string | undefined} text
 */
function namesIn(text) {
    return subjectAltNames(text, 1).names;
}

// What Node.js writes for the extension is the input of everything below. These texts were
// captured from it, from the fixtures and from hand-built certificates, so they are the real
// shape and not a guess at it.

test("splits entries on a comma and space outside quoted values, each on its first colon, and decodes quoted values with JSON.parse: leaf-san-comma.pem and leaf-san-quotes.pem", async (t) => {
    await t.test("leaf-san-comma.pem: a comma inside a value does not make another name", () => {
        const { dns, uri } = sanOf("leaf-san-comma.pem");
        assert.deepEqual(dns, ["a, b.example", "comma.example"]);
        assert.deepEqual(uri, ["https://example.com/x, y"]);
    });

    await t.test("leaf-san-comma.pem: the text inside its DirName does not leak into any list", () => {
        const { dns, ip, email, uri } = sanOf("leaf-san-comma.pem");
        assert.equal([...dns, ...ip, ...email, ...uri].filter((name) => /John|certdrift/.test(name)).length, 0);
    });

    await t.test("leaf-san-quotes.pem: quotes inside a value are decoded", () => {
        const { dns, uri } = sanOf("leaf-san-quotes.pem");
        assert.deepEqual(dns, ['q"uote.example', "quotes.example"]);
        assert.deepEqual(uri, ['https://example.com/"q"']);
    });

    await t.test("a quoted value keeps a comma and space even when the text does not escape it", () => {
        // Node.js writes the comma as ,, but nothing here relies on it: a split on ", " would break this.
        assert.deepEqual(namesIn('DNS:"a, b", DNS:c').dns, ["a, b", "c"]);
    });

    await t.test("a quoted value that looks like another entry stays one name", () => {
        assert.deepEqual(namesIn('DNS:"x\\u002c DNS:injected.example"').dns, ["x, dns:injected.example"]);
    });

    await t.test("each entry is split on its first colon: the value keeps the others", () => {
        const { names } = subjectAltNames("URI:https://example.com:8443/a:b, email:a:b@example.com, DNS:IP Address:1.2.3.4", 1);
        assert.deepEqual(names.uri, ["https://example.com:8443/a:b"]);
        assert.deepEqual(names.email, ["a:b@example.com"]);
        assert.deepEqual(names.dns, ["ip address:1.2.3.4"]);
        assert.deepEqual(names.ip, []);
    });

    await t.test("an unquoted value runs up to the next comma and space", () => {
        assert.deepEqual(namesIn("DNS:a.example,b.example, DNS:c.example").dns, ["a.example,b.example", "c.example"]);
    });
});

test("the prefix for addresses is IP Address:, and nothing else is read as an address", () => {
    assert.deepEqual(sanOf("leaf-san-kinds.pem").ip, ["192.0.2.10", "2001:db8::1"]);

    // Only the prefix Node.js writes is an address. `IP` is a type like any other that has no list.
    const { names, unrepresented } = subjectAltNames("IP:192.0.2.1, DNS:192.0.2.2, IP Address:192.0.2.3", 1);
    assert.deepEqual(names.ip, ["192.0.2.3"]);
    assert.deepEqual(names.dns, ["192.0.2.2"]);
    assert.deepEqual(unrepresented, [{ type: "IP", count: 1 }]);
});

test("the four lists are always present and empty when there is nothing: dns lowercase and sorted, ip canonical and sorted, email and uri sorted", async (t) => {
    await t.test("a certificate without the extension", () => {
        assert.deepEqual(sanOf("root-ca.pem"), { dns: [], ip: [], email: [], uri: [] });
    });

    await t.test("no text and an empty text", () => {
        for (const text of [undefined, ""]) {
            assert.deepEqual(subjectAltNames(text, 1), { names: { dns: [], ip: [], email: [], uri: [] }, unrepresented: [] });
        }
    });

    await t.test("the lists come out in their order whatever the order in the certificate", () => {
        const text = [
            "DNS:b.example", "DNS:WWW.Example.COM", "DNS:a.example",
            "IP Address:2001:DB8:0:0:0:0:0:1", "IP Address:10.0.0.2", "IP Address:9.0.0.1", "IP Address:0:0:0:0:0:0:0:1",
            "email:z@example.com", "email:Ops@example.com", "email:a@example.com",
            "URI:https://z.example/", "URI:HTTPS://Example.com/Path", "URI:https://a.example/",
        ].join(", ");
        assert.deepEqual(namesIn(text), {
            dns: ["a.example", "b.example", "www.example.com"],
            // Sorted as text, like the rest: a second, numeric order would be a second rule.
            ip: ["10.0.0.2", "2001:db8::1", "9.0.0.1", "::1"],
            email: ["Ops@example.com", "a@example.com", "z@example.com"],
            uri: ["HTTPS://Example.com/Path", "https://a.example/", "https://z.example/"],
        });
    });

    await t.test("only email and uri keep their case: they are not folded", () => {
        assert.deepEqual(namesIn("email:Ops@Example.COM, URI:HTTPS://Example.com/Path").email, ["Ops@Example.COM"]);
    });

    await t.test("dns lowercases A to Z and leaves every other letter as it is", () => {
        // É is U+00C9; folding it would turn the byte Node.js reported into a different one.
        assert.deepEqual(namesIn('DNS:"\\u00c9XAMPLE.COM"').dns, ["Éxample.com"]);
    });

    await t.test("a name that appears twice appears twice", () => {
        assert.deepEqual(namesIn("DNS:a.example, DNS:A.example").dns, ["a.example", "a.example"]);
    });

    await t.test("every fixture has all four lists", () => {
        for (const name of ["leaf-p256.pem", "leaf-san-kinds.pem", "leaf-san-comma.pem", "intermediate.pem", "root-ca.pem"]) {
            assert.deepEqual(Object.keys(sanOf(name)), ["dns", "ip", "email", "uri"], name);
        }
    });
});

test("canonical IPv6 is compressed and lowercase without any dependency: ::, leading zeros, an embedded IPv4 address and uppercase input", async (t) => {
    /** @type {[string, string, string][]} */
    const CASES = [
        ["the unspecified address", "0:0:0:0:0:0:0:0", "::"],
        ["the unspecified address, already compressed", "::", "::"],
        ["the loopback address", "0:0:0:0:0:0:0:1", "::1"],
        ["the loopback address, compressed", "::1", "::1"],
        ["Node.js's spelling: eight groups, uppercase", "2001:DB8:0:0:0:0:0:1", "2001:db8::1"],
        ["leading zeros", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
        ["uppercase", "FE80::ABCD", "fe80::abcd"],
        ["the first of two equal runs is compressed", "2001:0db8:0000:0000:0001:0000:0000:0001", "2001:db8::1:0:0:1"],
        ["the longest run is compressed, not the first", "1:0:0:2:0:0:0:3", "1:0:0:2::3"],
        ["a single zero group is written, not compressed", "1:0:1:0:1:0:1:0", "1:0:1:0:1:0:1:0"],
        ["a run at the start", "0:0:1:2:3:4:5:6", "::1:2:3:4:5:6"],
        ["a run at the end", "1:2:3:4:5:6:0:0", "1:2:3:4:5:6::"],
        ["a :: that stands for one group is written out", "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"],
        ["an embedded IPv4 address, mapped", "::ffff:192.0.2.1", "::ffff:c000:201"],
        ["an embedded IPv4 address, in full", "0:0:0:0:0:FFFF:192.0.2.1", "::ffff:c000:201"],
        ["an embedded IPv4 address, compatible", "::192.0.2.1", "::c000:201"],
        ["an embedded IPv4 address after another prefix", "64:ff9b::192.0.2.33", "64:ff9b::c000:221"],
        ["an embedded IPv4 address that is not compressed away", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"],
        ["IPv4", "192.0.2.10", "192.0.2.10"],
        ["IPv4 at its limits", "255.255.255.255", "255.255.255.255"],
        ["IPv4 zeros", "0.0.0.0", "0.0.0.0"],
    ];
    for (const [name, text, expected] of CASES) {
        await t.test(name, () => assert.equal(canonicalAddress(text), expected));
    }

    await t.test("text that is not an address gives null", () => {
        const NOT_ADDRESSES = [
            "", " ", "::1 ", " ::1", ":", ":::", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8",
            "12345::", "g::1", "::1%eth0", "::ffff:1.2.3", "::ffff:1.2.3.256", "1.2.3.4::", "::1.2.3.4:1", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
            "1.2.3", "1.2.3.4.5", "256.0.0.1", "010.0.0.1", "1.2.3.04", "-1.2.3.4", "1.2.3.4/24", "example.com", "<invalid length=5>",
        ];
        for (const text of NOT_ADDRESSES) assert.equal(canonicalAddress(text), null, JSON.stringify(text));
    });

    // The WHATWG URL serializer writes IPv6 the same way, and nothing here is derived from it,
    // so it checks the implementation instead of repeating it. Every address made of the groups
    // 0, 1 and ffff covers every shape of zero run, 3^8 of them.
    await t.test("agrees with Node.js's URL serializer on every address made of the groups 0, 1 and ffff, in three spellings", () => {
        const groups = ["0", "1", "ffff"];
        let checked = 0;
        for (let n = 0; n < 3 ** 8; n += 1) {
            const written = Array.from({ length: 8 }, (_, i) => groups[Math.floor(n / 3 ** i) % 3]);
            const expected = new URL(`http://[${written.join(":")}]/`).hostname.slice(1, -1);
            const padded = written.map((group) => group.padStart(4, "0").toUpperCase()).join(":");
            for (const text of [written.join(":"), padded, written.join(":").toUpperCase()]) {
                assert.equal(canonicalAddress(text), expected, text);
                checked += 1;
            }
        }
        assert.equal(checked, 3 * 6561);
    });

    await t.test("agrees with Node.js's URL serializer on addresses with an IPv4 tail", () => {
        for (const text of ["::1.2.3.4", "::ffff:1.2.3.4", "1::1.2.3.4", "64:ff9b::1.2.3.4", "0:0:0:0:0:0:0.0.0.0", "1:2:3:4:5:6:255.255.255.255"]) {
            assert.equal(canonicalAddress(text), new URL(`http://[${text}]/`).hostname.slice(1, -1), text);
        }
    });
});

test("a type the contract does not represent gives one SAN_TYPE_UNREPRESENTED warning per certificate and type, pointing at that certificate: leaf-san-kinds.pem", async (t) => {
    /** @param {import("../src/inspect.js").Observation} observation */
    const sanWarnings = (observation) => observation.warnings.filter((warning) => warning.code === "SAN_TYPE_UNREPRESENTED");

    await t.test("leaf-san-kinds.pem: its DirName and its otherName each give one, and the names it can represent are all there", () => {
        const observation = observe("leaf-san-kinds.pem");
        const warnings = sanWarnings(observation);
        assert.equal(warnings.length, 2);
        assert.deepEqual(warnings.map((warning) => warning.certificate), [0, 0]);
        assert.match(warnings[0].message, /DirName/);
        assert.match(warnings[1].message, /othername/);
        assert.deepEqual(observation.certificates[0].san, {
            dns: ["kinds.example"],
            ip: ["192.0.2.10", "2001:db8::1"],
            email: ["ops@example.com"],
            uri: ["https://example.com/service"],
        });
        assert.deepEqual(errorsOf(observation), []);
    });

    await t.test("the warning points at the certificate's index, not its input block", () => {
        const leaf = fixture("leaf-san-kinds.pem").toString("latin1");
        const intermediate = fixture("intermediate.pem").toString("latin1");
        const observation = inspect(intermediate + leaf, { at: AT });
        assert.equal(observation.certificates[1].san.dns[0], "kinds.example");
        assert.deepEqual(sanWarnings(observation).map((warning) => warning.certificate), [1, 1]);
        assert.deepEqual(errorsOf(observation), []);
    });

    await t.test("after a duplicate was dropped it points at the index the certificate has in the observation, and follows the duplicate warning", () => {
        const leaf = fixture("leaf-san-kinds.pem").toString("latin1");
        const intermediate = fixture("intermediate.pem").toString("latin1");
        // Input blocks 1 and 2 are the same certificate, so the leaf is block 3 and index 1.
        const observation = inspect(intermediate + intermediate + leaf, { at: AT });
        assert.deepEqual(observation.warnings.map((warning) => [warning.code, warning.certificate]), [
            ["DUPLICATE_CERTIFICATE", 0],
            ["SAN_TYPE_UNREPRESENTED", 1],
            ["SAN_TYPE_UNREPRESENTED", 1],
        ]);
    });

    await t.test("several entries of one type in a certificate give one warning for the type, in order of first appearance", () => {
        // Made with: openssl req -new -x509 -key <P-256 key> -subj /CN=many.example -days 3650 -addext
        //   "subjectAltName=DNS:many.example,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:a@example.com,RID:1.2.3.4,
        //   otherName:1.3.6.1.4.1.311.20.2.3;UTF8:b@example.com,RID:1.2.3.5"
        // Node.js writes it as: DNS:many.example, othername:UPN:a@example.com, Registered ID:1.2.3.4,
        //   othername:UPN:b@example.com, Registered ID:1.2.3.5
        const pem = [
            "-----BEGIN CERTIFICATE-----",
            "MIIBszCCAVqgAwIBAgIUcrltkqi2JwEwsr6LVnehlbM1oV4wCgYIKoZIzj0EAwIw",
            "FzEVMBMGA1UEAwwMbWFueS5leGFtcGxlMB4XDTI2MTAxMDE3NDMxNloXDTM2MTAw",
            "NzE3NDMxNlowFzEVMBMGA1UEAwwMbWFueS5leGFtcGxlMFkwEwYHKoZIzj0CAQYI",
            "KoZIzj0DAQcDQgAEv3Va1nb6Exh1RGloZ0Hpcgpn78a3nAYDDHJaVW81BJBXBFft",
            "RU1tjN9cAS4CSQMaDnDySbcDFUk2wzzuML7CaKOBgzCBgDBfBgNVHREEWDBWggxt",
            "YW55LmV4YW1wbGWgHQYKKwYBBAGCNxQCA6APDA1hQGV4YW1wbGUuY29tiAMqAwSg",
            "HQYKKwYBBAGCNxQCA6APDA1iQGV4YW1wbGUuY29tiAMqAwUwHQYDVR0OBBYEFKhp",
            "D30NlqhjKwCIjnaKclqiLI/fMAoGCCqGSM49BAMCA0cAMEQCIDjg4SBeU9KwKR19",
            "rVXyeuUEx21pja5taVvtdr+QlCWVAiABP0EwY9p39B1z3XmqW8qmCtPhgOKz5I89",
            "/79t4llnDw==",
            "-----END CERTIFICATE-----",
            "",
        ].join("\n");
        const observation = inspect(pem, { at: AT });
        assert.deepEqual(observation.certificates[0].san, { dns: ["many.example"], ip: [], email: [], uri: [] });
        assert.deepEqual(observation.warnings.map((warning) => [warning.code, warning.certificate]), [
            ["SAN_TYPE_UNREPRESENTED", 0],
            ["SAN_TYPE_UNREPRESENTED", 0],
        ]);
        assert.match(observation.warnings[0].message, /2 othername entries/);
        assert.match(observation.warnings[1].message, /2 Registered ID entries/);
        assert.deepEqual(errorsOf(observation), []);
    });

    await t.test("several entries of one type give one warning that counts them", () => {
        const { names, unrepresented } = subjectAltNames('DirName:"CN=a", DNS:x.example, DirName:"CN=b", othername:UPN:u@example.com, DirName:"CN=c"', 1);
        assert.deepEqual(names.dns, ["x.example"]);
        assert.deepEqual(unrepresented, [{ type: "DirName", count: 3 }, { type: "othername", count: 1 }]);
    });

    await t.test("a certificate with only representable names gives none", () => {
        assert.deepEqual(sanWarnings(observe("leaf-p256.pem")), []);
        assert.deepEqual(observe("leaf-p256.pem").warnings, []);
    });

    await t.test("every type Node.js writes that has no list is reported, with the label it writes", () => {
        for (const label of ["DirName", "othername", "Registered ID", "X400Name", "EdiPartyName"]) {
            const value = label === "DirName" ? '"CN=a"' : label === "Registered ID" ? "1.2.3.4" : "<unsupported>";
            assert.deepEqual(subjectAltNames(`${label}:${value}`, 1).unrepresented, [{ type: label, count: 1 }], label);
        }
    });

    await t.test("a type Node.js may write in the future is reported too, not dropped", () => {
        const { names, unrepresented } = subjectAltNames("Frobnicate:x, DNS:a.example", 1);
        assert.deepEqual(unrepresented, [{ type: "Frobnicate", count: 1 }]);
        assert.deepEqual(names.dns, ["a.example"]);
    });
});

test("no generic list is added for unrepresented types: san holds exactly dns, ip, email and uri", () => {
    for (const name of ["leaf-san-kinds.pem", "leaf-san-comma.pem"]) {
        const observation = observe(name);
        assert.deepEqual(Object.keys(observation.certificates[0].san), ["dns", "ip", "email", "uri"], name);
        // Nothing of the DirName or the otherName reaches the output in any form.
        assert.doesNotMatch(JSON.stringify(observation), /kinds directory name|CN=|UPN|user@example\.com|Doe/, name);
    }
});

test("SAN text that cannot be read throws a ParseError that names the input block", async (t) => {
    const UNREADABLE = [
        ["an entry with no colon", "DNS"],
        ["a trailing separator", "DNS:a.example, "],
        ["a leading separator", ", DNS:a.example"],
        ["an empty entry between separators", "DNS:a.example, , DNS:b.example"],
        ["text that is not TYPE:value", "not a list"],
        ["an unterminated quote", 'DNS:"a.example'],
        ["a quote that ends early", 'DNS:"a" b'],
        ["a quoted value that is not JSON", 'DNS:"\\x"'],
        ["a quoted value followed by text with no separator", 'DNS:"a"b'],
    ];
    for (const [name, text] of UNREADABLE) {
        await t.test(name, () => {
            assert.throws(() => subjectAltNames(text, 7), (error) => {
                assert.ok(error instanceof ParseError, `expected a ParseError, got ${error}`);
                assert.equal(error.block, 7);
                assert.match(error.message, /input block 7\b/);
                return true;
            }, JSON.stringify(text));
        });
    }

    await t.test("an IP Address that is not an address, such as the length marker Node.js writes", () => {
        for (const text of ["IP Address:<invalid length=5>", "IP Address:<invalid length=0>", "IP Address:example.com", "IP Address:"]) {
            assert.throws(() => subjectAltNames(text, 3), (error) => {
                assert.ok(error instanceof ParseError);
                assert.equal(error.block, 3);
                assert.match(error.message, /input block 3\b/);
                return true;
            }, text);
        }
    });

    await t.test("a certificate whose SAN holds an address of five bytes, read from the material", () => {
        // Made with: openssl req -new -x509 -key <P-256 key> -subj /CN=badip2 -days 30 -addext "2.5.29.17=DER:30078705010203040A"
        // The extension holds an IP address of five bytes, which is neither IPv4 nor IPv6.
        const pem = [
            "-----BEGIN CERTIFICATE-----",
            "MIIBVjCB/aADAgECAhQmEW7Xr9IGLzm41wKE7iAt4FNHKjAKBggqhkjOPQQDAjAR",
            "MQ8wDQYDVQQDDAZiYWRpcDIwHhcNMjYxMDEwMTczMDI1WhcNMjYxMTA5MTczMDI1",
            "WjARMQ8wDQYDVQQDDAZiYWRpcDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS/",
            "dVrWdvoTGHVEaWhnQelyCmfvxrecBgMMclpVbzUEkFcEV+1FTW2M31wBLgJJAxoO",
            "cPJJtwMVSTbDPO4wvsJoozMwMTAQBgNVHREECTAHhwUBAgMECjAdBgNVHQ4EFgQU",
            "qGkPfQ2WqGMrAIiOdopyWqIsj98wCgYIKoZIzj0EAwIDSAAwRQIhAN9tYvWcPIWf",
            "4wcIvjJdDHp2F8YZ81E5loKQ4clvJqbJAiB0htRm6ISv9S7DVDYmic2EK1AE9Swh",
            "fVBYf2C42DhyOQ==",
            "-----END CERTIFICATE-----",
            "",
        ].join("\n");
        assert.throws(() => inspect(pem, { at: AT }), (error) => {
            assert.ok(error instanceof ParseError);
            assert.equal(error.block, 1);
            assert.match(error.message, /input block 1\b.*IP address/);
            return true;
        });
    });
});
