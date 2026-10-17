import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalAddress } from "../src/san.js";
import { isHostName, servernameOf, targetOf } from "../src/tls/target.js";

// The rules for reading a target, without a socket. The module that connects is tested in
// tls.test.js.

test("a target is a host name, an IPv4 address or a bracketed IPv6 address, each with an optional port that defaults to 443", () => {
    assert.deepEqual(targetOf("example.com"), { host: "example.com", port: 443, ref: "example.com:443", servername: "example.com" });
    assert.deepEqual(targetOf("example.com:8443"), { host: "example.com", port: 8443, ref: "example.com:8443", servername: "example.com" });
    assert.deepEqual(targetOf("192.0.2.1"), { host: "192.0.2.1", port: 443, ref: "192.0.2.1:443", servername: null });
    assert.deepEqual(targetOf("192.0.2.1:8443"), { host: "192.0.2.1", port: 8443, ref: "192.0.2.1:8443", servername: null });
    assert.deepEqual(targetOf("[2001:db8::1]"), { host: "2001:db8::1", port: 443, ref: "[2001:db8::1]:443", servername: null });
    assert.deepEqual(targetOf("[2001:db8::1]:443"), { host: "2001:db8::1", port: 443, ref: "[2001:db8::1]:443", servername: null });
    assert.deepEqual(targetOf("[::1]:8443"), { host: "::1", port: 8443, ref: "[::1]:8443", servername: null });
    // The ends of the port range, and a name that is a single label.
    assert.equal(targetOf("localhost:1").port, 1);
    assert.equal(targetOf("localhost:65535").port, 65535);
    assert.equal(targetOf("my_host-1.example.test").host, "my_host-1.example.test");
});

test("ref always writes the port, lowercases a host name and writes IPv6 in brackets as san.ip does", () => {
    assert.equal(targetOf("Example.COM").ref, "example.com:443");
    assert.equal(targetOf("EXAMPLE.com:443").ref, targetOf("example.com").ref);
    assert.equal(targetOf("Example.COM").servername, "example.com");

    // The same address written in every way RFC 4291 allows labels one server one way, the way
    // the subject alternative names label it. The core's own function is the reference.
    for (const address of ["2001:DB8:0:0::1", "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "::ffff:192.0.2.1", "0:0:0:0:0:0:0:1", "1:0:0:2:0:0:0:3", "fe80::0:0:1", "::"]) {
        const expected = `[${canonicalAddress(address)}]:443`;
        assert.equal(targetOf(`[${address}]`).ref, expected, address);
        assert.equal(targetOf(`[${address}]:443`).ref, expected, address);
        assert.equal(targetOf(`[${address}]`).host, canonicalAddress(address), address);
    }
});

test("a target that is not host[:port] or [IPv6][:port] throws TypeError", () => {
    const refused = [
        // Not text.
        undefined, null, 443, {}, ["example.com"], new String("example.com"),
        // Nothing, or no host.
        "", ":443", "[]", "[]:443", " ", "example.com ", " example.com",
        // The port.
        "example.com:", "example.com:0", "example.com:00443", "example.com:0443", "example.com:65536", "example.com:99999", "example.com:-1",
        "example.com:+443", "example.com:4.43", "example.com:https", "example.com:443:443", "example.com:1e3", "example.com:٤٤٣",
        "192.0.2.1:", "192.0.2.1:70000", "[::1]:", "[::1]:0", "[::1]:65536", "[::1]:http",
        // IPv6 outside brackets, and what is not IPv6 inside them.
        "2001:db8::1", "::1", "2001:db8::1:443", "[192.0.2.1]", "[192.0.2.1]:443", "[example.com]", "[::1", "::1]", "[::1]x", "[::1]443",
        "[::1]:443:1", "[[::1]]", "[::g]", "[1:2:3:4:5:6:7:8:9]",
        // A zone names an interface of this machine, not a server.
        "[fe80::1%en0]", "[fe80::1%25en0]:443",
        // A host name that is not one.
        "example..com", ".example.com", "example.com.", "exa mple.com", "exa/mple.com", "example.com/path", "https://example.com", "user@example.com",
        "exämple.com", "例え.jp", "a".repeat(64) + ".example", `${"a.".repeat(127)}a`,
        "example.com\n", "exam\u0000ple.com", "-", "*.example.com", "-a.example", "a-.example", "a.-b.example",
        // A last label that is a number is read by resolvers as part of an IPv4 address.
        "127.1", "0x7f.0.0.1", "127.0.1", "1.2.3.4.5", "256.1.1.1", "010.0.0.1", "192.0.2.01", "2130706433", "example.123", "0x7f", "localhost.0x",
    ];
    for (const target of refused) {
        assert.throws(() => targetOf(target), TypeError, JSON.stringify(target));
    }
});

test("a target that starts with a scheme and :// is refused as a URL, in any letter case, and says that the target is host[:port]", () => {
    const urls = [
        "https://example.com", "ftp://a", "example.com://", "HTTPS://example.com:443/x", "http://[::1]:8443", "hTTp://x", "https://", "a://",
        "a+b.c-d://x", "https://example.com:8443", "https://192.0.2.1", "ssh://user@example.com", "x://", "svn+ssh://host/path",
    ];
    for (const url of urls) {
        assert.throws(() => targetOf(url), (error) => {
            assert.ok(error instanceof TypeError, url);
            assert.equal(error.message, `target ${JSON.stringify(url)} cannot be read: a URL is not accepted: the target is host[:port]`);
            return true;
        }, url);
    }
});

test("a host:port, a bracketed IPv6 target and a bare host are not caught by the rule for a URL, and neither is a text that merely looks like one", () => {
    for (const accepted of ["example.com", "example.com:443", "localhost:8443", "[::1]", "[::1]:443", "[2001:db8::1]:443", "192.0.2.1:443", "a:1", "ex_ample.com:443"]) {
        assert.doesNotThrow(() => targetOf(accepted), accepted);
    }
    // Not a scheme as RFC 3986 writes it (it starts with a digit, a hyphen, a space or an underscore
    // inside, or has no //), so they keep the reason they always had.
    for (const [text, reason] of /** @type {[string, RegExp][]} */ ([
        ["1http://x", /the port must be a whole number/],
        ["-x://y", /the port must be a whole number/],
        ["ex_ample.com://", /the port must be a whole number/],
        [" https://x", /the port must be a whole number/],
        ["https ://x", /the port must be a whole number/],
        ["https:example.com", /the port must be a whole number/],
        ["https:/example.com", /the port must be a whole number/],
        ["//example.com", /write a host name/],
        ["[::1]://x", /the port must be a whole number/],
        ["example.com:443://", /must be written in brackets/],
        ["mailto:a@b", /the port must be a whole number/],
    ])) {
        assert.throws(() => targetOf(text), (error) => {
            assert.ok(error instanceof TypeError);
            assert.match(error.message, reason, text);
            assert.doesNotMatch(error.message, /URL/, text);
            return true;
        }, text);
    }
});

test("the rule for a URL changes only which reason is given: over generated texts, a text is refused as a URL exactly when it starts with a scheme and ://, and no text that is read starts with one", () => {
    const pieces = ["https", "HTTP", "ftp", "a", "1", "-", "+", ".", "_", ":", "//", "/", "[", "]", "::1", "example.com", "443", "192.0.2.1", " ", "@", "%"];
    const start = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
    let urls = 0;
    let read = 0;
    /** @param {string} text */
    const check = (text) => {
        /** @type {string | undefined} */
        let message;
        try {
            targetOf(text);
            read += 1;
        } catch (error) {
            message = /** @type {Error} */ (error).message;
        }
        const refusedAsUrl = message !== undefined && message.includes("a URL is not accepted");
        assert.equal(refusedAsUrl, start.test(text), JSON.stringify(text));
        if (refusedAsUrl) urls += 1;
    };
    for (const first of pieces) {
        for (const second of pieces) {
            check(first + second);
            for (const third of pieces) {
                check(first + second + third);
                for (const fourth of pieces) check(first + second + third + fourth);
            }
        }
    }
    assert.ok(urls > 100, `${urls} texts refused as a URL`);
    assert.ok(read > 50, `${read} texts read`);
});

test("a refused target's message says what to write, and quotes the target so that it cannot break a line", () => {
    assert.throws(() => targetOf("2001:db8::1"), /must be written in brackets, as \[2001:db8::1\]:443/);
    assert.throws(() => targetOf("example.com:99999"), /port must be a whole number from 1 to 65535/);
    assert.throws(() => targetOf("[fe80::1%en0]"), /zone/);
    assert.throws(() => targetOf("127.1"), /write a host name, an IPv4 address or a bracketed IPv6 address/);
    assert.throws(() => targetOf(443), /target must be a string/);
    assert.throws(() => targetOf("bad\nhost"), (error) => {
        assert.ok(error instanceof TypeError);
        assert.doesNotMatch(error.message, /\n/);
        assert.match(error.message, /"bad\\nhost"/);
        return true;
    });
});

test("a host name accepts the longest forms and refuses the first one past them", () => {
    const label63 = "a".repeat(63);
    assert.equal(isHostName(label63), true);
    assert.equal(isHostName("a".repeat(64)), false);
    // 253 characters in all.
    const longest = [label63, label63, label63, "a".repeat(61)].join(".");
    assert.equal(longest.length, 253);
    assert.equal(isHostName(longest), true);
    assert.equal(isHostName(`${longest}a`), false);
    assert.equal(isHostName(""), false);
    assert.equal(isHostName("192.0.2.1"), false);
    assert.equal(isHostName("1password.com"), true);
});

test("a server name given by the caller is kept as typed, and must be a host name", () => {
    assert.equal(servernameOf(undefined), undefined);
    assert.equal(servernameOf("Api.Example.COM"), "Api.Example.COM");
    assert.equal(servernameOf("localhost"), "localhost");
    for (const given of ["", " ", "a b", "192.0.2.1", "127.1", "::1", "[::1]", "2001:db8::1", "bücher.example", "example.com.", "a".repeat(254), 443, null, {}, false]) {
        assert.throws(() => servernameOf(given), TypeError, JSON.stringify(given));
    }
});
